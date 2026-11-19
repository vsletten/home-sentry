"""`homesentry reflector`: the outside-in check as a service, for people without a VPS.

It connect-scans the address the HTTP request came from, and nothing else. That one rule is
what makes it safe to run publicly (the GRC ShieldsUP model): nobody can aim it at a
third party. Rules:

- target = the TCP peer of the request (or X-Forwarded-For from a loopback reverse proxy when
  REFLECTOR_TRUST_PROXY=1, e.g. Caddy terminating TLS). Only globally routable addresses.
- optional `extra` IPv6 targets must sit in the requester's own /64 (the same home network:
  every device there has its own public address), at most 16.
- connect-only: no payload is ever sent, so nothing prints, logs in or gets exploited.
- one check per /32 (IPv4) or /64 (IPv6) per COOLDOWN seconds, MAX_SCANS at a time.
- nothing written to disk; the rate-limit table lives in memory for COOLDOWN seconds.

Run it on two names (an A-only and an AAAA-only host) or one dual-stack name; the app forces
the IP version per request so both get tested.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .exposure import HOME_PORTS

COOLDOWN = 300
MAX_SCANS = 8
MAX_EXTRA = 16
CONNECT_TIMEOUT = 1.5
PER_SCAN = 64


IP = ipaddress.IPv4Address | ipaddress.IPv6Address


def is_public(ip: IP) -> bool:
    return ip.is_global


def bucket(ip: IP) -> str:
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def requester(request: Request, trust_proxy: bool) -> str:
    peer = request.client.host if request.client else ""
    if trust_proxy and peer in ("127.0.0.1", "::1"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[-1].strip()  # the hop our own proxy appended
    return peer


def valid_extra(source: IP, extra: list[Any]) -> list[str]:
    if source.version != 6:
        return []
    net = ipaddress.ip_network(f"{source}/64", strict=False)
    out = []
    for e in extra[: MAX_EXTRA * 2]:
        try:
            a = ipaddress.ip_address(str(e))
        except ValueError:
            continue
        if a.version == 6 and a in net and is_public(a) and a != source and str(a) not in out:
            out.append(str(a))
    return out[:MAX_EXTRA]


async def connect_scan(target: str, ports: list[int], sem: asyncio.Semaphore) -> list[int]:
    async def one(p: int) -> int | None:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(target, p), CONNECT_TIMEOUT)
            except (OSError, TimeoutError):
                return None
            w.close()  # connect-only: not one byte is sent
            return p

    return sorted(p for p in await asyncio.gather(*(one(p) for p in ports)) if p)


def create_app(scan=connect_scan, clock=time.monotonic) -> FastAPI:
    app = FastAPI(title="HomeSentry reflector", docs_url=None, redoc_url=None, openapi_url=None)
    trust = os.environ.get("REFLECTOR_TRUST_PROXY") == "1"
    recent: dict[str, float] = {}
    gate = asyncio.Semaphore(MAX_SCANS)

    @app.get("/")
    def about():
        return {
            "service": "homesentry-reflector",
            "does": "scans the TCP ports of the address your request comes from; nothing else",
            "ports": len(HOME_PORTS),
            "cooldown_s": COOLDOWN,
        }

    @app.post("/v1/check")
    async def check(request: Request):
        try:
            src = ipaddress.ip_address(requester(request, trust))
        except ValueError:
            return JSONResponse({"error": "no usable source address"}, status_code=400)
        if not is_public(src):
            return JSONResponse({"error": "only public addresses are checked"}, status_code=403)
        now = clock()
        for k in [k for k, t in recent.items() if now - t > COOLDOWN]:
            del recent[k]
        b = bucket(src)
        if b in recent:
            wait = int(COOLDOWN - (now - recent[b])) + 1
            return JSONResponse(
                {"error": "one check per network every few minutes"},
                status_code=429,
                headers={"Retry-After": str(wait)},
            )
        if gate.locked():
            return JSONResponse({"error": "busy, try again shortly"}, status_code=503)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        extra = valid_extra(src, body.get("extra") or [] if isinstance(body, dict) else [])
        recent[b] = now
        async with gate:
            t0 = time.monotonic()
            sem = asyncio.Semaphore(PER_SCAN)
            targets = [str(src), *extra]
            results = await asyncio.gather(*(scan(t, HOME_PORTS, sem) for t in targets))
        return {
            "family": f"ipv{src.version}",
            "seen_ip": str(src),  # yours, echoed so the app can spot a VPN exit; not stored
            "open": results[0],
            "extra": [{"addr": a, "open": o} for a, o in zip(extra, results[1:], strict=True)],
            "scanned": len(HOME_PORTS),
            "seconds": round(time.monotonic() - t0, 1),
        }

    return app
