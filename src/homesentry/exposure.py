"""What the internet can reach, for people who don't own a VPS.

Three layers, cheapest first. Each one stands on its own:

1. **Router-reported** (local, free, always on). Ask the router what it has been told to open:
   UPnP IGD port mappings (how consoles, cameras, NAS boxes and Plex quietly open ports),
   NAT-PMP, and the router's own external address. That address alone answers a big
   question: in 100.64.0.0/10 (carrier-grade NAT: T-Mobile/Verizon home internet, Starlink,
   many fiber ISPs) nothing on the internet can start an IPv4 connection to the house at all;
   in RFC 1918 the router is behind another NAT. Nothing leaves the LAN.
2. **Active reflector** (opt-in). A tiny stateless service (`homesentry reflector`, see
   reflector.py) that connect-scans *only the address the request came from*, so it can't be
   pointed at anyone else, over IPv4 and IPv6. The SSH-to-your-own-box probe in outside.py
   remains the do-it-yourself version of the same thing.
3. **Passive** (opt-in, `HOMESENTRY_INTERNETDB=1`). Shodan's InternetDB says what internet
   scanners already saw on our public IP (weekly). Free for non-commercial use only; a paid
   app needs Shodan's enterprise license. It tells Shodan our IP, so it's off by default.

The public IP is used in memory only and never stored, as in outside.py.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urljoin

import httpx

# Ports that matter for a home's internet exposure: remote access, file sharing, cameras/NVRs,
# home automation, media servers, router management, databases and dev servers people forward
# "just for a minute". Ours (nmap's frequency table can't be bundled), used when nmap's isn't
# installed, which is every Mac.
HOME_PORTS = sorted(
    {
        *(20, 21, 22, 23, 25, 53, 80, 81, 82, 83, 88, 110, 111, 119, 135, 139, 143, 389, 443),
        *(445, 465, 548, 554, 587, 631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1521),
        *(1723, 1883, 1900, 2000, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 2869, 3000, 3001),
        *(3128, 3306, 3389, 3478, 3689, 4000, 4443, 4444, 4567, 4711, 5000, 5001, 5060, 5222),
        *(5357, 5432, 5555, 5601, 5800, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 6667, 7000),
        *(7001, 7070, 7443, 7547, 7681, 8000, 8001, 8008, 8009, 8060, 8069, 8080, 8081, 8082),
        *(8083, 8086, 8088, 8089, 8090, 8096, 8123, 8181, 8200, 8291, 8333, 8384, 8443, 8444),
        *(8448, 8500, 8554, 8581, 8686, 8834, 8880, 8888, 8889, 8899, 8920, 8999, 9000, 9001),
        *(9080, 9090, 9091, 9100, 9200, 9443, 9999, 10000, 10001, 10243, 11211, 11434, 12345),
        *(15672, 16992, 16993, 18080, 20000, 25565, 27017, 32400, 34567, 37777, 47808, 49152),
        *(50000, 51413, 51820, 55443),
    }
)

IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
)
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")
MAX_MAPPINGS = 256


def classify_external(ip: str | None) -> str:
    """public | cgnat | private (behind another NAT) | unknown"""
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return "unknown"
    if a.version == 4 and a in CGNAT:
        return "cgnat"
    if a.is_private or a.is_loopback or a.is_link_local:
        return "private"
    return "public" if a.is_global else "unknown"


# ---- UPnP IGD ---------------------------------------------------------------------------
def igd_locations(seconds: float = 3.0, local_ip: str | None = None) -> dict[str, set[str]]:
    """M-SEARCH for Internet Gateway Devices: {responder ip: {description URLs}}."""
    from .discover import safe_ssdp_location

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    if local_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
    for st in IGD_TYPES:
        msg = (
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n'
        )
        s.sendto(msg.encode(), ("239.255.255.250", 1900))
    out: dict[str, set[str]] = {}
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, (ip, _) = s.recvfrom(8192)
        except TimeoutError:
            continue
        for line in data.decode(errors="ignore").split("\r\n"):
            k, sep, v = line.partition(":")
            if sep and k.strip().upper() == "LOCATION" and safe_ssdp_location(ip, v.strip()):
                out.setdefault(ip, set()).add(v.strip())
    s.close()
    return out


def parse_igd(xml: str, location: str) -> list[tuple[str, str]]:
    """[(service type, absolute control URL)] for the WAN connection services, best first.
    Control URLs must stay on the host that described them (a forged description must not
    turn us into a request-forger against other LAN hosts)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    base = location
    for el in root.iter():
        if el.tag.split("}")[-1] == "URLBase" and el.text:
            base = el.text.strip()
    want_host = httpx.URL(location).host
    found = {}
    for svc in root.iter():
        if svc.tag.split("}")[-1] != "service":
            continue
        f = {c.tag.split("}")[-1]: (c.text or "").strip() for c in svc}
        if f.get("serviceType") in WAN_SERVICES and f.get("controlURL"):
            url = urljoin(base, f["controlURL"])
            try:
                if httpx.URL(url).host == want_host:
                    found.setdefault(f["serviceType"], url)
            except httpx.InvalidURL:
                continue
    return [(t, found[t]) for t in WAN_SERVICES if t in found]


def soap(client: httpx.Client, url: str, service: str, action: str, args=None) -> dict:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    env = (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service}">{body}</u:{action}></s:Body></s:Envelope>'
    )
    r = client.post(
        url,
        content=env,
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service}#{action}"',
        },
    )
    out = {}
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        return {"_status": r.status_code}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if not list(el) and el.text is not None:
            out[tag] = el.text.strip()
    out["_status"] = r.status_code
    return out


def read_igd(location: str, client: httpx.Client) -> dict[str, Any] | None:
    """External IP, connection status and every port mapping one IGD reports. Read-only: only
    Get* actions are ever sent."""
    try:
        services = parse_igd(client.get(location).text, location)
    except httpx.HTTPError:
        return None
    if not services:
        return None
    svc, url = services[0]
    res: dict[str, Any] = {"service": svc.rsplit(":", 2)[-2], "mappings": []}
    try:
        res["external_ip"] = soap(client, url, svc, "GetExternalIPAddress").get(
            "NewExternalIPAddress"
        )
        res["status"] = soap(client, url, svc, "GetStatusInfo").get("NewConnectionStatus")
        for i in range(MAX_MAPPINGS):
            m = soap(client, url, svc, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
            if m["_status"] != 200 or "NewExternalPort" not in m:
                break  # 713 SpecifiedArrayIndexInvalid = end of the table
            res["mappings"].append(
                {
                    "proto": (m.get("NewProtocol") or "").upper(),
                    "external_port": int(m.get("NewExternalPort") or 0),
                    "internal_ip": m.get("NewInternalClient"),
                    "internal_port": int(m.get("NewInternalPort") or 0),
                    "enabled": m.get("NewEnabled", "1") in ("1", "true"),
                    "description": (m.get("NewPortMappingDescription") or "")[:80],
                    "lease_s": int(m.get("NewLeaseDuration") or 0),
                }
            )
    except (httpx.HTTPError, ValueError):
        res["partial"] = True
    return res


# ---- NAT-PMP (RFC 6886): Apple routers and some others ---------------------------------
def parse_natpmp(data: bytes) -> str | None:
    if len(data) < 12:
        return None
    ver, op, code, _epoch = struct.unpack("!BBHI", data[:8])
    if ver != 0 or op != 128 or code != 0:
        return None
    return socket.inet_ntoa(data[8:12])


def natpmp_external(gateway: str, timeout: float = 1.5) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00\x00", (gateway, 5351))
        data, (src, _) = s.recvfrom(64)
        return parse_natpmp(data) if src == gateway else None
    except OSError:
        return None
    finally:
        s.close()


def router_report(
    ctx: dict[str, str], client: httpx.Client | None = None
) -> tuple[dict[str, Any], str | None]:
    """Layer 1 for one network: what its router says is open and what kind of WAN address it
    has. Returns (report to store, external IP for in-memory comparison only)."""
    own = client is None
    client = client or httpx.Client(timeout=4, follow_redirects=False)
    try:
        rep: dict[str, Any] = {"network": ctx["cidr"], "gateway": ctx["gateway"], "igd": []}
        for ip, locs in igd_locations(local_ip=ctx.get("local_ip")).items():
            for loc in sorted(locs)[:3]:
                got = read_igd(loc, client)
                if got:
                    rep["igd"].append({"router": ip, **got})
                    break
        pmp = natpmp_external(ctx["gateway"]) if ctx.get("gateway") else None
        ext = next((g.get("external_ip") for g in rep["igd"] if g.get("external_ip")), None)
        ext = ext or pmp
        rep.update(wan=classify_external(ext), natpmp=pmp is not None, at=time.strftime("%F %T"))
        for g in rep["igd"]:  # the address itself is never stored, only its class
            g.pop("external_ip", None)
        return rep, ext
    finally:
        if own:
            client.close()


# ---- IPv6: every device with a global address is individually addressable ---------------
def is_global_v6(addr: str) -> bool:
    try:
        a = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    return a.version == 6 and a.is_global


def parse_ndp(text: str, iface: str | None = None) -> dict[str, str]:
    """macOS `ndp -an`: {global v6 address: mac}."""
    from .netinfo import norm_mac

    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3 or (iface and parts[2] != iface):
            continue
        addr, mac = parts[0].split("%")[0], parts[1]
        if is_global_v6(addr) and re.fullmatch(r"[0-9a-f]{1,2}(:[0-9a-f]{1,2}){5}", mac, re.I):
            out[addr] = norm_mac(mac)
    return out


def parse_ip6_neigh(js: str) -> dict[str, str]:
    """Linux `ip -j -6 neigh`: {global v6 address: mac}."""
    import json

    out = {}
    for n in json.loads(js or "[]"):
        if (
            n.get("lladdr")
            and is_global_v6(n.get("dst", ""))
            and "FAILED" not in n.get("state", [])
        ):
            out[n["dst"]] = n["lladdr"].lower()
    return out


def v6_neighbors(iface: str) -> dict[str, str]:
    import subprocess

    from .netinfo import platform

    try:
        if platform() == "darwin":
            r = subprocess.run(["ndp", "-an"], capture_output=True, text=True, timeout=10)
            return parse_ndp(r.stdout, iface)
        r = subprocess.run(
            ["ip", "-j", "-6", "neigh", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return parse_ip6_neigh(r.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}


def one_per_device(addrs: dict[str, str], limit: int = 32) -> dict[str, str]:
    """{mac: one global address}: services listen on every address, so one per device is
    enough; prefer stable (EUI-64 / DHCPv6-looking) over temporary ones."""
    out: dict[str, str] = {}
    for addr, mac in sorted(addrs.items(), key=lambda kv: ("ff:fe" not in kv[0], len(kv[0]))):
        out.setdefault(mac, addr)
    return dict(list(out.items())[:limit])


# ---- Layer 2 client: the reflector ------------------------------------------------------
def reflector_check(
    base: str, family: int, extra: list[str] | None = None, transport=None
) -> dict[str, Any]:
    """Ask a reflector to scan the address this request comes from. `family` 4 or 6 forces the
    connection over that IP version (bind the local side), so each family is tested for real."""
    local = "0.0.0.0" if family == 4 else "::"
    transport = transport or httpx.HTTPTransport(local_address=local, retries=1)
    with httpx.Client(transport=transport, timeout=90) as c:
        r = c.post(f"{base.rstrip('/')}/v1/check", json={"extra": extra or []})
    if r.status_code == 429:
        raise RuntimeError(f"reflector: rate limited, retry in {r.headers.get('retry-after')}s")
    r.raise_for_status()
    return r.json()


# ---- Layer 3: passive (Shodan InternetDB) ------------------------------------------------
def internetdb(client: httpx.Client | None = None) -> dict[str, Any]:
    return _internetdb(client)


def _internetdb(client: httpx.Client | None = None) -> dict[str, Any]:
    """What scanners already saw on our public IP. `GET /` = "my IP", so we never send it."""
    own = client is None
    client = client or httpx.Client(timeout=10)
    try:
        r = client.get("https://internetdb.shodan.io/")
        if r.status_code == 404:
            return {"known": False, "ports": [], "vulns": [], "at": time.strftime("%F %T")}
        r.raise_for_status()
        j = r.json()
        return {
            "known": True,
            "ports": sorted(int(p) for p in j.get("ports", [])),
            "vulns": sorted(j.get("vulns", []))[:50],
            "tags": j.get("tags", [])[:10],
            "at": time.strftime("%F %T"),
        }  # ip and hostnames deliberately dropped
    finally:
        if own:
            client.close()
