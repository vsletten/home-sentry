"""`homesentry probe`: run every collector, write nothing, print what this machine can see.

Two jobs:
  * diagnostics on any machine ("what does HomeSentry see from here?"), and
  * cross-platform verification: probe from a Mac (or later Windows), then `homesentry
    compare probe.json` on the appliance diffs that view against the inventory, which is
    the answer key.

Each collector runs in isolation: one that fails records its error and the rest still run,
because "mDNS crashed on macOS" is exactly the finding a probe exists to report.
The output holds MACs and IPs; it is for your own machines and is never sent anywhere.
"""

from __future__ import annotations

import platform as pyplatform
import sys
import time
import traceback
from typing import Any

from . import discover, netinfo

Sighting = tuple[str, str, str]


def _timed(errors: dict[str, str], timings: dict[str, float], name: str, fn, default):
    t = time.monotonic()
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - report, don't crash: that's the probe's job
        errors[name] = f"{type(e).__name__}: {e}"
        if "-v" in sys.argv:
            traceback.print_exc()
        return default
    finally:
        timings[name] = round(time.monotonic() - t, 2)


def collect(ports: bool = False, mdns_seconds: float = 8.0) -> dict[str, Any]:
    errors: dict[str, str] = {}
    timings: dict[str, float] = {}
    out: dict[str, Any] = {
        "probe_version": 1,
        "host": {
            "platform": netinfo.platform(),
            "os": f"{pyplatform.system()} {pyplatform.release()}",
            "mac_ver": pyplatform.mac_ver()[0] or None,
            "machine": pyplatform.machine(),
            "python": pyplatform.python_version(),
            "hostname": pyplatform.node(),
        },
        "started": time.time(),
        "port_engine": discover.port_engine() if ports else None,
        "errors": errors,
        "timings": timings,
        "networks": [],
    }
    ctxs = _timed(errors, timings, "lan_contexts", discover.lan_contexts, [])
    peers = _timed(errors, timings, "tailscale", discover.tailscale_peers, {})
    out["tailscale_peers_on_lan"] = len(peers)
    for ctx in ctxs:
        tag = ctx["iface"]
        neigh = _timed(
            errors,
            timings,
            f"{tag}:arp",
            lambda c=ctx: discover.arp_sweep(c["cidr"], c["iface"]),
            {},
        )
        if ctx.get("mac"):
            neigh[ctx["local_ip"]] = ctx["mac"]
        ips = sorted(neigh, key=_ipkey)
        ptr = _timed(errors, timings, f"{tag}:dns", lambda i=ips: discover.reverse_dns(i), {})
        md = _timed(
            errors,
            timings,
            f"{tag}:mdns",
            lambda c=ctx: discover.mdns(c["iface"], int(mdns_seconds), local_ip=c["local_ip"]),
            {},
        )
        sd = _timed(
            errors, timings, f"{tag}:ssdp", lambda c=ctx: discover.ssdp(local_ip=c["local_ip"]), {}
        )
        svc = None
        if ports:
            svc = _timed(
                errors, timings, f"{tag}:ports", lambda i=ips: discover.service_scan(i), None
            )
        hosts: dict[str, Any] = {}
        for ip in sorted(set(ips) | set(md) | set(sd), key=_ipkey):
            mac = neigh.get(ip, "")
            vendor = discover.oui_vendor(mac) if mac else None
            rnd = discover.is_random_mac(mac) if mac else False
            sights = md.get(ip, []) + sd.get(ip, []) + (svc or {}).get(ip, [])
            # same NAT-vs-peer judgment the real scan makes (a Mac behind an AP's NAT)
            sights += discover.attribute_tailscale(
                peers.get(ip, []), vendor, rnd, self_reports=md.get(ip, [])
            )
            hosts[ip] = {
                "mac": mac,
                "vendor": vendor,
                "random_mac": rnd if mac else None,
                "ptr": ptr.get(ip),
                "sightings": sorted({tuple(s) for s in sights}),
            }
        out["networks"].append(
            ctx
            | {
                "hosts": hosts,
                "counts": {
                    "arp": len(neigh),
                    "mdns": len(md),
                    "ssdp": len(sd),
                    "ports": None if svc is None else len(svc),
                },
            }
        )
    out["seconds"] = round(time.time() - out["started"], 1)
    return out


def _ipkey(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999,)


# ---- compare a probe against the inventory (the answer key) -------------------------------
def compare(probe: dict[str, Any], store) -> dict[str, Any]:
    from . import identify

    devices = [d for d in store.devices(include_retired=True)]
    by_mac = {d["mac"]: d for d in devices if d.get("mac")}
    report: dict[str, Any] = {"host": probe.get("host"), "errors": probe.get("errors"), "nets": []}
    for net in probe.get("networks", []):
        cidr = net["cidr"]
        key_online = {
            d["mac"]: d
            for d in devices
            if d.get("network") == cidr and d.get("online") and not d.get("retired") and d["mac"]
        }
        seen = {h["mac"]: (ip, h) for ip, h in net["hosts"].items() if h.get("mac")}
        matched, missing, extra, ports_diff, svc_diff, ident = [], [], [], [], [], []
        for mac, d in sorted(key_online.items(), key=lambda kv: _ipkey(kv[1]["ip"] or "")):
            name = d["label"] or d["ip"]
            if mac not in seen:
                missing.append(name)
                continue
            ip, h = seen[mac]
            matched.append(name)
            ev = store.evidence(d["id"])
            key_ports = _ports([(e["source"], e["key"], e["value"]) for e in ev])
            got_ports = _ports(h["sightings"])
            scanned_key = any(e["source"] == "ports" and e["key"] == "scanned" for e in ev)
            if net["counts"].get("ports") is not None and scanned_key and key_ports != got_ports:
                ports_diff.append(
                    {
                        "device": name,
                        "only_key": sorted(key_ports - got_ports, key=int),
                        "only_probe": sorted(got_ports - key_ports, key=int),
                    }
                )
            key_svc = {e["value"] for e in ev if e["source"] == "mdns" and e["key"] == "service"}
            got_svc = {v for s, k, v in h["sightings"] if s == "mdns" and k == "service"}
            if got_svc != key_svc and (got_svc or key_svc):
                svc_diff.append(
                    {
                        "device": name,
                        "only_key": sorted(key_svc - got_svc),
                        "only_probe": sorted(got_svc - key_svc),
                    }
                )
            # Collector parity, not inventory parity: guess from the SAME kinds of evidence on
            # both sides (the inventory also knows gateway DHCP names, wizard answers, ...).
            gw = ip == net.get("gateway")
            vendor = discover.oui_vendor(mac)
            scanned_ports = net["counts"].get("ports") is not None
            key_ev = [
                e
                for e in ev
                if e["source"] in COLLECTED and (scanned_ports or e["source"] != "ports")
            ]
            kg = identify.guess(key_ev, vendor, is_gateway=gw, is_self=False)
            pg = identify.guess(
                [
                    {"source": s, "key": k, "value": v}
                    for s, k, v in h["sightings"]
                    if s in COLLECTED
                ],
                vendor,
                is_gateway=gw,
                is_self=False,
            )
            want = {k: kg.get(k) for k in ("device_type", "make", "model")}
            got = {k: pg.get(k) for k in ("device_type", "make", "model")}
            if want != got:
                ident.append({"device": name, "key": want, "probe": got})
        for mac, (ip, h) in seen.items():
            if mac not in key_online:
                known = by_mac.get(mac)
                extra.append(
                    {
                        "ip": ip,
                        "vendor": h.get("vendor"),
                        "known_as": (known["label"] or known["ip"]) if known else None,
                        "random_mac": h.get("random_mac"),
                    }
                )
        report["nets"].append(
            {
                "cidr": cidr,
                "iface": net["iface"],
                "on_key_network": bool(key_online),
                "key_online": len(key_online),
                "probe_hosts": len(seen),
                "matched": len(matched),
                "missing": missing,
                "extra": extra,
                "ports_diff": ports_diff,
                "mdns_diff": svc_diff,
                "identity_diff": ident,
                "counts": net["counts"],
            }
        )
    return report


# LAN collectors whose parity we test. Tailscale is not one: its view depends on which peers
# are online right now and on stored NAT verdicts, not on the OS the probe runs on.
COLLECTED = {"mdns", "ssdp", "ports"}


def _ports(sights) -> set[str]:
    return {v.split("/")[0] for s, k, v in sights if s == "ports" and k == "open_port"}


def render(report: dict[str, Any]) -> str:
    h = report.get("host") or {}
    lines = [f"probe from {h.get('hostname')} ({h.get('os')}, {h.get('machine')})"]
    for k, v in (report.get("errors") or {}).items():
        lines.append(f"  ERROR {k}: {v}")
    for n in report["nets"]:
        lines.append(
            f"\n{n['cidr']} on {n['iface']}: probe saw {n['probe_hosts']} hosts; "
            + (
                f"answer key has {n['key_online']} online, matched {n['matched']}"
                if n["on_key_network"]
                else "NOT a network the inventory knows (a hidden/NATted network?)"
            )
        )
        lines.append(f"  collectors: {n['counts']}")
        if n["missing"]:
            lines.append(f"  missing (key saw, probe didn't): {', '.join(n['missing'])}")
        for e in n["extra"]:
            tag = f"known as {e['known_as']}" if e["known_as"] else "unknown to inventory"
            rnd = ", random MAC" if e["random_mac"] else ""
            lines.append(f"  extra {e['ip']} ({e['vendor'] or 'no vendor'}{rnd}): {tag}")
        for d in n["ports_diff"]:
            lines.append(
                f"  ports {d['device']}: key-only {d['only_key']} probe-only {d['only_probe']}"
            )
        for d in n["mdns_diff"]:
            lines.append(
                f"  mdns  {d['device']}: key-only {d['only_key']} probe-only {d['only_probe']}"
            )
        for d in n["identity_diff"]:
            lines.append(f"  ident {d['device']}: key {d['key']} probe {d['probe']}")
    return "\n".join(lines)
