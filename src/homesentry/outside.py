"""Outside-in exposure check: what the internet can reach.

Layers (see exposure.py): the router's own report (UPnP IGD / NAT-PMP, always on, local),
then an active check, either over SSH from a host you own (below) or from a HomeSentry
reflector (`PROBE_URL=`), plus opt-in passive lookup (`INTERNETDB=1`). Devices with public
IPv6 addresses are checked one by one.

The SSH probe:

The probe script is piped to `python3 -` on the probe host's stdin: nothing is installed
or written there. It targets the address the probe host sees our SSH connection coming
from (SSH_CLIENT), i.e. the home WAN IP, so the workstation never needs to know or store
it, and no third-party "port check" service ever learns anything.

TCP connect scan only (no raw packets, no banners), bounded concurrency so a busy CI box
barely notices. Config: ~/.config/homesentry/probe.env
    PROBE_SSH=ci-vps                               # ssh alias / user@host
    PROBE_SSH_AGENT=/run/user/1000/keyring/ssh     # optional IdentityAgent
or  PROBE_URL=https://reflector.example            # a HomeSentry reflector instead
    INTERNETDB=1                                   # also ask Shodan InternetDB (opt-in)
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any


def conf_path() -> Path:
    from . import config_dir

    return config_dir() / "probe.env"


NMAP_SERVICES = [
    Path("/usr/share/nmap/nmap-services"),
    Path("/snap/nmap/current/usr/share/nmap/nmap-services"),
]
FALLBACK_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    81,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    554,
    587,
    993,
    995,
    1194,
    1723,
    1883,
    2049,
    3000,
    3306,
    3389,
    5000,
    5060,
    5432,
    5900,
    7547,
    8000,
    8080,
    8081,
    8181,
    8443,
    8888,
    9000,
    9100,
    11434,
    32400,
    51820,
]
ALWAYS = [7547, 8181, 11434, 32400, 51820, 8443]  # TR-069, gateway remote mgmt, Ollama, ...

# Runs on the PROBE host. Prints JSON with port numbers only: never echoes the target.
REMOTE = r"""
import asyncio, json, os, sys, time
target = os.environ["SSH_CLIENT"].split()[0]
args = sys.argv[1:]
extra = args[args.index("--v6") + 1:] if "--v6" in args else []
ports = [int(p) for p in (args[:args.index("--v6")] if "--v6" in args else args)]
async def one(sem, p):
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(target, p), 1.5)
            w.close()
            return p
        except Exception:
            return None
async def scan(sem, t):
    async def one_t(p):
        async with sem:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(t, p), 1.5)
                w.close()
                return p
            except Exception:
                return None
    return sorted(p for p in await asyncio.gather(*(one_t(p) for p in ports)) if p)
async def main():
    sem = asyncio.Semaphore(64)
    t = time.time()
    hits = await scan(sem, target)
    v6 = [{"addr": a, "open": await scan(sem, a)} for a in extra]
    fam = "ipv6" if ":" in target else "ipv4"
    print(json.dumps({"open": hits, "scanned": len(ports), "v6": v6,
                      "seconds": round(time.time() - t, 1), "family": fam}))
asyncio.run(main())
"""


def load_conf(path: Path | None = None) -> dict[str, str] | None:
    path = path or conf_path()
    if not path.exists():
        return None
    out = {}
    for line in path.read_text().splitlines():
        k, sep, v = line.partition("=")
        if sep and not k.strip().startswith("#"):
            out[k.strip()] = v.strip().strip("\"'")
    return out if (out.get("PROBE_SSH") or out.get("PROBE_URL") or out.get("INTERNETDB")) else None


def top_ports(n: int = 1000) -> list[int]:
    for p in NMAP_SERVICES:
        if p.exists():
            rows = []
            for line in p.read_text(errors="ignore").splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1].endswith("/tcp") and not line.startswith("#"):
                    try:
                        rows.append((float(parts[2]), int(parts[1].split("/")[0])))
                    except ValueError:
                        continue
            ports = [port for _, port in sorted(rows, reverse=True)[:n]]
            break
    else:  # no nmap (every Mac): our own list of what matters for a home
        from .exposure import HOME_PORTS

        ports = list(HOME_PORTS)
    return sorted(set(ports) | set(ALWAYS))


def ssh_cmd(conf: dict[str, str]) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if conf.get("PROBE_SSH_AGENT"):
        cmd += ["-o", f"IdentityAgent={conf['PROBE_SSH_AGENT']}"]
    return cmd + [conf["PROBE_SSH"]]


def run_probe(
    conf: dict[str, str], ports: list[int], runner=subprocess.run, v6: list[str] | None = None
) -> dict[str, Any]:
    cmd = ssh_cmd(conf) + ["python3", "-", *map(str, ports)]
    if v6:
        cmd += ["--v6", *v6]
    r = runner(cmd, input=REMOTE, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"probe via {conf['PROBE_SSH']} failed: {r.stderr.strip()[-300:]}")
    res = json.loads(r.stdout.strip().splitlines()[-1])
    res.update(probe=conf["PROBE_SSH"], at=time.strftime("%F %T"))
    return res


def _device_by(store, *, ip: str | None = None, mac: str | None = None):
    for d in store.devices():
        if (ip and d["ip"] == ip) or (mac and d["mac"] == mac):
            return d
    return None


def _record(store, device_id: int, key: str, value: Any) -> None:
    store.clear_evidence(device_id, "outside", key)
    if value is not None:
        store.add_evidence(device_id, "outside", key, json.dumps(value))


def run_and_record(store, log=print, rethreat: bool = True) -> dict[str, Any]:
    """Every layer that's available, recorded where the exposure lives: router/WAN results on
    the gateway, port forwards and IPv6 results on the device they point at."""
    from . import discover, exposure, threat

    conf = load_conf() or {}
    ctxs = discover.lan_contexts()
    out: dict[str, Any] = {"layers": []}
    gw = None
    router_ext = None
    v6_targets: dict[str, str] = {}  # address -> mac
    for d in store.devices():  # forwards are re-derived every run
        store.clear_evidence(d["id"], "outside", "forward")
    for i, ctx in enumerate(ctxs):
        rep, ext = exposure.router_report(ctx)
        router_ext = router_ext or ext
        g = _device_by(store, ip=ctx["gateway"])
        if i == 0:
            gw = g
        if g:
            _record(store, g["id"], "router", rep)
        for igd in rep["igd"]:
            for m in igd["mappings"]:
                target = _device_by(store, ip=m["internal_ip"]) or g
                if target:
                    store.add_evidence(
                        target["id"], "outside", "forward", json.dumps({**m, "wan": rep["wan"]})
                    )
        n_maps = sum(len(x["mappings"]) for x in rep["igd"])
        log(
            f"outside-in: router on {ctx['cidr']}: WAN {rep['wan']}, "
            f"UPnP {'on' if rep['igd'] else 'off/absent'} ({n_maps} mappings), "
            f"NAT-PMP {'on' if rep['natpmp'] else 'off'}"
        )
        for mac, addr in exposure.one_per_device(exposure.v6_neighbors(ctx["iface"])).items():
            v6_targets[mac] = addr
    out["layers"].append("router")
    by_addr = {a: m for m, a in v6_targets.items()}

    active = None
    if conf.get("PROBE_SSH"):
        ports = top_ports()
        log(f"outside-in: probing {len(ports)} TCP ports from {conf['PROBE_SSH']} ...")
        active = run_probe(conf, ports, v6=list(by_addr))
    elif conf.get("PROBE_URL"):
        url = conf["PROBE_URL"]
        log(f"outside-in: asking reflector {url} ...")
        r4 = exposure.reflector_check(url, 4)
        active = {
            "open": r4["open"],
            "scanned": r4["scanned"],
            "seconds": r4["seconds"],
            "family": "ipv4",
            "probe": httpx_host(url),
            "at": time.strftime("%F %T"),
            "v6": [],
        }
        if router_ext and r4.get("seen_ip") and r4["seen_ip"] != router_ext:
            active["vpn"] = True  # the reflector saw some other exit: we tested the VPN
        try:
            r6 = exposure.reflector_check(url, 6, extra=list(by_addr))
            active["v6"] = r6.get("extra", [])
        except Exception as e:  # noqa: BLE001 - no IPv6 path is common and fine
            log(f"outside-in: no IPv6 check ({e.__class__.__name__})")
    if active:
        active.setdefault("probe", conf.get("PROBE_SSH"))
        active.setdefault("at", time.strftime("%F %T"))
        log(f"outside-in: {len(active['open'])} open {active['open']} in {active['seconds']}s")
        if gw:
            _record(store, gw["id"], "result", {k: v for k, v in active.items() if k != "v6"})
        for r in active.get("v6", []):
            d = _device_by(store, mac=by_addr.get(r["addr"]))
            if d:
                _record(
                    store,
                    d["id"],
                    "v6",
                    {"open": r["open"], "probe": active["probe"], "at": active["at"]},
                )
        out["layers"].append("active")
        out.update(active)

    if conf.get("INTERNETDB") == "1":
        try:
            passive = exposure.internetdb()
            if gw:
                _record(store, gw["id"], "passive", passive)
            out["layers"].append("passive")
            log(f"outside-in: InternetDB knows {passive['ports'] or 'nothing'}")
        except Exception as e:  # noqa: BLE001
            log(f"outside-in: InternetDB lookup failed: {e}")

    if rethreat:  # the watch loop runs the threat pass itself right after
        threat.run(store, log=log)
    return out


def httpx_host(url: str) -> str:
    import httpx

    return httpx.URL(url).host


WHY = {
    22: "SSH",
    23: "Telnet",
    80: "a web server",
    443: "a web server",
    445: "SMB file sharing",
    3389: "Remote Desktop",
    5900: "VNC",
    7547: "TR-069 ISP management",
    8181: "the gateway's remote-management page",
    11434: "the Ollama API (no authentication)",
    32400: "Plex",
    51820: "WireGuard",
}


def findings(res: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for p in res.get("open", []):
        what = WHY.get(p, "a service")
        sev = "critical" if p in (23, 445, 3389, 5900, 11434) else "high"
        if p == 51820:
            sev = "info"  # WireGuard answering TCP would be odd, but it's usually deliberate
        out.append(
            {
                "severity": sev,
                "kind": "outside",
                "title": f"TCP {p} reachable from the internet",
                "detail": f"An outside-in check from {res.get('probe')} connected to TCP {p} "
                f"on your public {res.get('family', 'ipv4')} address: {what}. "
                "If you didn't open this on purpose, close it on the gateway.",
                "data": {"port": p, "at": res.get("at")},
            }
        )
    if not out:
        out.append(
            {
                "severity": "info",
                "kind": "outside",
                "title": f"Outside-in: 0 of {res.get('scanned')} TCP ports reachable",
                "detail": f"Checked from {res.get('probe')} at {res.get('at')}: nothing on "
                f"your public {res.get('family', 'ipv4')} address accepted a "
                "connection. UDP was not tested.",
                "data": {"at": res.get("at")},
            }
        )
    return out


DANGEROUS = {23, 139, 445, 2375, 3389, 5900, 11434}
OUTER = {
    "cgnat": "your internet connection is behind carrier-grade NAT, so the internet can't reach "
    "it over IPv4",
    "private": "this router sits behind another router, so it's reachable only from that "
    "router's network unless the outer one forwards the port too",
}


def vpn_findings(res: dict[str, Any]) -> list[dict[str, Any]]:
    if not res.get("vpn"):
        return []
    return [
        {
            "severity": "low",
            "kind": "outside",
            "title": "Outside-in check went through a VPN",
            "detail": "The reflector saw a different public address than your router has, so it "
            "tested your VPN's exit, not your home. Pause the VPN on this computer and re-run.",
            "data": {"at": res.get("at")},
        }
    ]


def router_findings(rep: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    if rep.get("wan") == "cgnat":
        out.append(
            {
                "severity": "info",
                "kind": "outside",
                "title": "Carrier-grade NAT: the internet can't reach you over IPv4",
                "detail": "Your router's internet address is a shared carrier address "
                "(100.64.0.0/10). Nothing on the internet can start an IPv4 connection to "
                "your home, whatever is forwarded. IPv6 is separate.",
                "data": {"at": rep.get("at")},
            }
        )
    n = sum(len(g.get("mappings", [])) for g in rep.get("igd", []))
    if rep.get("igd"):
        out.append(
            {
                "severity": "medium" if n else "low",
                "kind": "config",
                "title": f"UPnP port opening is on ({n} open)" if n else "UPnP port opening is on",
                "detail": "Any device or program on your network can ask this router to open "
                "a port to the internet, without asking you. Consoles and media servers use it; "
                "so does malware. Turn UPnP off on the router unless something you rely on "
                "breaks, and forward that one port by hand instead.",
                "data": {"mappings": n, "wan": rep.get("wan")},
            }
        )
    return out


def forward_findings(m: dict[str, Any]) -> list[dict[str, Any]]:
    port, proto = m.get("external_port"), m.get("proto", "TCP")
    what = WHY.get(m.get("internal_port"), "a service")
    if proto == "UDP":
        sev = "low"  # game/voice traffic: usually what the console asked for
    else:
        sev = "critical" if m.get("internal_port") in DANGEROUS else "high"
    note = ""
    if m.get("wan") in OUTER:
        sev, note = "low", f" Lower risk for now: {OUTER[m['wan']]}."
    desc = f' ("{m["description"]}")' if m.get("description") else ""
    return [
        {
            "severity": sev,
            "kind": "outside",
            "title": f"Router forwards {proto} {port} from the internet to this device",
            "detail": f"The router's UPnP table maps {proto} {port} on your internet address to "
            f"port {m.get('internal_port')} here{desc}: {what}. A program on this device asked "
            f"for it; anyone on the internet can now connect.{note}",
            "data": {"port": port, "proto": proto},
        }
    ]


def v6_findings(r: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for p in r.get("open", []):
        out.append(
            {
                "severity": "critical" if p in DANGEROUS else "high",
                "kind": "outside",
                "title": f"TCP {p} reachable from the internet over IPv6",
                "detail": "This device has its own public IPv6 address, and "
                f"{WHY.get(p, 'a service')} on TCP {p} accepted a connection from "
                f"{r.get('probe')} at {r.get('at')}. "
                "IPv6 skips NAT entirely: the router's IPv6 firewall is the only thing in the "
                "way. Turn on its inbound IPv6 blocking, or close the service.",
                "data": {"port": p, "at": r.get("at")},
            }
        )
    return out


def passive_findings(p: dict[str, Any]) -> list[dict[str, Any]]:
    if not p.get("known"):
        return [
            {
                "severity": "info",
                "kind": "outside",
                "title": "Internet scanners have nothing on record for your address",
                "detail": "Shodan InternetDB had no open ports for your public IP "
                f"({p.get('at')}).",
                "data": {"at": p.get("at")},
            }
        ]
    return [
        {
            "severity": "critical" if port in DANGEROUS else "high",
            "kind": "outside",
            "title": f"Internet scanners recorded TCP {port} open on your address",
            "detail": f"Shodan's weekly scan saw {WHY.get(port, 'a service')} on TCP {port} "
            "of your public IP. That's what attackers' search engines show. If it's not "
            "deliberate, close it; if your IP changed recently it may be the previous owner's.",
            "data": {"port": port, "at": p.get("at")},
        }
        for port in p.get("ports", [])
    ]


def evidence_findings(e: dict[str, Any]) -> list[dict[str, Any]]:
    """Dispatch for threat.assess_device: one stored 'outside' evidence row -> findings."""
    v = json.loads(e["value"])
    return {
        "result": lambda: findings(v) + vpn_findings(v),
        "router": lambda: router_findings(v),
        "forward": lambda: forward_findings(v),
        "v6": lambda: v6_findings(v),
        "passive": lambda: passive_findings(v),
    }.get(e["key"], list)()
