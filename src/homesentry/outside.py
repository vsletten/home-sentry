"""Outside-in exposure check from a host you own (e.g. a VPS), over SSH.

The probe script is piped to `python3 -` on the probe host's stdin: nothing is installed
or written there. It targets the address the probe host sees our SSH connection coming
from (SSH_CLIENT), i.e. the home WAN IP, so the workstation never needs to know or store
it, and no third-party "port check" service ever learns anything.

TCP connect scan only (no raw packets, no banners), bounded concurrency so a busy CI box
barely notices. Config: ~/.config/homesentry/probe.env
    PROBE_SSH=ci-vps                               # ssh alias / user@host
    PROBE_SSH_AGENT=/run/user/1000/keyring/ssh     # optional IdentityAgent
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
ports = [int(p) for p in sys.argv[1:]]
async def one(sem, p):
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(target, p), 1.5)
            w.close()
            return p
        except Exception:
            return None
async def main():
    sem = asyncio.Semaphore(64)
    t = time.time()
    hits = [p for p in await asyncio.gather(*(one(sem, p) for p in ports)) if p]
    fam = "ipv6" if ":" in target else "ipv4"
    print(json.dumps({"open": sorted(hits), "scanned": len(ports),
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
    return out if out.get("PROBE_SSH") else None


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
    else:
        ports = list(FALLBACK_PORTS)
    return sorted(set(ports) | set(ALWAYS))


def ssh_cmd(conf: dict[str, str]) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if conf.get("PROBE_SSH_AGENT"):
        cmd += ["-o", f"IdentityAgent={conf['PROBE_SSH_AGENT']}"]
    return cmd + [conf["PROBE_SSH"]]


def run_probe(conf: dict[str, str], ports: list[int], runner=subprocess.run) -> dict[str, Any]:
    cmd = ssh_cmd(conf) + ["python3", "-", *map(str, ports)]
    r = runner(cmd, input=REMOTE, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"probe via {conf['PROBE_SSH']} failed: {r.stderr.strip()[-300:]}")
    res = json.loads(r.stdout.strip().splitlines()[-1])
    res.update(probe=conf["PROBE_SSH"], at=time.strftime("%F %T"))
    return res


def run_and_record(store, log=print, rethreat: bool = True) -> dict[str, Any] | None:
    """Probe, then attach the result to the gateway device (where WAN exposure lives)."""
    from . import discover, threat

    conf = load_conf()
    if not conf:
        log(f"outside-in: not configured (create {conf_path()} with PROBE_SSH=<ssh alias>)")
        return None
    ports = top_ports()
    log(f"outside-in: probing {len(ports)} TCP ports from {conf['PROBE_SSH']} ...")
    res = run_probe(conf, ports)
    log(f"outside-in: {len(res['open'])} open {res['open']} in {res['seconds']}s")
    gw_ip = discover.lan_context()["gateway"]
    gw = next((d for d in store.devices() if d["ip"] == gw_ip and d["mac"]), None)
    if gw:
        store.clear_evidence(gw["id"], "outside")
        store.add_evidence(gw["id"], "outside", "result", json.dumps(res))
        if rethreat:  # the watch loop runs the threat pass itself right after
            threat.run(store, log=log)
    return res


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
                "connection. UDP and IPv6 clients were not tested.",
                "data": {"at": res.get("at")},
            }
        )
    return out
