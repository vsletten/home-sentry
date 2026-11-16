"""Remote sensors: other machines in the house that see networks this one can't.

A laptop or Mac mini joined to the Wi-Fi sits *behind* a Wi-Fi router's NAT, on a network
the appliance's wire never touches. A sensor is just such a machine running `homesentry
probe` (stores nothing) over SSH; the appliance folds what it saw into the inventory with
exactly the pipeline its own scan uses.

Config: ~/.config/homesentry/sensors.env (mode 600)
    SENSORS=macbot-zero,laptop          # ssh aliases / user@host, comma-separated
    SENSOR_SSH_AGENT=/run/user/1000/keyring/ssh   # optional IdentityAgent
    SENSOR_PATH=~/.local/bin:/opt/homebrew/bin    # optional, prepended to PATH remotely

Traffic: one SSH session per sensor per scan, inside the house. The sensor is only asked
for networks the appliance does not already scan itself (--skip), so nothing is scanned
twice. A sensor that's asleep or unreachable is skipped and its networks keep their last
known state: no "everything went offline" storm when a laptop closes its lid.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

Sighting = tuple[str, str, str]


def conf_path() -> Path:
    from . import config_dir

    return config_dir() / "sensors.env"


def load_conf() -> dict[str, Any] | None:
    p = conf_path()
    if not p.exists():
        return None
    if p.stat().st_mode & 0o077:
        raise PermissionError(f"{p} must be mode 600")
    env: dict[str, str] = {}
    for line in p.read_text().splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and not k.startswith("#"):
            env[k.strip()] = v.strip().strip("'\"")
    hosts = [h.strip() for h in env.get("SENSORS", "").split(",") if h.strip()]
    if not hosts:
        return None
    return {
        "hosts": hosts,
        "agent": env.get("SENSOR_SSH_AGENT") or None,
        "path": env.get("SENSOR_PATH") or "$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin",
    }


def remote_command(conf: dict[str, Any], skip: list[str], ports: bool) -> str:
    args = ["homesentry", "probe", "--json"]
    for cidr in skip:
        args += ["--skip", cidr]
    if ports:
        args.append("--ports")
    path = conf["path"].replace("~", "$HOME")
    return f'export PATH="{path}:$PATH"; ' + " ".join(shlex.quote(a) for a in args)


def run_one(host: str, conf: dict[str, Any], skip: list[str], ports: bool) -> dict[str, Any]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if conf.get("agent"):
        cmd += ["-o", f"IdentityAgent={conf['agent']}"]
    cmd += [host, remote_command(conf, skip, ports)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=420 if ports else 180)
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "timed out"}
    except OSError as e:
        return {"host": host, "error": str(e)}
    try:
        probe = json.loads(r.stdout)
    except json.JSONDecodeError:
        err = (r.stderr or "").strip().splitlines()
        return {"host": host, "error": err[-1][:200] if err else f"exit {r.returncode}"}
    return {"host": host, "probe": probe}


def start(skip: list[str], ports: bool) -> list[Future] | None:
    """Kick off every configured sensor in the background (they run while we scan)."""
    try:
        conf = load_conf()
    except PermissionError:
        raise
    if not conf:
        return None
    ex = ThreadPoolExecutor(len(conf["hosts"]))
    futs = [ex.submit(run_one, h, conf, skip, ports) for h in conf["hosts"]]
    ex.shutdown(wait=False)
    return futs


# ---- probe JSON -> the same shape a local collection has --------------------------------
def networks_from_probe(probe: dict[str, Any], sensor: str) -> list[dict[str, Any]]:
    """Each network the sensor saw, as the collected-network dict scan._apply_network takes."""
    out = []
    for n in probe.get("networks", []):
        hosts = n.get("hosts") or {}
        by: dict[str, dict[str, list[Sighting]]] = {"mdns": {}, "ssdp": {}, "ports": {}}
        neigh, names = {}, {}
        for ip, h in hosts.items():
            if h.get("mac"):
                neigh[ip] = h["mac"]
            if h.get("ptr"):
                names[ip] = h["ptr"]
            for s in h.get("sightings", []):
                src = s[0]
                if src in by:  # the sensor's own tailscale view is not this network's truth
                    by[src].setdefault(ip, []).append(tuple(s))
        ports_ran = (n.get("counts") or {}).get("ports") is not None
        out.append(
            {
                "ctx": {k: n.get(k, "") for k in ("iface", "local_ip", "cidr", "gateway", "mac")},
                "neigh": neigh,
                "names": names,
                "mdns": by["mdns"],
                "ssdp": by["ssdp"],
                "svc": by["ports"] if ports_ran else None,
                "via": sensor,
            }
        )
    return out


def sensor_macs(probe: dict[str, Any]) -> set[str]:
    """Every MAC the sensor itself owns (it reports skipped networks' interfaces too)."""
    macs = {i.get("mac") for i in probe.get("interfaces", [])}
    macs |= {n.get("mac") for n in probe.get("networks", [])}
    return {m for m in macs if m}


def apple_ids(sightings) -> set[str]:
    """Per-machine AirPlay ids: the `deviceid=` TXT and the `<12 hex>@Name` RAOP instance."""
    out: set[str] = set()
    for src, key, val in sightings:
        if src != "mdns":
            continue
        if key == "name" and (m := re.match(r"^([0-9A-F]{12})@", val)):
            out.add(m.group(1))
        elif key.startswith("txt:") and (m := re.search(r'"deviceid=([0-9A-F:]{17})"', val)):
            out.add(m.group(1).replace(":", ""))
    return out


GENERIC_HOSTS = re.compile(
    r"^(android|iphone|ipad|localhost|esp[-_]?[0-9a-f]*|[0-9a-f-]{32,36}|[0-9a-f]{12,})(-\d+)?$",
    re.I,
)


def mdns_hosts(sightings) -> set[str]:
    """Distinctive `<name>.local` hosts (macOS makes them unique on a network by adding -2)."""
    out = set()
    for src, key, val in sightings:
        if src == "mdns" and key == "host" and val.lower().endswith(".local"):
            name = val[:-6].lower()
            if name and not GENERIC_HOSTS.match(name):
                out.add(name)
    return out


def same_box(mac_a: str, mac_b: str, window: int = 32) -> bool:
    """Two MACs that are one multi-port device: same vendor block and nearly consecutive.
    Routers allocate a run of addresses (LAN, WAN, each radio): Arista/Mojo uses ...:89:9f on
    the wired side and ...:89:90 for the Wi-Fi network it routes."""
    a, b = mac_a.lower().split(":"), mac_b.lower().split(":")
    if len(a) != 6 or len(b) != 6 or a[:3] != b[:3] or mac_a == mac_b:
        return False
    if int(a[0], 16) & 2:  # locally administered (random) addresses prove nothing
        return False
    na, nb = int("".join(a[3:]), 16), int("".join(b[3:]), 16)
    return abs(na - nb) <= window
