"""`homesentry doctor`: is this appliance healthy? Every check is read-only."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any

from . import __version__, config_dir, data_dir
from .store import Store

OK, WARN, FAIL = "ok", "warn", "fail"


def _age(ts: float | None) -> str:
    if not ts:
        return "never"
    h = (time.time() - ts) / 3600
    return f"{h:.1f}h ago" if h < 48 else f"{h / 24:.0f}d ago"


def checks(store: Store, runner=subprocess.run) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(name: str, status: str, msg: str) -> None:
        out.append({"check": name, "status": status, "msg": msg})

    d = data_dir()
    mode = d.stat().st_mode & 0o777
    add("data dir", OK if not mode & 0o077 else FAIL, f"{d} (mode {mode:o})")
    from . import discover, netinfo

    plat = netinfo.platform()
    try:
        ctx = netinfo.lan_context()
        add("network", OK, f"{ctx['cidr']} on {ctx['iface']} via {ctx['gateway'] or '?'} ({plat})")
    except Exception as e:  # noqa: BLE001 - the check's whole point is to report this
        add("network", FAIL, f"can't read this machine's network on {plat}: {e}")
    required = {"linux": ("ip",), "darwin": ("route", "ifconfig", "arp")}.get(plat, ())
    for tool in required:
        p = shutil.which(tool)
        add(f"tool {tool}", OK if p else FAIL, p or "missing (LAN discovery)")
    engine = discover.port_engine()
    nmap = shutil.which("nmap")
    if engine == "nmap" and nmap and os.path.realpath(nmap).startswith("/snap/"):
        # snap-confine refuses to run under NoNewPrivileges/ProtectSystem/PrivateTmp,
        # so a snap nmap silently fails every port scan inside the hardened units.
        add(
            "tool nmap",
            FAIL,
            f"{nmap} is a snap: it can't run in the sandboxed units; "
            "install the distro package (apt install nmap) or drop HOMESENTRY_PORTSCAN=nmap",
        )
    else:
        add("port scanner", OK, "built-in" if engine == "native" else f"nmap ({nmap})")
    try:
        import zeroconf  # noqa: F401

        add("mdns", OK, "built-in (zeroconf)")
    except ImportError:
        av = shutil.which("avahi-browse")
        add("mdns", OK if av else WARN, av or "no zeroconf and no avahi-browse: mDNS is off")
    ts = netinfo.tailscale_cmd()
    add("tool tailscale", OK if ts else WARN, ts[0] if ts else "missing (names from your tailnet)")
    ssh = shutil.which("ssh")
    add("tool ssh", OK if ssh else WARN, ssh or "missing (outside-in probe)")
    for name, need in (
        ("env", "OLLAMA_API_KEY for the wizard/Ask"),
        ("gateway.env", "gateway reader"),
        ("probe.env", "outside-in check"),
        ("notify.env", "push alerts"),
    ):
        f = config_dir() / name
        if not f.exists():
            add(f"config {name}", WARN if name != "notify.env" else OK, f"not set up ({need})")
            continue
        m = f.stat().st_mode & 0o777
        add(
            f"config {name}",
            OK if not m & 0o077 else FAIL,
            f"mode {m:o}" + ("" if not m & 0o077 else " (must be 600)"),
        )
    add(
        "llm key",
        OK if os.environ.get("OLLAMA_API_KEY") else WARN,
        "OLLAMA_API_KEY present"
        if os.environ.get("OLLAMA_API_KEY")
        else "OLLAMA_API_KEY not in this environment (the service reads ~/.config/homesentry/env)",
    )
    kev = d / "intel" / "kev.json"
    kev_ts = kev.stat().st_mtime if kev.exists() else None
    add(
        "threat intel",
        OK if kev_ts and time.time() - kev_ts < 3 * 86400 else WARN,
        f"CISA KEV cache {_age(kev_ts)}",
    )
    last = store.last_scan()
    lt = last["finished"] if last else None
    add("last scan", OK if lt and time.time() - lt < 6 * 3600 else WARN, _age(lt))
    ps = store.last_scan_with("ports")
    add(
        "last port scan",
        OK if ps and time.time() - ps["finished"] < 2 * 86400 else WARN,
        _age(ps["finished"] if ps else None),
    )
    if plat != "linux":
        add("background service", WARN, f"no background service for {plat} yet")
        return out
    for unit in ("homesentry.service", "homesentry-watch.timer"):
        try:
            r = runner(
                ["systemctl", "--user", "is-active", unit],
                capture_output=True,
                text=True,
                timeout=5,
            )
            state = (r.stdout or "").strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            state = "unknown"
        add(f"unit {unit}", OK if state == "active" else WARN, state)
    return out


def main(store: Store) -> int:
    rows = checks(store)
    sym = {OK: "✓", WARN: "!", FAIL: "✗"}
    print(f"HomeSentry {__version__} doctor")
    for r in rows:
        print(f"  {sym[r['status']]} {r['check']:<24} {r['msg']}")
    bad = sum(r["status"] == FAIL for r in rows)
    warn = sum(r["status"] == WARN for r in rows)
    print(f"{len(rows)} checks: {bad} failing, {warn} warnings")
    return 1 if bad else 0
