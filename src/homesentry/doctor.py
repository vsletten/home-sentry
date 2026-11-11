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
    for tool, why in (
        ("ip", "LAN discovery"),
        ("nmap", "port/service scans"),
        ("avahi-browse", "mDNS discovery"),
        ("tailscale", "device names from your tailnet"),
        ("ssh", "outside-in probe"),
    ):
        p = shutil.which(tool)
        add(f"tool {tool}", OK if p else (FAIL if tool == "ip" else WARN), p or f"missing ({why})")
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
