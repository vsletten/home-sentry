"""`homesentry service install|uninstall|status`: run HomeSentry in the background at login.

macOS: one LaunchAgent (~/Library/LaunchAgents/com.homesentry.agent.plist) running
`homesentry serve --watch-every 30`, so a headless Mac mini is a complete appliance: UI on
loopback (or $HOMESENTRY_BIND) plus monitoring, no Terminal window. Linux uses the systemd
user units in deploy/systemd (see the README); `status` reports them.

The desktop app doesn't need this: it runs the same server itself while it's open (and in the
menu bar when its window is closed).
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

LABEL = "com.homesentry.agent"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def executable() -> str:
    """The homesentry entry point that is running now (uv tool, venv or bundled app)."""
    argv0 = Path(sys.argv[0])
    if argv0.name == "homesentry" and argv0.exists():
        return str(argv0.resolve())
    return shutil.which("homesentry") or str(argv0.resolve())


def launch_agent(exe: str, every_min: float, log_dir: Path, bind: str | None) -> dict[str, Any]:
    args = [exe, "serve", "--watch-every", f"{every_min:g}"]
    if bind:
        args += ["--host", bind]
    return {
        "Label": LABEL,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},  # restart on crash, not after a clean stop
        "ProcessType": "Background",
        "Nice": 10,
        "LowPriorityIO": True,
        "ThrottleInterval": 30,
        "StandardOutPath": str(log_dir / "agent.log"),
        "StandardErrorPath": str(log_dir / "agent.log"),
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONUNBUFFERED": "1"},
    }


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, timeout=20)


def install(every_min: float = 30, bind: str | None = None) -> str:
    if sys.platform != "darwin":
        raise SystemExit("on Linux use the systemd user units in deploy/systemd (see README)")
    from . import data_dir

    logs = data_dir() / "logs"
    logs.mkdir(exist_ok=True, mode=0o700)
    p = plist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    domain = f"gui/{os.getuid()}"
    if p.exists():
        _launchctl("bootout", domain, str(p))
    p.write_bytes(plistlib.dumps(launch_agent(executable(), every_min, logs, bind)))
    p.chmod(0o644)
    r = _launchctl("bootstrap", domain, str(p))
    if r.returncode != 0:
        raise SystemExit(f"launchctl bootstrap failed: {r.stderr.strip() or r.returncode}")
    return str(p)


def uninstall() -> bool:
    if sys.platform != "darwin":
        raise SystemExit("on Linux: systemctl --user disable --now homesentry.service ...")
    p = plist_path()
    if not p.exists():
        return False
    _launchctl("bootout", f"gui/{os.getuid()}", str(p))
    p.unlink()
    return True


def status() -> dict[str, Any]:
    if sys.platform == "darwin":
        p = plist_path()
        r = _launchctl("print", f"gui/{os.getuid()}/{LABEL}")
        state = "not installed"
        if p.exists():
            state = "loaded" if r.returncode == 0 else "installed, not loaded"
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("state = "):
                    state = line.split("= ", 1)[1]
        return {"kind": "launchd", "plist": str(p), "state": state}
    units = {}
    for u in ("homesentry.service", "homesentry-watch.timer"):
        try:
            r = subprocess.run(
                ["systemctl", "--user", "is-active", u], capture_output=True, text=True, timeout=5
            )
            units[u] = r.stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            units[u] = "unknown"
    return {"kind": "systemd", "units": units}
