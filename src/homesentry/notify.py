"""Optional push notifications for timeline events. OFF unless configured.

~/.config/homesentry/notify.env (mode 600):
    NOTIFY_URL=https://ntfy.sh/<your-private-topic>   # or a self-hosted ntfy / any webhook
    NOTIFY_TOKEN=...                                  # optional bearer token
    NOTIFY_MIN_SEVERITY=medium                        # critical|high|medium|low|info
    NOTIFY_NAMES=0                                    # 1 = include your device labels

ntfy-compatible: one POST per scan with a plain-text body and Title/Priority/Tags headers.
A push leaves the house (ntfy.sh is a third party), so by default it names devices only by
type ("nas: Went offline"). Labels are opt-in, and event titles never carry IPs or MACs.
Nothing is sent at all unless configured.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .store import Store


def conf_path() -> Path:
    from . import config_dir

    return config_dir() / "notify.env"


SEV = ["critical", "high", "medium", "low", "info"]


def load_conf(path: Path | None = None) -> dict[str, str] | None:
    path = path or conf_path()  # resolved per call: a default arg would freeze it at import
    if not path.exists():
        return None
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must be mode 600 (it may hold a token)")
    conf = {}
    for line in path.read_text().splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and not k.startswith("#"):
            conf[k.strip()] = v.strip().strip('"').strip("'")
    return conf if conf.get("NOTIFY_URL") else None


def compose(
    store: Store, events: list[dict[str, Any]], min_sev: str, labels: bool = False
) -> tuple[str, str, str]:
    floor = SEV.index(min_sev) if min_sev in SEV else SEV.index("medium")
    picked = sorted(
        (e for e in events if SEV.index(e["severity"]) <= floor),
        key=lambda e: SEV.index(e["severity"]),
    )
    if not picked:
        return "", "", ""
    names = {
        d["id"]: (d["label"] or d["model"] or d["make"] if labels else None)
        or (d["device_type"] or "").replace("_", " ")
        or "a device"
        for d in store.devices(include_retired=True)
    }

    def who(e: dict[str, Any]) -> str:
        return names.get(e["device_id"], "a device") if e["device_id"] else "household"

    lines = [f"[{e['severity']}] {who(e)}: {e['title']}" for e in picked[:12]]
    if len(picked) > 12:
        lines.append(f"... and {len(picked) - 12} more")
    title = f"HomeSentry: {len(picked)} change{'s' * (len(picked) != 1)}"
    prio = "high" if picked[0]["severity"] in ("critical", "high") else "default"
    return title, "\n".join(lines), prio


def send(store: Store, events: list[dict[str, Any]], log=print, poster=httpx.post) -> int:
    try:
        conf = load_conf()
    except PermissionError as e:
        log(f"notify: {e}")
        return 0
    if not conf:
        return 0
    title, body, prio = compose(
        store,
        events,
        conf.get("NOTIFY_MIN_SEVERITY", "medium"),
        labels=conf.get("NOTIFY_NAMES", "0").lower() in ("1", "true", "yes"),
    )
    if not body:
        return 0
    headers = {"Title": title, "Priority": prio, "Tags": "shield"}
    if conf.get("NOTIFY_TOKEN"):
        headers["Authorization"] = f"Bearer {conf['NOTIFY_TOKEN']}"
    try:
        r = poster(conf["NOTIFY_URL"], content=body.encode(), headers=headers, timeout=10)
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001 - a dead webhook must not break monitoring
        log(f"notify: failed ({type(e).__name__})")
        return 0
    n = body.count("\n") + 1
    log(f"notify: sent {n} line(s)")
    return n
