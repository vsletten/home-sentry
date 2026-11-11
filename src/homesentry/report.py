"""Household security report: one self-contained, printable HTML page.

`homesentry report -o report.html` or /report in the UI. Local data only; nothing is
sent anywhere to build it.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from pathlib import Path
from typing import Any

from . import __version__, data_dir, netmap, plan
from .store import Store


def context(store: Store, icon=lambda t: "❔", days: int = 7) -> dict[str, Any]:
    p = plan.build(store)
    names = {
        d["id"]: d["label"] or d["model"] or d["make"] or d["ip"] or f"device {d['id']}"
        for d in store.devices(include_retired=True)
    }
    for a in p["actions"]:
        a["rendered"] = plan.render_title(a, names.get)
    worst: dict[int, str] = {}
    for f in store.findings():
        if f["severity"] != "info" and (
            f["device_id"] not in worst
            or plan.SEV.index(f["severity"]) < plan.SEV.index(worst[f["device_id"]])
        ):
            worst[f["device_id"]] = f["severity"]
    devices = sorted(
        store.devices(),
        key=lambda d: (plan.SEV.index(worst.get(d["id"], "info")), (d["label"] or "").lower()),
    )
    since = time.time() - days * 86400
    events = store.events(limit=200, since=since)
    gw = next((d for d in devices if d["device_type"] == "gateway"), None)
    outside = None
    if gw:
        for e in store.evidence(gw["id"]):
            if e["source"] == "outside" and e["key"] == "result":
                outside = json.loads(e["value"]) | {"ts": e["ts"]}
    kev = data_dir() / "intel" / "kev.json"
    hidden = [n for n in netmap.model(store, icon)["nodes"] if n["hidden"] is not None]
    trend = [s["summary"].get("score") for s in store.scans(90) if "score" in s["summary"]]
    return {
        "generated": dt.datetime.now().strftime("%A %d %B %Y, %H:%M"),
        "version": __version__,
        "plan": p,
        "names": names,
        "devices": devices,
        "worst": worst,
        "events": events,
        "days": days,
        "outside": outside,
        "kev_age_h": round((time.time() - kev.stat().st_mtime) / 3600, 1) if kev.exists() else None,
        "hidden": hidden,
        "trend": trend,
        "last_scan": store.last_scan(),
        "good_news": [e for e in events if e["kind"] in ("finding_resolved", "firmware_changed")],
    }


def render(store: Store) -> str:
    from .web.ui import env

    e = env()
    return e.get_template("report.html").render(**context(store, e.globals["icon"]))


def write(store: Store, path: Path) -> Path:
    path.write_text(render(store))
    return path
