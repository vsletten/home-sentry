"""Posture score + action plan: turn a pile of findings into "do these things, in this order".

Score: 100 minus weighted findings (capped per device, so one awful box can't sink the
house alone), minus a little for devices nobody can identify. Accepted risks don't count.
The plan maps every finding to a remediation playbook (kbdata/playbooks.yaml, generic KB
knowledge) and ranks actions by how much score they buy per minute of effort.
"""

from __future__ import annotations

import math
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from . import data_dir
from .store import Store
from .watch import finding_key

PLAYBOOKS = Path(__file__).parent / "kbdata" / "playbooks.yaml"
WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
# Per-device penalty saturates smoothly toward DEVICE_CAP: one awful box can't sink the
# whole house, yet every fix on it still moves the score (a hard cap made some fixes +0).
DEVICE_CAP = 18.0
UNKNOWN_EACH, UNKNOWN_CAP = 1.0, 6.0
SEV = ["critical", "high", "medium", "low", "info"]
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


@cache
def _builtin() -> tuple[dict[str, Any], ...]:
    return tuple(yaml.safe_load(PLAYBOOKS.read_text()) or [])


def playbooks() -> list[dict[str, Any]]:
    """Local additions (data_dir()/kb/playbooks.yaml) win over the shipped pack."""
    local = data_dir() / "kb" / "playbooks.yaml"
    extra = yaml.safe_load(local.read_text()) if local.exists() else []
    return list(extra or []) + list(_builtin())


def grade(score: float) -> str:
    return next(g for floor, g in GRADES if score >= floor)


def _matches(pb: dict[str, Any], f: dict[str, Any], d: dict[str, Any]) -> bool:
    m = pb.get("match") or {}
    if "kind" in m and f["kind"] not in m["kind"]:
        return False
    if "device_type" in m and (d.get("device_type") or "") not in m["device_type"]:
        return False
    if "title" in m and not re.search(m["title"], f["title"]):
        return False
    if "make" in m and not re.search(m["make"], d.get("make") or ""):
        return False
    return True


def _penalty(findings: list[dict[str, Any]], unknown: int) -> float:
    per: dict[int, float] = {}
    for f in findings:
        per[f["device_id"]] = per.get(f["device_id"], 0.0) + WEIGHT[f["severity"]]
    dev = sum(DEVICE_CAP * (1 - math.exp(-v / DEVICE_CAP)) for v in per.values())
    return dev + min(UNKNOWN_CAP, unknown * UNKNOWN_EACH)


def _inputs(store: Store) -> tuple[list[dict], list[dict], dict, list[dict]]:
    devices = {d["id"]: d for d in store.devices()}
    acc = store.accepted()
    live, accepted = [], []
    for f in store.findings():
        if f["device_id"] not in devices or f["severity"] == "info":
            continue
        f = dict(f, fkey=finding_key(f))
        (accepted if (f["device_id"], f["fkey"]) in acc else live).append(f)
    # "unknown" = we can't even say what kind of thing it is (a Mac with no model is known)
    unknown = [
        d
        for d in devices.values()
        if not d["confirmed"]
        and (not d["device_type"] or (d["confidence"] or 0) < 0.25)
        and d.get("online") != 0
    ]
    return live, accepted, devices, unknown


def score(store: Store) -> dict[str, Any]:
    live, _, _, unknown = _inputs(store)
    s = round(max(0.0, 100.0 - _penalty(live, len(unknown))))
    return {"score": s, "grade": grade(s)}


def build(store: Store) -> dict[str, Any]:
    live, accepted, devices, unknown = _inputs(store)
    base_pen = _penalty(live, len(unknown))
    pbs = playbooks()
    acts: dict[str, dict[str, Any]] = {}
    covered_devices: dict[int, dict[str, Any]] = {}
    for pb in pbs:  # whole-device playbooks first: they claim everything on that box.
        if pb.get("covers") == "device":  # (match on device fields only: make/device_type)
            for d in devices.values():
                if _matches(pb, {"kind": "", "title": ""}, d):
                    covered_devices.setdefault(d["id"], pb)
    for f in live:
        d = devices[f["device_id"]]
        pb = covered_devices.get(d["id"]) or next(
            (p for p in pbs if p.get("covers") != "device" and _matches(p, f, d)), None
        )
        pb = pb or {
            "id": "review",
            "title": "Review: " + f["title"] + " on {device}",
            "who": "you",
            "effort_min": 10,
            "why": f.get("detail") or "",
            "steps": ["Read the finding on the device page and decide: fix or accept."],
        }
        household = pb.get("group") == "household"
        key = f"{pb['id']}:{'all' if household else d['id']}"
        a = acts.setdefault(
            key,
            {
                "key": key,
                "playbook": pb["id"],
                "title": pb["title"],
                "why": " ".join((pb.get("why") or "").split()),
                "steps": pb.get("steps") or [],
                "who": pb.get("who", "you"),
                "effort_min": int(pb.get("effort_min", 10)),
                "guide": pb.get("guide"),
                "household": household,
                "device_ids": [],
                "findings": [],
            },
        )
        if d["id"] not in a["device_ids"]:
            a["device_ids"].append(d["id"])
        a["findings"].append(
            {k: f[k] for k in ("device_id", "fkey", "title", "severity", "kind", "id")}
        )
    if unknown:
        acts["identify:all"] = {
            "key": "identify:all",
            "playbook": "identify",
            "title": f"Identify {len(unknown)} unknown device{'s' * (len(unknown) != 1)}",
            "why": "You can't secure what you can't name. Each unknown device is a box nobody "
            "is watching. The wizard takes a photo of the label and does the rest.",
            "steps": ["Open each unknown device and use the wizard: a label photo is enough."],
            "who": "you",
            "effort_min": 3 * len(unknown),
            "guide": None,
            "household": True,
            "device_ids": [d["id"] for d in unknown],
            "findings": [],
        }
    for a in acts.values():
        fids = {f["id"] for f in a["findings"]}
        rest = [f for f in live if f["id"] not in fids]
        n_unknown = 0 if a["playbook"] == "identify" else len(unknown)
        a["gain"] = round(base_pen - _penalty(rest, n_unknown), 1)
        a["worst"] = min((f["severity"] for f in a["findings"]), key=SEV.index, default="medium")
        a["quick_win"] = a["effort_min"] <= 10 and a["gain"] > 0
    # value per effort, with effort dampened (sqrt): a 2-hour fix for two criticals should
    # still outrank a 2-minute cosmetic one
    ranked = sorted(
        acts.values(),
        key=lambda a: (-(a["gain"] / math.sqrt(max(a["effort_min"], 4))), SEV.index(a["worst"])),
    )
    cur = round(max(0.0, 100.0 - base_pen))
    projected, removed = [], set()
    unknown_left = len(unknown)
    for a in ranked[:5]:
        removed |= {f["id"] for f in a["findings"]}
        if a["playbook"] == "identify":
            unknown_left = 0
        rest = [f for f in live if f["id"] not in removed]
        projected.append(round(max(0.0, 100.0 - _penalty(rest, unknown_left))))
    return {
        "score": cur,
        "grade": grade(cur),
        "actions": ranked,
        "projected": projected,  # score after doing the top 1, 2, ... actions
        "accepted": accepted,
        "unknown": [d["id"] for d in unknown],
        "counts": {s: sum(1 for f in live if f["severity"] == s) for s in SEV[:4]},
    }


def render_title(a: dict[str, Any], namer) -> str:
    """{device} -> a local name (UI) or a [D7] handle (LLM)."""
    if "{device}" not in a["title"]:
        return a["title"]
    ids = a["device_ids"]
    who = namer(ids[0]) if len(ids) == 1 else f"{len(ids)} devices"
    return a["title"].replace("{device}", who)
