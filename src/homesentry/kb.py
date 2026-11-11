"""Ad-hoc device knowledge base: one YAML file per device model.

KB entries hold only GENERIC device knowledge (make/model/type, how to recognize it,
notes). Never household data: no MACs, serials, IPs, names. That keeps the KB shareable
and lets it grow into the subscription-side KB later.

Read from: the packaged seed dir (kbdata/devices) + the local learned dir (data_dir()/kb).
Write to: the local learned dir only.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import yaml

from . import data_dir

# Shipped with the package (so `uv tool install` / wheels carry it): the KB "pack".
SEED_DIR = Path(__file__).parent / "kbdata" / "devices"

# evidence (source, key) -> KB match rule name.
# Only MODEL-specific self-reports qualify. Deliberately excluded (learned the hard way):
#  - UPnP modelDescription: family-level ("DIRECTV Plus HD DVR" is on every DIRECTV box)
#  - HTTP titles: describe software, not hardware ("Netdata"), and nmap's noise lines
#    ("Did not follow redirect to http://<your IP>") would leak household data into the KB.
MATCHABLE = {
    ("ssdp", "modelName"): "ssdp_model",
}
RULES = {"ssdp_model", "mdns_model"}  # the only rule names honored when matching
GENERIC_SSDP_MODELS = {
    "mediarenderer",
    "mediaserver",
    "remoteuiserverdevice",
    "basic",
    "1.0",
    "windows media player sharing",
    "upnp/av",
    "dmr",
    "dms",
}


def learned_dir() -> Path:
    d = data_dir() / "kb"
    d.mkdir(parents=True, exist_ok=True)
    return d


def slug(*parts: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", " ".join(p for p in parts if p).lower()).strip("-")


def load(dirs: list[Path] | None = None) -> list[dict[str, Any]]:
    entries = []
    for d in dirs or [SEED_DIR, learned_dir()]:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml")):
            e = yaml.safe_load(f.read_text()) or {}
            e["_file"] = str(f)
            entries.append(e)
    return entries


def match(entries: list[dict[str, Any]], facts: dict[str, set[str]]) -> dict[str, Any] | None:
    """facts: rule name -> observed values. Exact, case-insensitive match on any rule."""
    for e in entries:
        for rule, wanted in (e.get("match") or {}).items():
            if rule not in RULES:  # stale rule types from older KB files are inert
                continue
            seen = {v.lower() for v in facts.get(rule, set())}
            if any(str(w).lower() in seen for w in wanted or []):
                return e
    return None


def facts_from_evidence(evidence: list[dict[str, Any]]) -> dict[str, set[str]]:
    facts: dict[str, set[str]] = {}
    for ev in evidence:
        if ev["source"] == "mdns" and ev["key"] == "txt:_device-info._tcp":
            m = re.search(r'"model=([^"]+)"', ev["value"])
            if m and m.group(1) not in {"MacSamba", "RackMac", "Xserve"}:
                facts.setdefault("mdns_model", set()).add(m.group(1))
            continue
        rule = MATCHABLE.get((ev["source"], ev["key"]))
        if not rule:
            continue
        v = ev["value"].strip()
        if rule == "ssdp_model" and v.lower() in GENERIC_SSDP_MODELS:
            continue
        facts.setdefault(rule, set()).add(v)
    return facts


def learn(identity: dict[str, Any], evidence: list[dict[str, Any]], out_dir: Path | None = None):
    """Create/extend a KB entry from a user-confirmed identification."""
    make, model = (identity.get("make") or "").strip(), (identity.get("model") or "").strip()
    if not make or not model:
        return None
    path = (out_dir or learned_dir()) / f"{slug(make, model)}.yaml"
    entry: dict[str, Any] = yaml.safe_load(path.read_text()) if path.exists() else {}
    entry.setdefault("make", make)
    entry.setdefault("model", model)
    if identity.get("device_type"):
        entry["device_type"] = identity["device_type"]
    rules = {k: v for k, v in (entry.get("match") or {}).items() if k in RULES}
    entry["match"] = rules
    for rule, values in facts_from_evidence(evidence).items():
        merged = set(rules.get(rule, [])) | values
        rules[rule] = sorted(merged)
    fw = (identity.get("firmware") or "").strip()
    if fw:
        entry["firmware_seen"] = sorted(set(entry.get("firmware_seen", [])) | {fw})
    entry.setdefault("notes", "")
    entry.setdefault("learned", time.strftime("%Y-%m-%d"))
    path.write_text(yaml.safe_dump(entry, sort_keys=False, allow_unicode=True))
    return path
