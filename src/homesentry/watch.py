"""Continuous monitoring: what changed since the last scan, and a scheduler for the timer.

Every scan (manual or timed) takes a snapshot before and after, diffs them and writes
events: new devices, retired devices coming back, infrastructure going offline, ports
opening/closing, firmware changes, findings appearing/escalating/resolving.

Event titles never contain device names or addresses. The UI renders the device label
from device_id, which keeps events safe to summarize for the LLM.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import re
import time
from collections.abc import Iterator
from typing import Any

from . import data_dir
from .store import Store

SEV = ["critical", "high", "medium", "low", "info"]
# Devices that are supposed to stay put. Their comings and goings are news; a phone
# leaving the house is not.
INFRA = {
    "gateway",
    "router",
    "modem",
    "network",
    "nas",
    "camera",
    "smart-home",
    "printer",
    "set-top-box",
    "streaming",
    "tv",
    "alarm_hub",
    "appliance",
    "speaker",
}
RISKY_PORTS = {"21", "23", "111", "139", "445", "548", "554", "1883", "2049", "3389", "5900"}


class ScanBusy(RuntimeError):
    """Another scan holds the lock (timer vs. button)."""


@contextlib.contextmanager
def scan_lock() -> Iterator[None]:
    path = data_dir() / "scan.lock"
    with open(path, "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ScanBusy("another scan is already running") from None
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def finding_key(f: dict[str, Any]) -> str:
    """Stable identity of a finding across scans: the CVE *count* and outside-in port
    totals change as intel updates, the underlying issue doesn't."""
    t = re.sub(r":\s*\d+ CVE leads?$", "", f["title"])
    t = re.sub(r"\b\d+ of \d+\b", "N of N", t)
    return f"{f['kind']}:{t}"


# ---- snapshot / diff -------------------------------------------------------------
def snapshot(store: Store) -> dict[str, Any]:
    snap: dict[str, Any] = {"devices": {}, "ports": {}, "port_scanned": {}, "findings": {}}
    for d in store.devices(include_retired=True):
        did = d["id"]
        snap["devices"][did] = {
            k: d.get(k)
            for k in ("mac", "ip", "online", "firmware", "retired", "device_type", "confirmed")
        } | {"vendor": d.get("oui_vendor")}
        ev = store.evidence(did)
        snap["ports"][did] = sorted(
            {
                e["value"].split(" ")[0]
                for e in ev
                if e["source"] == "nmap" and e["key"] == "open_port"
            }
        )
        snap["port_scanned"][did] = any(e["source"] == "nmap" and e["key"] == "scanned" for e in ev)
    for f in store.findings():
        snap["findings"][f"{f['device_id']}|{finding_key(f)}"] = {
            "device_id": f["device_id"],
            "severity": f["severity"],
            "title": f["title"],
            "kind": f["kind"],
        }
    return snap


def _ev(kind, severity, title, device_id=None, detail=None, **data) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "title": title,
        "device_id": device_id,
        "detail": detail,
        "data": data,
    }


def diff(before: dict[str, Any], after: dict[str, Any], ports_scanned: bool) -> list[dict]:
    out: list[dict[str, Any]] = []
    bdev, adev = before["devices"], after["devices"]
    if not bdev:
        n = sum(1 for d in adev.values() if d["mac"] and not d["retired"])
        return [_ev("baseline", "info", f"Baseline inventory: {n} devices")] if n else []

    def watched(d: dict[str, Any]) -> bool:
        return bool(d.get("confirmed")) or (d.get("device_type") or "") in INFRA

    for did, a in adev.items():
        b = bdev.get(did)
        if b is None:
            if not a["mac"] or a["retired"]:
                continue
            if a["online"]:
                out.append(
                    _ev(
                        "new_device",
                        "medium",
                        "New device joined the network",
                        did,
                        f"Never seen before. NIC vendor: {a['vendor'] or 'unknown'}. "
                        "If you don't recognize it, identify it with the wizard.",
                    )
                )
            else:
                out.append(
                    _ev(
                        "device_remembered",
                        "info",
                        "Gateway remembers a device we haven't seen on the wire",
                        did,
                    )
                )
            continue
        if b["retired"] and not a["retired"]:
            out.append(
                _ev(
                    "reappeared",
                    "high",
                    "A retired device is talking on the network again",
                    did,
                    "You marked this device decommissioned. Either it was repurposed or "
                    "something is reusing its hardware address.",
                )
            )
        if a["retired"]:
            continue
        if watched(a) and b["online"] is not None and a["online"] is not None:
            if b["online"] and not a["online"]:
                out.append(_ev("device_offline", "info", "Went offline", did))
            elif not b["online"] and a["online"]:
                out.append(_ev("device_online", "info", "Back online", did))
        if watched(a) and b["ip"] and a["ip"] and b["ip"] != a["ip"]:
            out.append(_ev("ip_changed", "info", "Address changed", did, old=b["ip"], new=a["ip"]))
        if b["firmware"] and a["firmware"] and b["firmware"] != a["firmware"]:
            out.append(
                _ev(
                    "firmware_changed",
                    "info",
                    "Firmware changed",
                    did,
                    f"{b['firmware']} → {a['firmware']}",
                    old=b["firmware"],
                    new=a["firmware"],
                )
            )
        if ports_scanned and a["online"] and before["port_scanned"].get(did):
            bp, ap = set(before["ports"].get(did, [])), set(after["ports"].get(did, []))
            for p in sorted(ap - bp):
                risky = p.split("/")[0] in RISKY_PORTS
                out.append(
                    _ev("port_opened", "medium" if risky else "low", f"Port {p} opened", did)
                )
            for p in sorted(bp - ap):
                out.append(_ev("port_closed", "info", f"Port {p} closed", did))

    bf, af = before["findings"], after["findings"]
    for k, f in af.items():
        dev = adev.get(f["device_id"]) or {}
        if dev.get("retired") or f["severity"] == "info":
            continue
        old = bf.get(k)
        if old is None:
            out.append(
                _ev("finding_new", f["severity"], f"New finding: {f['title']}", f["device_id"])
            )
        elif SEV.index(f["severity"]) < SEV.index(old["severity"]):
            out.append(
                _ev(
                    "finding_escalated",
                    f["severity"],
                    f"Escalated to {f['severity']}: {f['title']}",
                    f["device_id"],
                    f"Was {old['severity']}. Usually new intel, e.g. CISA adding a CVE "
                    "to its actively-exploited list.",
                )
            )
    for k, f in bf.items():
        dev = adev.get(f["device_id"]) or {}
        if k not in af and f["severity"] != "info" and not dev.get("retired"):
            out.append(_ev("finding_resolved", "info", f"Resolved: {f['title']}", f["device_id"]))
    return out


# ---- scheduler (what the systemd timer runs) --------------------------------------
def _due(store: Store, key: str, hours: float, now: float) -> bool:
    if hours <= 0:
        return False
    s = store.last_scan_with(key)
    return s is None or now - (s["started"] or 0) >= hours * 3600


def _outside_due(store: Store, hours: float, now: float) -> bool:
    if hours <= 0:
        return False
    for d in store.devices():
        for e in store.evidence(d["id"]):
            if e["source"] == "outside" and e["key"] == "result":
                return now - e["ts"] >= hours * 3600
    return True


def run_watch(
    store: Store,
    ports_every_h: float = 12,
    gateway_every_h: float = 6,
    outside_every_h: float = 24,
    notify: bool = True,
    log=print,
) -> dict[str, Any]:
    """One monitoring tick: quick scan always; port scan, gateway read and outside-in
    check only when they're due (they're slower, or touch other boxes)."""
    from . import outside
    from .scan import run_scan

    now = time.time()
    did_outside = False
    if outside.load_conf() and _outside_due(store, outside_every_h, now):
        try:
            outside.run_and_record(store, log=log, rethreat=False)
            did_outside = True
        except Exception as e:  # noqa: BLE001 - the probe host being down isn't fatal
            log(f"outside-in failed: {e}")
    summary = run_scan(
        store,
        ports=_due(store, "ports", ports_every_h, now),
        gateway=_due(store, "gateway", gateway_every_h, now),
        log=log,
        extra={"outside": did_outside, "trigger": "timer"},
    )
    if notify:
        from . import notify as notifier

        sent = notifier.send(store, summary.get("event_list", []), log=log)
        summary["notified"] = sent
    return summary


def describe(events: list[dict[str, Any]]) -> str:
    return json.dumps([{k: e[k] for k in ("kind", "severity", "title")} for e in events])
