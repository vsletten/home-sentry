"""Deterministic first-pass identification from collected evidence.

Cheap, local, no LLM. Produces a best guess with a confidence and the reasons.
The wizard takes over where this runs out.
"""

from __future__ import annotations

import re
from typing import Any

from . import kb as kblib

MDNS_TYPE_HINTS = {
    "_googlecast._tcp": "streaming",
    "_amzn-wplay._tcp": "streaming",
    "_roku-rcp._tcp": "streaming",
    "_airplay._tcp": "apple",
    "_raop._tcp": "speaker",
    "_sonos._tcp": "speaker",
    "_spotify-connect._tcp": "speaker",
    "_ipp._tcp": "printer",
    "_ipps._tcp": "printer",
    "_printer._tcp": "printer",
    "_pdl-datastream._tcp": "printer",
    "_hap._tcp": "smart-home",
    "_hap._udp": "smart-home",
    "_matter._tcp": "smart-home",
    "_matterc._udp": "smart-home",
    "_hue._tcp": "smart-home",
    "_adisk._tcp": "nas",
}
# Samba's mDNS device-info advertises fake Apple models so Finder shows a nice icon
SAMBA_FAKE_MODELS = {"MacSamba", "RackMac", "Xserve", "TimeCapsule", "PowerMac", "MacPro"}
SSDP_TYPE_HINTS = {
    "InternetGatewayDevice": "router",
    "WFADevice": "router",
    "MediaRenderer": "media",
    "MediaServer": "media",
    "ZonePlayer": "speaker",
    "dial": "streaming",
}


def guess(
    evidence: list[dict[str, Any]],
    oui_vendor: str | None,
    is_gateway: bool = False,
    is_self: bool = False,
    kb_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    by: dict[tuple[str, str], list[str]] = {}
    for ev in evidence:
        by.setdefault((ev["source"], ev["key"]), []).append(ev["value"])

    def first(src: str, key: str) -> str | None:
        vals = by.get((src, key))
        return vals[0] if vals else None

    reasons: list[str] = []
    g: dict[str, Any] = {"device_type": None, "make": None, "model": None, "confidence": 0.0}

    def offer(field: str, value: str | None, conf: float, why: str) -> None:
        if not value:
            return
        if g[field] is None or conf > g.get(f"_{field}_c", 0):
            g[field] = value
            g[f"_{field}_c"] = conf
            reasons.append(f"{field}={value} ({why})")

    # 1. KB rules learned from earlier confirmations: strongest signal we have
    facts = kblib.facts_from_evidence(evidence)
    hit = kblib.match(kb_entries or [], facts)
    if hit:
        offer("make", hit.get("make"), 0.9, "KB match")
        offer("model", hit.get("model"), 0.9, "KB match")
        offer("device_type", hit.get("device_type"), 0.9, "KB match")

    # 2. UPnP device description: vendors usually self-report here
    manu = first("ssdp", "manufacturer")
    models = [
        m for m in by.get(("ssdp", "modelName"), []) if m.lower() not in kblib.GENERIC_SSDP_MODELS
    ]
    offer("make", manu, 0.7, "UPnP manufacturer")
    if models:
        offer("model", models[0], 0.7, "UPnP modelName")
    for dt in by.get(("ssdp", "deviceType"), []):
        for k, t in SSDP_TYPE_HINTS.items():
            if k in dt:
                offer("device_type", t, 0.5, f"UPnP {k}")
    desc = first("ssdp", "modelDescription") or ""
    if re.search(r"\b(DVR|Receiver|set.?top)\b", desc, re.I):
        offer("device_type", "set-top-box", 0.65, "UPnP description")

    # 3. mDNS: Apple device-info model, service types
    for txt in by.get(("mdns", "txt:_device-info._tcp"), []):
        m = re.search(r'"model=([^"]+)"', txt)
        if m and m.group(1) in SAMBA_FAKE_MODELS:
            offer("device_type", "nas", 0.35, "Samba file server")  # Samba poses as a Mac
        elif m:
            offer("model", m.group(1), 0.55, "mDNS device-info")
            if m.group(1).startswith(("Mac", "iMac")):
                offer("make", "Apple", 0.6, "mDNS device-info")
                offer("device_type", "computer", 0.6, "Mac model id")
    services = set(by.get(("mdns", "service"), []))
    for svc in services:
        offer("device_type", MDNS_TYPE_HINTS.get(svc), 0.45, f"mDNS {svc}")
    if "_companion-link._tcp" in services:
        offer("make", "Apple", 0.55, "Apple companion-link")
        if services & {"_ssh._tcp", "_sftp-ssh._tcp", "_rfb._tcp"}:
            offer("device_type", "computer", 0.55, "Apple + ssh/vnc")
    names = " ".join(by.get(("mdns", "name"), []) + by.get(("mdns", "host"), []))
    if re.search(r"\bT?NAS\b|synology|qnap|diskstation", names, re.I):
        offer("device_type", "nas", 0.6, "NAS-style name")
        if re.match(r"TNAS", names):
            offer("make", "TerraMaster", 0.6, "TNAS-* hostname")

    # 4. Open ports / service banners
    ports = by.get(("nmap", "open_port"), [])
    portnums = {p.split("/")[0] for p in ports}
    if portnums & {"631", "9100", "515"}:
        offer("device_type", "printer", 0.55, "printer ports")
    for p in ports:
        if m := re.search(r"\b(\w+) printer web interface", p):
            offer("make", m.group(1), 0.5, "printer web banner")
            offer("device_type", "printer", 0.6, "printer web banner")

    # 5. Web admin page title
    for title in by.get(("nmap", "http_title"), []):
        offer("make", _vendor_in(title), 0.4, "HTTP title")

    # 6. Tailscale peer: the node's own name and OS
    ts_os = (first("tailscale", "os") or "").lower()
    if ts_os == "macos":
        offer("make", "Apple", 0.65, "Tailscale macOS node")
        offer("device_type", "computer", 0.65, "Tailscale macOS node")
    elif ts_os == "ios":
        offer("make", "Apple", 0.65, "Tailscale iOS node")
        offer("device_type", "phone", 0.5, "Tailscale iOS node")
    elif ts_os == "android":
        offer("device_type", "phone", 0.5, "Tailscale Android node")
    elif ts_os in ("windows", "linux"):
        offer("device_type", "computer", 0.5, f"Tailscale {ts_os} node")

    # 7. Network role and OUI: weak but always available
    if is_gateway:
        offer("device_type", "router", 0.6, "default gateway")
    if is_self:
        offer("device_type", "computer", 0.95, "this host")
    offer("make", _clean_vendor(oui_vendor), 0.3, "MAC vendor (OUI)")

    found = [g.pop(f"_{f}_c", 0.0) for f in ("device_type", "make", "model")]
    # identity confidence = how much of type/make/model we pinned, weighted by strength
    g["confidence"] = round(sum(found) / 3, 2)
    g["reasons"] = reasons
    return g


KNOWN_VENDORS = [
    "Netgear",
    "TP-Link",
    "ASUS",
    "Linksys",
    "Arris",
    "Technicolor",
    "Motorola",
    "Ubiquiti",
    "Synology",
    "QNAP",
    "TerraMaster",
    "Hikvision",
    "Dahua",
    "Roku",
    "Samsung",
    "LG",
    "Sonos",
    "Eero",
    "Google",
    "Amazon",
    "Ring",
    "Wyze",
    "Hubitat",
    "Philips",
    "Epson",
    "Brother",
    "HP",
    "Canon",
    "Xfinity",
    "DIRECTV",
    "Netatmo",
]


def _vendor_in(text: str) -> str | None:
    for v in KNOWN_VENDORS:
        if re.search(rf"\b{re.escape(v)}\b", text, re.I):
            return v
    return None


def _clean_vendor(v: str | None) -> str | None:
    if not v:
        return None
    v = re.sub(
        r"[,.]?\s+(inc|ltd|llc|co|corp|corporation|limited|gmbh|s\.?a)\.?\b.*$", "", v, flags=re.I
    )
    return v.strip() or None
