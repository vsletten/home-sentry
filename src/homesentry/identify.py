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
    # Apple devices publish their exact hardware model id in AirPlay/RAOP TXT (am= / model=)
    for k in ("txt:_raop._tcp", "txt:_airplay._tcp"):
        for txt in by.get(("mdns", k), []):
            if (m := re.search(r'"(?:am|model)=([A-Za-z]+)(\d+,\d+)"', txt)) and (
                hit := APPLE_MODELS.get(m.group(1))
            ):
                dtype, family = hit
                ident = m.group(1) + m.group(2)
                offer("make", "Apple", 0.8, "AirPlay model id")
                offer("device_type", dtype, 0.8, f"AirPlay model id {ident}")
                offer("model", APPLE_NAMES.get(ident, f"{family} ({ident})"), 0.75, "AirPlay model")
    # Macs advertise AirPlay receivers too (macOS 12+), so _raop alone would call them speakers.
    # The name a Mac publishes ("Victor's MacBook Pro", "Mac-mini.local") settles it.
    if m := re.search(
        r"\b(MacBook(?: Pro| Air)?|Mac[ -]mini|iMac|Mac[ -]Pro|Mac[ -]Studio)\b", names
    ):
        offer("make", "Apple", 0.6, "Mac name")
        offer("device_type", "computer", 0.6, f"mDNS name {m.group(1)}")
    elif re.search(r"\b(iPhone|iPad)\b", names):
        offer("make", "Apple", 0.6, "iPhone/iPad name")
        offer("device_type", "phone", 0.55, "iPhone/iPad name")

    # 4. Open ports / service banners
    ports = by.get(("ports", "open_port"), [])
    portnums = {p.split("/")[0] for p in ports}
    if portnums & {"631", "9100", "515"}:
        offer("device_type", "printer", 0.55, "printer ports")
    if any(re.search(r"\bRaspbian\b", p) for p in ports):
        offer("make", "Raspberry Pi", 0.5, "Raspbian service banner")
        offer("device_type", "computer", 0.5, "Raspbian service banner")
    if "62078" in portnums:  # lockdownd: iPhone/iPad sync, but Apple TVs/HomePods run it too
        offer("make", "Apple", 0.55, "iOS sync port")
        offer("device_type", "phone", 0.4, "iOS sync port")
    if any(re.search(r"\bAirTunes\b|Apple remote desktop", p) for p in ports):
        offer("make", "Apple", 0.55, "Apple service banner")
        if portnums & {"22", "5900", "445"}:
            offer("device_type", "computer", 0.55, "Apple + ssh/vnc/smb")
    for p in ports:
        if m := re.search(r"\b(\w+) printer web interface", p):
            offer("make", m.group(1), 0.5, "printer web banner")
            offer("device_type", "printer", 0.6, "printer web banner")

    # 5. Web admin page title
    for title in by.get(("ports", "http_title"), []):
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

    nat_for = by.get(("tailscale", "nat_for"), [])
    if nat_for:
        offer("device_type", "router", 0.6, f"NATs Tailscale node {nat_for[0]}")

    # 7. The gateway's own admin pages: authoritative for the gateway itself
    offer("make", first("gateway", "vendor"), 0.95, "gateway admin page")
    offer("model", first("gateway", "model"), 0.95, "gateway admin page")
    if first("gateway", "model"):
        offer("device_type", "gateway", 0.95, "gateway admin page")

    # 8. DHCP hostname from the gateway's client table
    for hn in by.get(("gateway", "dhcp_name"), []):
        for rx, make, model, dtype in HOSTNAME_HINTS:
            if m := re.match(rx, hn, re.I):
                offer("make", make, 0.6, "DHCP hostname")
                offer("model", model or (m.group(1) if m.groups() else None), 0.55, "DHCP hostname")
                offer("device_type", dtype, 0.6, "DHCP hostname")

    # 9. Network role and OUI: weak but always available
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


# Apple hardware model id prefix -> (device type, family). Generic, public naming.
APPLE_MODELS = {
    "Mac": ("computer", "Mac"),
    "MacBookPro": ("computer", "MacBook Pro"),
    "MacBookAir": ("computer", "MacBook Air"),
    "MacBook": ("computer", "MacBook"),
    "iMac": ("computer", "iMac"),
    "Macmini": ("computer", "Mac mini"),
    "MacPro": ("computer", "Mac Pro"),
    "AppleTV": ("streaming", "Apple TV"),
    "AudioAccessory": ("speaker", "HomePod"),
    "iPhone": ("phone", "iPhone"),
    "iPad": ("tablet", "iPad"),
}
APPLE_NAMES = {
    "AppleTV5,3": "Apple TV HD",
    "AppleTV6,2": "Apple TV 4K",
    "AppleTV11,1": "Apple TV 4K (2nd gen)",
    "AppleTV14,1": "Apple TV 4K (3rd gen)",
    "AudioAccessory1,1": "HomePod",
    "AudioAccessory5,1": "HomePod mini",
    "AudioAccessory6,1": "HomePod (2nd gen)",
}

# hostname regex -> make, model (None = first capture group), type
HOSTNAME_HINTS = [
    (r"DIRECTV-([A-Z0-9]+)-", "DIRECTV", None, "set-top-box"),
    (r"Xbox ?(One|Series ?[XS])?", "Microsoft", None, "game-console"),
    (r"HP-([A-Z0-9-]+?)-(?:Workstation|PC|Desktop|Laptop)", "HP", None, "computer"),
    (r"(iPhone|iPad)", "Apple", None, "phone"),
    (r"Roku", "Roku", None, "streaming"),
    (r"Canon", "Canon", None, "printer"),
]

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
