"""mDNS / DNS-SD discovery in pure Python (python-zeroconf): same evidence on every OS.

Replaces `avahi-browse` (Linux-only). Works next to a system responder (avahi-daemon,
macOS mDNSResponder, Windows' DNS client) because zeroconf shares UDP 5353 with SO_REUSEPORT.

Evidence per IPv4 address, identical in shape to what the avahi parser produced, so the
identify/KB code never knows which collector ran:
    ("mdns", "service", "_airplay._tcp")
    ("mdns", "name", "Living Room")              instance name
    ("mdns", "host", "Living-Room.local")        target host, no trailing dot
    ("mdns", "txt:_airplay._tcp", '"model=AppleTV6,2" "srcvers=..."')
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

Sighting = tuple[str, str, str]

META = "_services._dns-sd._udp.local."
# TXT records that rotate on purpose (Apple's companion-link changes its rp* identifiers every
# few minutes): storing them adds a fresh evidence row per scan and identifies nothing.
ROTATING_TXT = {"_companion-link._tcp"}


def browse(local_ip: str | None = None, seconds: float = 8.0) -> dict[str, list[Sighting]] | None:
    """Listen for `seconds`. None if mDNS could not run at all (vs {} = nobody advertised)."""
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf
    except ImportError:
        return None
    try:
        zc = Zeroconf(
            interfaces=[local_ip] if local_ip else None,  # type: ignore[list-item]
            ip_version=IPVersion.V4Only,
        )
    except OSError:
        return None
    found: set[tuple[str, str]] = set()  # (type, instance fqdn)
    types: set[str] = set()
    lock = threading.Lock()
    browsers = []

    def on_instance(zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            with lock:
                found.add((service_type, name))

    def on_type(zeroconf, service_type, name, state_change):
        if state_change is not ServiceStateChange.Added:
            return
        with lock:
            if name in types:
                return
            types.add(name)
        browsers.append(ServiceBrowser(zeroconf, name, handlers=[on_instance]))

    try:
        browsers.append(ServiceBrowser(zc, META, handlers=[on_type]))
        time.sleep(seconds)
        with lock:
            todo = sorted(found)
        with ThreadPoolExecutor(16) as ex:
            infos = list(ex.map(lambda t: (t[0], _resolve(zc, *t)), todo))
    finally:
        for b in browsers:
            b.cancel()
        zc.close()
    res: dict[str, set[Sighting]] = {}
    for stype, info in infos:
        if info is None:
            continue
        for ip, sights in info_sightings(stype, info).items():
            res.setdefault(ip, set()).update(sights)
    return {ip: sorted(v) for ip, v in res.items()}


def _resolve(zc, stype: str, name: str):
    try:
        from zeroconf import ServiceInfo

        info = ServiceInfo(stype, name)
        return info if info.request(zc, 3000) else None
    except Exception:  # noqa: BLE001 - one bad responder must not sink the browse
        return None


def info_sightings(stype: str, info) -> dict[str, set[Sighting]]:
    """One resolved service -> {ipv4: sightings}. Pure enough to test with a stand-in object."""
    short = stype.removesuffix(".local.").removesuffix(".")
    instance = info.name.removesuffix(stype).removesuffix(".")
    host = (info.server or "").removesuffix(".")
    txt = format_txt(info.properties or {})
    out: dict[str, set[Sighting]] = {}
    for ip in info.parsed_addresses():
        if ":" in ip:
            continue
        s = out.setdefault(ip, set())
        s.add(("mdns", "service", short))
        s.add(("mdns", "name", _unescape(instance)))
        if host:
            s.add(("mdns", "host", host))
        if txt and short not in ROTATING_TXT:
            s.add(("mdns", f"txt:{short}", txt[:400]))
    return out


def format_txt(props: dict) -> str:
    """TXT record as avahi prints it: `"k=v" "flag"` (identify/KB regexes expect that)."""
    parts = []
    for k, v in props.items():
        key = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
        if not key:
            continue
        if v is None:
            parts.append(f'"{key}"')
        else:
            val = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
            parts.append(f'"{key}={val}"')
    return " ".join(parts)


def _unescape(s: str) -> str:
    # DNS-SD instance names may carry backslash escapes (e.g. "\032" for space, "\." for dot)
    import re

    s = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s)
    return re.sub(r"\\(.)", r"\1", s)
