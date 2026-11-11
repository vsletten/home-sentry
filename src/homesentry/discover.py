"""Unprivileged LAN discovery: ARP sweep, mDNS, SSDP/UPnP, optional nmap service scan.

Each collector returns {ip: [(source, key, value), ...]}. No root required.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

Sighting = tuple[str, str, str]

OUI_PATHS = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/snap/nmap/current/usr/share/nmap/nmap-mac-prefixes"),
]


# ---- network context ---------------------------------------------------------
def lan_context() -> dict[str, str]:
    """Interface, local IP/MAC, CIDR and gateway of the default route."""
    routes = json.loads(_run(["ip", "-j", "route", "show", "default"]) or "[]")
    if not routes:
        raise RuntimeError("no default route")
    iface, gateway = routes[0]["dev"], routes[0].get("gateway", "")
    addrs = json.loads(_run(["ip", "-j", "-4", "addr", "show", "dev", iface]) or "[]")
    info = addrs[0]["addr_info"][0]
    net = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}").network
    mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
    return {
        "iface": iface,
        "local_ip": info["local"],
        "cidr": str(net),
        "gateway": gateway,
        "mac": mac,
    }


# ---- OUI ---------------------------------------------------------------------
_oui: dict[str, str] | None = None


def oui_vendor(mac: str) -> str | None:
    global _oui
    if _oui is None:
        _oui = {}
        for p in OUI_PATHS:
            if p.exists():
                _oui = parse_oui(p.read_text(errors="ignore"))
                break
    return _oui.get(mac.replace(":", "").upper()[:6])


def parse_oui(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or len(line) < 8:
            continue
        prefix, _, vendor = line.partition(" ")
        if len(prefix) == 6:
            out[prefix.upper()] = vendor.strip()
    return out


def is_random_mac(mac: str) -> bool:
    """Locally administered bit set => randomized/private MAC (phones, some laptops)."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


# ---- ARP ---------------------------------------------------------------------
def arp_sweep(cidr: str, iface: str) -> dict[str, str]:
    """Poke every address so the kernel ARP-resolves it, then read the neighbor table.
    Returns {ip: mac}. ARP resolution itself proves presence, even for hosts that drop pings."""
    nmap = shutil.which("nmap")
    if nmap:
        _run([nmap, "-sn", "-n", "-T4", cidr], timeout=120)
    else:  # crude fallback: UDP connect to every host triggers ARP
        net = ipaddress.ip_network(cidr)
        for host in net.hosts():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(b"", (str(host), 9))
            except OSError:
                pass
        time.sleep(3)
    return parse_neigh(_run(["ip", "-j", "neigh", "show", "dev", iface]) or "[]")


def parse_neigh(js: str) -> dict[str, str]:
    out = {}
    for n in json.loads(js):
        state = n.get("state") or []
        if n.get("lladdr") and "FAILED" not in state and ":" not in n["dst"]:
            out[n["dst"]] = n["lladdr"].lower()
    return out


def reverse_dns(ips: list[str]) -> dict[str, str]:
    def one(ip: str) -> tuple[str, str | None]:
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, None

    with ThreadPoolExecutor(16) as ex:
        return {ip: h for ip, h in ex.map(one, ips) if h}


# ---- mDNS --------------------------------------------------------------------
def mdns(iface: str, seconds: int = 8) -> dict[str, list[Sighting]]:
    if not shutil.which("avahi-browse"):
        return {}
    out = _run(
        ["timeout", str(seconds), "avahi-browse", "-atrp", "--no-db-lookup"], timeout=seconds + 5
    )
    return parse_avahi(out or "", iface)


def _avahi_unescape(s: str) -> str:
    raw = re.sub(rb"\\(\d{3})", lambda m: bytes([int(m.group(1))]), s.encode())
    return raw.decode("utf-8", errors="replace")


def parse_avahi(text: str, iface: str) -> dict[str, list[Sighting]]:
    res: dict[str, set[Sighting]] = {}
    for line in text.splitlines():
        f = line.split(";")
        if len(f) < 10 or f[0] != "=" or f[2] != "IPv4" or f[1] != iface:
            continue
        name, stype, host, ip = _avahi_unescape(f[3]), f[4], f[6], f[7]
        s = res.setdefault(ip, set())
        s.add(("mdns", "service", stype))
        s.add(("mdns", "name", name))
        s.add(("mdns", "host", host))
        txt = ";".join(f[9:]).strip()
        if txt:
            s.add(("mdns", f"txt:{stype}", _avahi_unescape(txt)[:400]))
    return {ip: sorted(v) for ip, v in res.items()}


# ---- SSDP / UPnP -------------------------------------------------------------
SSDP_MSG = (
    b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
    b"MX: 2\r\nST: ssdp:all\r\n\r\n"
)
UPNP_FIELDS = (
    "deviceType",
    "friendlyName",
    "manufacturer",
    "modelName",
    "modelNumber",
    "modelDescription",
)  # serialNumber/UDN deliberately not collected


def ssdp(seconds: float = 4.0) -> dict[str, list[Sighting]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.sendto(SSDP_MSG, ("239.255.255.250", 1900))
    locations: dict[str, set[str]] = {}
    servers: dict[str, set[str]] = {}
    end = time.time() + seconds
    while time.time() < end:
        try:
            data, (ip, _) = s.recvfrom(8192)
        except TimeoutError:
            continue
        hdrs = {}
        for line in data.decode(errors="ignore").split("\r\n"):
            k, sep, v = line.partition(":")
            if sep:
                hdrs[k.strip().upper()] = v.strip()
        if hdrs.get("SERVER"):
            servers.setdefault(ip, set()).add(hdrs["SERVER"])
        if hdrs.get("LOCATION"):
            locations.setdefault(ip, set()).add(hdrs["LOCATION"])
    s.close()
    res: dict[str, set[Sighting]] = {}
    for ip, srv in servers.items():
        res.setdefault(ip, set()).update(("ssdp", "server", v) for v in srv)
    with httpx.Client(timeout=4) as client:
        for ip, locs in locations.items():
            for loc in sorted(locs)[:6]:
                try:
                    xml = client.get(loc).text
                except httpx.HTTPError:
                    continue
                res.setdefault(ip, set()).update(parse_upnp_description(xml))
    return {ip: sorted(v) for ip, v in res.items()}


def parse_upnp_description(xml: str) -> set[Sighting]:
    out: set[Sighting] = set()
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for dev in root.iter():
        if not dev.tag.endswith("device"):
            continue
        for child in dev:
            tag = child.tag.split("}")[-1]
            if tag in UPNP_FIELDS and child.text and child.text.strip():
                out.add(("ssdp", tag, child.text.strip()))
    return out


# ---- nmap service scan (optional, slower) ------------------------------------
def service_scan(ips: list[str], top_ports: int = 100) -> dict[str, list[Sighting]]:
    nmap = shutil.which("nmap")
    if not nmap or not ips:
        return {}
    xml = _run(
        [
            nmap,
            "-sT",
            "-sV",
            "--version-light",
            "-T4",
            "-n",
            "--top-ports",
            str(top_ports),
            "--script",
            "http-title",
            "-oX",
            "-",
            *ips,
        ],
        timeout=900,
    )
    return parse_nmap_xml(xml or "")


def parse_nmap_xml(xml: str) -> dict[str, list[Sighting]]:
    res: dict[str, list[Sighting]] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return res
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr") or ""
        sights: list[Sighting] = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            desc = f"{port.get('portid')}/{port.get('protocol')}"
            if svc is not None:
                parts = [
                    svc.get("name"),
                    svc.get("product"),
                    svc.get("version"),
                    svc.get("extrainfo"),
                ]
                desc += " " + " ".join(p for p in parts if p)
            sights.append(("nmap", "open_port", desc.strip()))
            for sc in port.findall("script[@id='http-title']"):
                title = (sc.get("output") or "").strip()
                if title and not title.startswith(("Site doesn't have", "Did not follow")):
                    sights.append(("nmap", "http_title", title[:200]))
        if sights:
            res[ip] = sights
    return res


# ---- helpers -----------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 30) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
