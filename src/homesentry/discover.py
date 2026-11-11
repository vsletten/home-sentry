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


VIRTUAL_IFACE = ("lo", "docker", "br-", "veth", "tailscale", "virbr", "tun", "wg", "zt")
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_lan_ip(ip: str) -> bool:
    """Home-LAN address (RFC 1918). Stricter than ipaddress.is_private, which also says yes to
    documentation and other reserved ranges."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in RFC1918)


def lan_contexts() -> list[dict[str, str]]:
    """Every physical interface with a private IPv4: the default-route LAN first, then any
    extra legs (a USB-Ethernet into the eero, a Wi-Fi card, ...). Each is scanned."""
    out = [lan_context()]
    addrs = json.loads(_run(["ip", "-j", "-4", "addr", "show"]) or "[]")
    for a in addrs:
        iface = a.get("ifname", "")
        if iface == out[0]["iface"] or iface.startswith(VIRTUAL_IFACE):
            continue
        for info in a.get("addr_info", []):
            if not is_lan_ip(info["local"]):
                continue
            net = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}").network
            gw = (_run(["nmcli", "-g", "IP4.GATEWAY", "device", "show", iface]) or "").strip()
            mac_p = Path(f"/sys/class/net/{iface}/address")
            out.append(
                {
                    "iface": iface,
                    "local_ip": info["local"],
                    "cidr": str(net),
                    "gateway": gw,
                    "mac": mac_p.read_text().strip() if mac_p.exists() else "",
                }
            )
    return out


def tailscale_peers() -> dict[str, list[Sighting]]:
    """Tailscale peers with a direct LAN connection reveal the device's name and OS."""
    js = _run(["tailscale", "status", "--json"])
    return parse_tailscale(js or "{}")


def parse_tailscale(js: str) -> dict[str, list[Sighting]]:
    try:
        peers = (json.loads(js).get("Peer") or {}).values()
    except json.JSONDecodeError:
        return {}
    res: dict[str, list[Sighting]] = {}
    for p in peers:
        ip = (p.get("CurAddr") or "").rsplit(":", 1)[0]
        if not is_lan_ip(ip):
            continue
        res.setdefault(ip, []).extend(
            [("tailscale", "name", p.get("HostName", "")), ("tailscale", "os", p.get("OS", ""))]
        )
    return res


APPLE_OS = {"macos", "ios", "tvos"}
# NICs Macs commonly reach the LAN through: USB/Thunderbolt Ethernet dongles and docks.
ADAPTER_VENDORS = re.compile(
    r"ugreen|realtek|asix|belkin|anker|plugable|cable matters|startech|satechi|caldigit|"
    r"owc|other world|j5create|targus|kensington|d-link|tp-link|lenovo|dell|hp inc|"
    r"microsoft|ezcast|club 3d|sabrent|wavlink|amazon",
    re.I,
)
# mDNS services only Apple devices publish
APPLE_SELF = {"_companion-link._tcp", "_airplay._tcp", "_raop._tcp", "_apple-mobdev2._tcp"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower().replace("’", "").replace("'", ""))


def attribute_tailscale(
    sightings: list[Sighting],
    oui_vendor: str | None,
    random_mac: bool,
    self_reports: list[Sighting] | None = None,
) -> list[Sighting]:
    """A Tailscale peer's LAN endpoint only proves its packets LEAVE from that IP. If the
    device holding the IP can't be that peer (an Apple OS behind a non-Apple NIC vendor,
    and the device itself doesn't speak like a Mac), it's a NAT box in front of the peer:
    record that instead of naming it after the peer.

    Learned on a real LAN, both directions:
      - a MacBook behind a Linux access point doing NAT (non-Apple OUI, silent mDNS) -> NAT
      - a MacBook on a UGREEN USB-Ethernet dongle (non-Apple OUI, but it announces itself
        over mDNS with Apple-only services and its own name) -> it IS the peer
    """
    name = next((v for _, k, v in sightings if k == "name"), None)
    os_ = next((v for _, k, v in sightings if k == "os"), "").lower()
    if not name:
        return []
    vendor = oui_vendor or ""
    selfr = self_reports or []
    says_mine = any(
        k in ("host", "name") and _norm(name) and _norm(name) in _norm(v) for _, k, v in selfr
    )
    speaks_apple = any(k == "service" and v in APPLE_SELF for _, k, v in selfr)
    fits = (
        os_ not in APPLE_OS
        or random_mac
        or "apple" in vendor.lower()
        or says_mine
        or speaks_apple
        or bool(ADAPTER_VENDORS.search(vendor))
    )
    if fits:
        return sightings
    return [("tailscale", "nat_for", f"{name} ({os_})")]


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


def ssdp(seconds: float = 4.0, local_ip: str | None = None) -> dict[str, list[Sighting]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    if local_ip:  # send the M-SEARCH out of a specific LAN leg
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
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
def service_scan(ips: list[str], top_ports: int = 100) -> dict[str, list[Sighting]] | None:
    """Open ports + versions per host. None if the scan didn't run (vs {} = nothing open)."""
    nmap = shutil.which("nmap")
    if not nmap or not ips:
        return None
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
    if not xml or "<nmaprun" not in xml:
        return None  # nmap missing/failed: callers must NOT treat this as "all ports closed"
    return parse_nmap_xml(xml)


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
