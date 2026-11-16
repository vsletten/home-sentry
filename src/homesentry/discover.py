"""Unprivileged LAN discovery: ARP sweep, mDNS, SSDP/UPnP, optional port/service scan.

Each collector returns {ip: [(source, key, value), ...]}. No root, no nmap, no avahi: the
OS-specific reads are in netinfo, ports in portscan, mDNS in mdns. Linux and macOS today.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from . import netinfo

Sighting = tuple[str, str, str]

OUI_PATHS = [
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/snap/nmap/current/usr/share/nmap/nmap-mac-prefixes"),
]


# ---- network context (OS-specific reads live in netinfo) -----------------------
from .netinfo import RFC1918, VIRTUAL_IFACE, is_lan_ip, norm_mac  # noqa: E402,F401  re-exported


def lan_context() -> dict[str, str]:
    """Interface, local IP/MAC, CIDR and gateway of the default route."""
    return netinfo.lan_context()


def lan_contexts() -> list[dict[str, str]]:
    """Every physical interface with a private IPv4: the default-route LAN first, then any
    extra legs (a USB-Ethernet into a second router, a Wi-Fi card, ...). Each is scanned."""
    return netinfo.lan_contexts()


def tailscale_peers() -> dict[str, list[Sighting]]:
    """Tailscale peers with a direct LAN connection reveal the device's name and OS."""
    cmd = netinfo.tailscale_cmd()
    js = _run([*cmd, "status", "--json"]) if cmd else None
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
# The bundled IEEE MA-L table (scripts/build_oui.py) is THE vendor source on every OS, so a Mac
# and a Linux box name the same NIC the same way. nmap's table only fills prefixes the bundle
# lacks (none, in practice, when the bundle is fresh).
BUNDLED_OUI = Path(__file__).parent / "kbdata" / "oui.tsv.gz"
_oui: dict[str, str] | None = None


def load_oui() -> dict[str, str]:
    import gzip

    table: dict[str, str] = {}
    for p in OUI_PATHS:
        if p.exists():
            table.update(parse_oui(p.read_text(errors="ignore")))
            break
    if BUNDLED_OUI.exists():
        for line in gzip.decompress(BUNDLED_OUI.read_bytes()).decode().splitlines():
            prefix, _, vendor = line.partition("\t")
            if vendor:
                table[prefix] = vendor
    return table


def oui_vendor(mac: str) -> str | None:
    global _oui
    if _oui is None:
        _oui = load_oui()
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
SWEEP_MAX_HOSTS = 4096  # a /20; bigger "home" networks are misconfigured or not a home


def arp_sweep(cidr: str, iface: str, rounds: int = 2) -> dict[str, str]:
    """Poke every address so the OS ARP-resolves it, then read the neighbor table.
    Returns {ip: mac}. ARP resolution itself proves presence, even for hosts that drop pings.

    The poke is one empty UDP datagram to the discard port: unprivileged, the same on every OS,
    and the kernel must ARP before it can send it. Two rounds catch hosts that miss the first
    (Wi-Fi power save, ARP queue limits on big subnets). No nmap needed."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()][:SWEEP_MAX_HOSTS]
    for _ in range(rounds):
        poke(hosts)
        time.sleep(1.5)
    # only this network's addresses: macOS keeps link-local (169.254/16) entries for devices
    # that failed DHCP on the same interface, and those would rename a known device's IP
    return {ip: mac for ip, mac in netinfo.neighbors(iface).items() if _in(ip, net)}


def _in(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def poke(hosts: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        for i, host in enumerate(hosts):
            try:
                s.sendto(b"", (host, 9))
            except OSError:  # EHOSTDOWN/ENOBUFS on macOS once its ARP queue is full: pace it
                time.sleep(0.01)
            if i % 64 == 63:
                time.sleep(0.005)


def parse_neigh(js: str) -> dict[str, str]:
    return netinfo.parse_ip_neigh(js)


def reverse_dns(ips: list[str]) -> dict[str, str]:
    def one(ip: str) -> tuple[str, str | None]:
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, None

    # gethostbyaddr has no timeout knob and macOS waits ~5s per address with no PTR record:
    # one thread per address bounds the whole pass at one timeout
    with ThreadPoolExecutor(max(16, min(len(ips), 256))) as ex:
        return {ip: h for ip, h in ex.map(one, ips) if h}


# ---- mDNS --------------------------------------------------------------------
def mdns(iface: str, seconds: int = 8, local_ip: str | None = None) -> dict[str, list[Sighting]]:
    """Pure-Python mDNS (zeroconf) on every OS; avahi-browse only if zeroconf can't run."""
    from . import mdns as mdnslib

    got = mdnslib.browse(local_ip, seconds)
    if got is not None:
        return got
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
        if txt and stype != "_companion-link._tcp":  # rotating ids: bloat, identifies nothing
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


# SSDP devices answer an M-SEARCH by unicast UDP *from a random port* back to the port the
# search came from. A stateful host firewall cannot match those replies to the multicast search,
# so they are dropped unless the search leaves from a fixed port the firewall can allow
# (ufw: `allow in on <lan-if> proto udp from <lan-cidr> to any port 1901`).
SSDP_REPLY_PORT_DEFAULT = 1901


def ssdp_reply_port() -> int:
    """The fixed source port for M-SEARCH; HOMESENTRY_SSDP_PORT overrides, 0 means ephemeral.

    A bad value never aborts a scan: it is reported and the default is used.
    """
    raw = os.environ.get("HOMESENTRY_SSDP_PORT", "").strip()
    if not raw:
        return SSDP_REPLY_PORT_DEFAULT
    try:
        port = int(raw)
    except ValueError:
        port = -1
    if not 0 <= port <= 65535:
        print(
            f"  SSDP: ignoring invalid HOMESENTRY_SSDP_PORT={raw!r}; "
            f"using {SSDP_REPLY_PORT_DEFAULT}"
        )
        return SSDP_REPLY_PORT_DEFAULT
    return port


def _bind_reply_port(s: socket.socket, port: int) -> int:
    """Bind the search socket to the fixed reply port; fall back to an ephemeral one if taken.

    No SO_REUSEADDR: on Linux it would let this socket share a port another socket already
    holds, and unicast replies then reach only one of them. An occupied port must fail here.
    """
    if port:
        try:
            s.bind(("", port))
            return port
        except OSError as exc:
            print(
                f"  SSDP: reply port {port} unavailable ({exc}); using an ephemeral port, "
                "which a host firewall may block"
            )
    s.bind(("", 0))
    return s.getsockname()[1]


def safe_ssdp_location(responder: str, location: str) -> bool:
    """Only fetch a device description from the device that answered, on a private LAN address.

    SSDP replies are unauthenticated UDP: anyone on the LAN can send one. Following an arbitrary
    LOCATION would let them make this scanner request localhost or other internal services.
    """
    try:
        url = httpx.URL(location)
        host = ipaddress.ip_address(url.host)
        sender = ipaddress.ip_address(responder)
    except (ValueError, httpx.InvalidURL):
        return False
    if url.scheme not in ("http", "https") or host != sender:
        return False
    return host.is_private and not (host.is_loopback or host.is_link_local or host.is_unspecified)


def ssdp(seconds: float = 4.0, local_ip: str | None = None) -> dict[str, list[Sighting]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    _bind_reply_port(s, ssdp_reply_port())
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
    with httpx.Client(timeout=4, follow_redirects=False) as client:
        for ip, locs in locations.items():
            for loc in sorted(locs)[:6]:
                if not safe_ssdp_location(ip, loc):
                    continue
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


# ---- port / service scan (optional, slower) ------------------------------------
PORT_SRC = "ports"  # evidence source for open ports, whichever engine found them


def port_engine() -> str:
    """'native' (built in, every OS) unless HOMESENTRY_PORTSCAN=nmap asks for nmap -sV."""
    want = os.environ.get("HOMESENTRY_PORTSCAN", "native").strip().lower()
    return "nmap" if want == "nmap" and shutil.which("nmap") else "native"


def service_scan(ips: list[str], top_ports: int = 100) -> dict[str, list[Sighting]] | None:
    """Open ports + versions per host. None if the scan didn't run (vs {} = nothing open)."""
    if not ips:
        return None
    if port_engine() == "native":
        from . import portscan

        return portscan.scan(ips)
    return nmap_scan(ips, top_ports)


def nmap_scan(ips: list[str], top_ports: int = 100) -> dict[str, list[Sighting]] | None:
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
            sights.append((PORT_SRC, "open_port", desc.strip()))
            for sc in port.findall("script[@id='http-title']"):
                title = (sc.get("output") or "").strip()
                if title and not title.startswith(("Site doesn't have", "Did not follow")):
                    sights.append((PORT_SRC, "http_title", title[:200]))
        if sights:
            res[ip] = sights
    return res


# ---- helpers -----------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 30) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
