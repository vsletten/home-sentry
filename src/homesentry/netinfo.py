"""Platform layer: which LANs this machine is on, and who its neighbors are.

Everything OS-specific about *reading the network* lives here, behind three calls:

    lan_contexts() -> [{iface, local_ip, cidr, gateway, mac}, ...]   default-route LAN first
    neighbors(iface) -> {ip: mac}                                   the kernel's ARP table
    tailscale_cmd() -> [argv...] | None                             the Tailscale CLI, if any

Linux reads `ip -j` and /sys; macOS reads `route`, `ifconfig`, `arp` and `ipconfig`. Every
parser is a pure function over captured command output, so each platform is unit-tested on
every platform. Nothing here needs root.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

Context = dict[str, str]

RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

# Interfaces that are never a home LAN leg. Linux names, then macOS names.
VIRTUAL_IFACE = (
    "lo",
    "docker",
    "br-",
    "veth",
    "tailscale",
    "virbr",
    "tun",
    "wg",
    "zt",
    "utun",
    "bridge",
    "awdl",
    "llw",
    "gif",
    "stf",
    "anpi",
    "ap",
    "vmenet",
    "vnic",
)


def platform() -> str:
    """'linux', 'darwin' or 'windows' (HOMESENTRY_PLATFORM is not consulted: tests patch this)."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "windows"
    return sys.platform


def is_lan_ip(ip: str) -> bool:
    """Home-LAN address (RFC 1918). Stricter than ipaddress.is_private, which also says yes to
    documentation and other reserved ranges."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in RFC1918)


def norm_mac(mac: str) -> str:
    """Canonical lower-case, zero-padded MAC. macOS `arp` prints `f8:a2:6d:f6:3:9f`; Windows
    prints `f8-a2-6d-f6-03-9f`. The inventory is keyed by MAC, so every source must agree."""
    parts = re.split(r"[:-]", mac.strip().lower())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return ""
    return ":".join(p.zfill(2) for p in parts)


def _usable_mac(mac: str) -> bool:
    return (
        bool(mac)
        and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
        and not (
            int(mac[:2], 16) & 0x01  # multicast (01:00:5e:..., 33:33:...)
        )
    )


# ---- public API ----------------------------------------------------------------
def lan_context() -> Context:
    """Interface, local IP/MAC, CIDR and gateway of the default route."""
    return lan_contexts()[0]


def lan_contexts() -> list[Context]:
    """Every physical interface with a private IPv4: the default-route LAN first, then any
    extra legs (a USB-Ethernet into a second router, a Wi-Fi card, ...). Each is scanned."""
    plat = platform()
    if plat == "linux":
        return _linux_contexts()
    if plat == "darwin":
        return _darwin_contexts()
    raise RuntimeError(f"HomeSentry does not read networks on {plat} yet")


def neighbors(iface: str) -> dict[str, str]:
    """{ip: mac} from the OS neighbor (ARP) table for one interface."""
    plat = platform()
    if plat == "linux":
        return parse_ip_neigh(_run(["ip", "-j", "neigh", "show", "dev", iface]) or "[]")
    if plat == "darwin":
        return parse_arp_an(_run(["arp", "-an", "-i", iface]) or "", iface)
    return {}


def tailscale_cmd() -> list[str] | None:
    """The Tailscale CLI. On macOS the App Store / standalone app ships it inside the bundle
    and the `tailscale` shim on PATH is optional."""
    if p := shutil.which("tailscale"):
        return [p]
    if platform() == "darwin":
        app = Path("/Applications/Tailscale.app/Contents/MacOS/Tailscale")
        if app.exists():
            return [str(app)]
    return None


# ---- Linux ---------------------------------------------------------------------
def _linux_contexts() -> list[Context]:
    routes = json.loads(_run(["ip", "-j", "-4", "route", "show", "default"]) or "[]")
    addrs = json.loads(_run(["ip", "-j", "-4", "addr", "show"]) or "[]")
    macs = {}
    for a in addrs:
        iface = a.get("ifname", "")
        p = Path(f"/sys/class/net/{iface}/address")
        macs[iface] = p.read_text().strip() if p.exists() else a.get("address", "")
    default_if = routes[0]["dev"] if routes else ""
    extra_gw = {}
    for a in addrs:
        iface = a.get("ifname", "")
        lan = any(is_lan_ip(i.get("local", "")) for i in a.get("addr_info", []))
        if iface != default_if and lan and not iface.startswith(VIRTUAL_IFACE):
            gw = (_run(["nmcli", "-g", "IP4.GATEWAY", "device", "show", iface]) or "").strip()
            extra_gw[iface] = gw
    return linux_contexts_from(routes, addrs, macs, extra_gw)


def linux_contexts_from(
    routes: list[dict], addrs: list[dict], macs: dict[str, str], gateways: dict[str, str]
) -> list[Context]:
    """Pure: `ip -j -4 route show default` + `ip -j -4 addr show` -> contexts."""
    if not routes:
        raise RuntimeError("no default route")
    default_if, default_gw = routes[0]["dev"], routes[0].get("gateway", "")
    out: list[Context] = []
    for a in addrs:
        iface = a.get("ifname", "")
        is_default = iface == default_if
        if not is_default and iface.startswith(VIRTUAL_IFACE):
            continue
        for info in a.get("addr_info", []):
            if info.get("family", "inet") != "inet":
                continue
            if not is_default and not is_lan_ip(info["local"]):
                continue
            net = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}").network
            ctx = {
                "iface": iface,
                "local_ip": info["local"],
                "cidr": str(net),
                "gateway": default_gw if is_default else gateways.get(iface, ""),
                "mac": norm_mac(macs.get(iface, "")),
            }
            if is_default:
                out.insert(0, ctx)
            else:
                out.append(ctx)
            break
    if not out or out[0]["iface"] != default_if:
        raise RuntimeError(f"default route interface {default_if} has no IPv4 address")
    return out


def parse_ip_neigh(js: str) -> dict[str, str]:
    out = {}
    for n in json.loads(js):
        state = n.get("state") or []
        mac = norm_mac(n.get("lladdr") or "")
        if mac and _usable_mac(mac) and "FAILED" not in state and ":" not in n["dst"]:
            out[n["dst"]] = mac
    return out


# ---- macOS ---------------------------------------------------------------------
def _darwin_contexts() -> list[Context]:
    default = parse_route_get(_run(["route", "-n", "get", "default"]) or "")
    if not default.get("interface"):
        raise RuntimeError("no default route")
    ifaces = parse_ifconfig(_run(["ifconfig", "-a"]) or "")
    gateways = {default["interface"]: default.get("gateway", "")}
    for name in ifaces:
        if name not in gateways and not name.startswith(VIRTUAL_IFACE):
            gateways[name] = (_run(["ipconfig", "getoption", name, "router"]) or "").strip()
    return darwin_contexts_from(default["interface"], ifaces, gateways)


def darwin_contexts_from(
    default_if: str, ifaces: dict[str, dict], gateways: dict[str, str]
) -> list[Context]:
    """Pure: `route -n get default` interface + parsed `ifconfig -a` -> contexts."""
    out: list[Context] = []
    for name, info in ifaces.items():
        is_default = name == default_if
        if not info.get("inet") or info.get("status") == "inactive":
            continue
        if not is_default and (name.startswith(VIRTUAL_IFACE) or not is_lan_ip(info["inet"])):
            continue
        ctx = {
            "iface": name,
            "local_ip": info["inet"],
            "cidr": str(ipaddress.ip_interface(f"{info['inet']}/{info['prefixlen']}").network),
            "gateway": gateways.get(name, ""),
            "mac": norm_mac(info.get("ether", "")),
        }
        if is_default:
            out.insert(0, ctx)
        else:
            out.append(ctx)
    if not out or out[0]["iface"] != default_if:
        raise RuntimeError(f"default route interface {default_if} has no IPv4 address")
    return out


def parse_route_get(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, sep, v = line.strip().partition(":")
        if sep and k in ("gateway", "interface"):
            out[k] = v.strip()
    return out


def parse_ifconfig(text: str) -> dict[str, dict]:
    """macOS `ifconfig -a` -> {iface: {ether, inet, prefixlen, status}} (first IPv4 only)."""
    out: dict[str, dict] = {}
    cur: dict | None = None
    for line in text.splitlines():
        if m := re.match(r"^([A-Za-z0-9]+): flags=", line):
            cur = out.setdefault(m.group(1), {})
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("ether "):
            cur["ether"] = s.split()[1]
        elif s.startswith("inet ") and "inet" not in cur:
            m = re.match(r"inet (\S+) netmask (0x[0-9a-fA-F]+|\S+)", s)
            if m:
                cur["inet"] = m.group(1)
                mask = m.group(2)
                if mask.startswith("0x"):
                    cur["prefixlen"] = bin(int(mask, 16)).count("1")
                else:
                    cur["prefixlen"] = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
        elif s.startswith("status: "):
            cur["status"] = s.split(": ", 1)[1]
    return out


_ARP_RE = re.compile(r"^\? \((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\S+)")


def parse_arp_an(text: str, iface: str | None = None) -> dict[str, str]:
    """macOS `arp -an`: `? (10.0.0.5) at f8:a2:6d:f6:3:9f on en0 ifscope [ethernet]`."""
    out = {}
    for line in text.splitlines():
        m = _ARP_RE.match(line.strip())
        if not m or (iface and m.group(3) != iface):
            continue
        mac = norm_mac(m.group(2))  # "(incomplete)" normalizes to ""
        if mac and _usable_mac(mac):
            out[m.group(1)] = mac
    return out


# ---- helpers -------------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 30) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return None
