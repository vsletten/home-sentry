"""DNS resolver watch: who does this house actually ask for names?

The attack this catches is the one happening to home routers right now: a compromised
gateway hands every device a DNS server the attacker runs, then quietly answers for banks
and mail. Nothing else on the network looks different. So every scan records two things on
the gateway's device record:

    dhcp      the DNS servers DHCP handed THIS machine (what every device is told to use)
    upstream  the servers the gateway itself forwards to (its WAN side; gateway reader only)

The first sight is the baseline. A change is a timeline event; a set that differs from the
baseline is a finding until the owner accepts it, and accepting re-baselines, so the next
change alarms again. An unrecognized public resolver is a finding on first sight too: a box
that was already hijacked when HomeSentry arrived must never become "normal".

Privacy: resolver addresses are infrastructure, not people, but they still stay out of
event and finding titles (those reach the LLM and push alerts); they live in detail/data,
and the Ask analyst's scrubber redacts them from details before anything leaves.

Reading the lease needs no root anywhere:
    Linux   nmcli (the DHCP option itself), then resolvectl, then /etc/resolv.conf
    macOS   ipconfig getpacket <if> (the DHCP ACK itself), then scutil --dns
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from . import netinfo

# Well-known public resolvers. Not an allowlist of "good": a resolver missing here is only
# "unrecognized", and the owner can accept it. ISPs listed are the ones whose gateways
# HomeSentry reads today plus the big US cable/telco incumbents.
KNOWN: dict[str, str] = {}
for _name, _ips in (
    ("Comcast/Xfinity", "75.75.75.75 75.75.76.76 2001:558:feed::1 2001:558:feed::2"),
    (
        "Cloudflare",
        "1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3 2606:4700:4700::1111 "
        "2606:4700:4700::1001 2606:4700:4700::1112 2606:4700:4700::1002 "
        "2606:4700:4700::1113 2606:4700:4700::1003",
    ),
    ("Google", "8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844"),
    (
        "Quad9",
        "9.9.9.9 149.112.112.112 9.9.9.10 149.112.112.10 9.9.9.11 149.112.112.11 "
        "2620:fe::fe 2620:fe::9 2620:fe::10 2620:fe::fe:10 2620:fe::11 2620:fe::fe:11",
    ),
    (
        "OpenDNS",
        "208.67.222.222 208.67.220.220 208.67.222.123 208.67.220.123 "
        "2620:119:35::35 2620:119:53::53",
    ),
    (
        "AdGuard",
        "94.140.14.14 94.140.15.15 94.140.14.15 94.140.15.16 94.140.14.140 94.140.14.141 "
        "2a10:50c0::ad1:ff 2a10:50c0::ad2:ff",
    ),
    (
        "CleanBrowsing",
        "185.228.168.9 185.228.169.9 185.228.168.10 185.228.169.11 185.228.168.168 185.228.169.168",
    ),
    ("Level 3 / Lumen", "4.2.2.1 4.2.2.2 4.2.2.3 4.2.2.4 4.2.2.5 4.2.2.6 209.244.0.3 209.244.0.4"),
    ("Neustar UltraDNS", "64.6.64.6 64.6.65.6 156.154.70.1 156.154.71.1"),
    ("DNS.Watch", "84.200.69.80 84.200.70.40"),
    ("Spectrum", "209.18.47.61 209.18.47.62"),
    ("Cox", "68.105.28.11 68.105.28.12 68.105.29.11"),
    ("AT&T", "68.94.156.1 68.94.157.1"),
    ("Verizon", "71.242.0.12 71.252.0.12"),
):
    for _ip in _ips.split():
        KNOWN[_ip] = _name
# Resolvers that give every account its own address inside a block
KNOWN_NETS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = [
    (ipaddress.ip_network(n), name)
    for n, name in (
        ("45.90.28.0/24", "NextDNS"),
        ("45.90.30.0/24", "NextDNS"),
        ("2a07:a8c0::/32", "NextDNS"),
        ("2a07:a8c1::/32", "NextDNS"),
        ("76.76.2.0/24", "Control D"),
        ("76.76.10.0/24", "Control D"),
        ("194.242.2.0/24", "Mullvad"),
    )
]
TAILSCALE_DNS = "100.100.100.100"


# ---- classification (pure) -----------------------------------------------------------
def classify(ip: str, gateway: str | None = None, cidr: str | None = None) -> tuple[str, str]:
    """-> (class, human name). Classes: gateway, lan, loopback, tailscale, known, reserved,
    public (routable and not recognized: the one that matters), invalid."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid", "not an address"
    if gateway and ip == gateway:
        return "gateway", "your gateway"
    if a.is_loopback:
        return "loopback", "this machine"
    if ip == TAILSCALE_DNS:
        return "tailscale", "Tailscale MagicDNS"
    if cidr:
        try:
            if a in ipaddress.ip_network(cidr, strict=False):
                return "lan", "a device on your LAN"
        except ValueError:
            pass
    if (a.version == 4 and netinfo.is_lan_ip(ip)) or (a.version == 6 and a.is_private):
        return "lan", "a private address"
    if a.is_link_local:
        return "lan", "a link-local address"
    if name := KNOWN.get(ip):
        return "known", name
    for net, name in KNOWN_NETS:
        if a.version == net.version and a in net:
            return "known", name
    if not a.is_global:
        return "reserved", "a reserved address"
    return "public", "an unrecognized public resolver"


def unrecognized(ips: list[str], gateway: str | None, cidr: str | None) -> list[str]:
    return [ip for ip in ips if classify(ip, gateway, cidr)[0] == "public"]


def describe(ips: list[str], gateway: str | None = None, cidr: str | None = None) -> str:
    """'your gateway', 'Cloudflare (2)', 'your gateway + an unrecognized public resolver':
    the set in words, never addresses (this is what titles and push alerts may carry)."""
    counts: dict[str, int] = {}
    for ip in ips:
        name = classify(ip, gateway, cidr)[1]
        counts[name] = counts.get(name, 0) + 1
    if not counts:
        return "none"
    return " + ".join(f"{n} ({c})" if c > 1 else n for n, c in counts.items())


def fingerprint(ips: list[str]) -> str:
    """Short stable id of a resolver set, for finding titles: accepting one set never
    accepts the next one, and the title still carries no address."""
    return hashlib.sha1(",".join(sorted(ips)).encode()).hexdigest()[:6]


# ---- parsers (pure; one per OS tool) ----------------------------------------------------
_NMCLI_DNS = re.compile(
    r"^DHCP[46]\.OPTION\[\d+\]:\s*(?:domain_name_servers|dhcp6_name_servers)\s*=\s*(.+)$", re.M
)


def parse_nmcli(text: str) -> list[str]:
    """`nmcli -t -f DHCP4.OPTION,DHCP6.OPTION device show <if>`: the DHCP options as the
    server sent them. Terse mode escapes ':' in values as '\\:'."""
    out: list[str] = []
    for m in _NMCLI_DNS.finditer(text):
        out += [v.replace("\\:", ":") for v in m.group(1).split()]
    return _clean(out)


def parse_resolvectl(text: str, iface: str | None = None) -> list[str]:
    """`resolvectl dns`: 'Link 2 (eth0): 10.0.0.1 ...' per link. The named link, else all."""
    links: dict[str, list[str]] = {}
    for m in re.finditer(r"^Link \d+ \(([^)]+)\):\s*(.*)$", text, re.M):
        links[m.group(1)] = m.group(2).split()
    if iface and iface in links:
        return _clean(links[iface])
    return _clean([ip for ips in links.values() for ip in ips])


def parse_resolv_conf(text: str) -> list[str]:
    """nameserver lines, minus local stubs (127.0.0.53 means 'ask systemd-resolved')."""
    out = [
        m.group(1)
        for m in re.finditer(r"^\s*nameserver\s+(\S+)", text, re.M)
        if classify(m.group(1))[0] != "loopback"
    ]
    return _clean(out)


def parse_ipconfig_packet(text: str) -> list[str]:
    """macOS `ipconfig getpacket en0`: 'domain_name_server (ip_mult): {10.0.0.1, 1.1.1.1}'."""
    m = re.search(r"domain_name_server \(ip(?:_mult)?\):\s*\{?([^}\n]*)\}?", text)
    return _clean(re.split(r"[,\s]+", m.group(1).strip())) if m else []


def parse_scutil(text: str) -> list[str]:
    """macOS `scutil --dns`: the nameservers of resolver #1 (the default resolver)."""
    out: list[str] = []
    in_first = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("resolver #"):
            if in_first:
                break
            in_first = s == "resolver #1"
            continue
        if in_first and (m := re.match(r"nameserver\[\d+\]\s*:\s*(\S+)", s)):
            out.append(m.group(1))
    return _clean(out)


def _clean(ips: list[str]) -> list[str]:
    seen: list[str] = []
    for ip in ips:
        ip = ip.strip().strip(",").split("%")[0]  # fe80::1%en0 -> fe80::1
        if ip and classify(ip)[0] != "invalid" and ip not in seen:
            seen.append(ip)
    return seen


# ---- collection ----------------------------------------------------------------------
def collect(ctx: dict[str, str], run=None) -> dict[str, Any] | None:
    """The DNS servers this machine was handed for `ctx['iface']`, plus how we learned them.
    'dhcp' sources read the lease itself; the others read what the OS ended up configured
    with (which the owner may have set by hand)."""
    run = run or netinfo._run
    iface = ctx.get("iface") or ""
    plat = netinfo.platform()
    if plat == "linux":
        out = run(["nmcli", "-t", "-f", "DHCP4.OPTION,DHCP6.OPTION", "device", "show", iface])
        if s := parse_nmcli(out or ""):
            return {"servers": s, "via": "dhcp (nmcli)"}
        if s := parse_resolvectl(run(["resolvectl", "dns"]) or "", iface):
            return {"servers": s, "via": "resolvectl"}
        try:
            text = Path("/etc/resolv.conf").read_text()
        except OSError:
            text = ""
        if s := parse_resolv_conf(text):
            return {"servers": s, "via": "resolv.conf"}
    elif plat == "darwin":
        if s := parse_ipconfig_packet(run(["ipconfig", "getpacket", iface]) or ""):
            return {"servers": s, "via": "dhcp (ipconfig)"}
        if s := parse_scutil(run(["scutil", "--dns"]) or ""):
            return {"servers": s, "via": "scutil"}
    return None


# ---- storage on the gateway's device record -----------------------------------------------
SOURCE = "dns"


def stored(evidence: list[dict[str, Any]], key: str = "servers") -> dict[str, Any] | None:
    for e in evidence:
        if e["source"] == SOURCE and e["key"] == key:
            try:
                return json.loads(e["value"])
            except ValueError:
                return None
    return None


def record(
    store,
    device_id: int,
    dhcp: list[str] | None,
    via: str | None,
    upstream: list[str] | None,
) -> dict[str, Any]:
    """Store what we saw this scan. A part we could not read this time (no gateway read,
    nmcli missing) keeps its previous value: 'unknown right now' is not 'changed'.
    The first sight of each part becomes its baseline."""
    ev = store.evidence(device_id)
    prev = stored(ev) or {}
    cur = {
        "dhcp": dhcp if dhcp is not None else prev.get("dhcp") or [],
        "upstream": upstream if upstream is not None else prev.get("upstream") or [],
        "via": via or prev.get("via"),
    }
    base = stored(ev, "baseline") or {}
    nb = dict(base)
    if not nb.get("dhcp") and cur["dhcp"]:
        nb["dhcp"] = cur["dhcp"]
    if not nb.get("upstream") and cur["upstream"]:
        nb["upstream"] = cur["upstream"]
    if nb != base:
        store.delete_evidence(device_id, SOURCE, "baseline")
        store.add_evidence(device_id, SOURCE, "baseline", json.dumps(nb))
    store.delete_evidence(device_id, SOURCE, "servers")
    store.add_evidence(device_id, SOURCE, "servers", json.dumps(cur))
    return cur


def rebaseline(store, device_id: int) -> None:
    """The owner accepted the current set: it is the new normal."""
    cur = stored(store.evidence(device_id))
    if cur:
        store.delete_evidence(device_id, SOURCE, "baseline")
        parts = {k: v for k in ("dhcp", "upstream") if (v := cur.get(k))}
        store.add_evidence(device_id, SOURCE, "baseline", json.dumps(parts))


def is_dns_fkey(fkey: str) -> bool:
    return fkey.startswith(("config:DNS points at", "config:DNS resolvers changed"))


# ---- findings ------------------------------------------------------------------------
def changed(cur: dict[str, Any], base: dict[str, Any]) -> list[str]:
    """Which parts differ from the baseline (order ignored; a part the baseline never had
    cannot have changed)."""
    out = []
    for key in ("dhcp", "upstream"):
        b, c = base.get(key) or [], cur.get(key) or []
        if b and c and set(b) != set(c):
            out.append(key)
    return out


def findings(
    cur: dict[str, Any] | None,
    base: dict[str, Any] | None,
    gateway: str | None,
    cidr: str | None,
) -> list[dict[str, Any]]:
    if not cur:
        return []
    dhcp, up = cur.get("dhcp") or [], cur.get("upstream") or []
    via = cur.get("via") or "this machine"
    source = f"DHCP list read via {via}" + (
        "; upstream list from the gateway's WAN status page." if up else "."
    )
    unknown = unrecognized(dhcp, gateway, cidr) + unrecognized(up, gateway, cidr)
    if unknown:
        where = (
            "DHCP tells every device in the house to resolve names at"
            if unrecognized(dhcp, gateway, cidr)
            else "The gateway forwards every DNS query to"
        )
        n = len(unknown)
        return [
            {
                "severity": "high",
                "kind": "config",
                "title": "DNS points at an unrecognized public resolver "
                f"(set {fingerprint(unknown)})",
                "detail": (
                    f"{where} {n} address{'es' if n != 1 else ''} that {'are' if n != 1 else 'is'} "
                    "neither your gateway, a device on your LAN, nor a resolver HomeSentry "
                    "knows (your ISP's, Cloudflare, Google, Quad9, OpenDNS, NextDNS, ...). "
                    "This is exactly what a DNS-hijacked router looks like: whoever runs that "
                    "resolver decides where 'mybank.com' goes. If you set it yourself, accept "
                    "this finding and it becomes the expected set. "
                    f"Unrecognized: {', '.join(unknown)}. {source}"
                ),
                "data": {"unknown": unknown, "dhcp": dhcp, "upstream": up, "via": via},
            }
        ]
    if base and (parts := changed(cur, base)):
        fp = fingerprint([*dhcp, "|", *up])
        what = " and ".join(
            {"dhcp": "what DHCP hands out", "upstream": "where the gateway forwards"}[p]
            for p in parts
        )
        old = ", ".join(
            f"{p}: {describe(base.get(p) or [], gateway, cidr)}" for p in ("dhcp", "upstream")
        )
        new = ", ".join(
            f"{p}: {describe(cur.get(p) or [], gateway, cidr)}" for p in ("dhcp", "upstream")
        )
        return [
            {
                "severity": "medium",
                "kind": "config",
                "title": f"DNS resolvers changed from the baseline (set {fp})",
                "detail": (
                    f"Changed: {what}. Baseline was {old}; now {new}. All of the new addresses "
                    "are recognized, so this is most likely a deliberate change (yours, or your "
                    "ISP's). If it was yours, accept this finding: the new set becomes the "
                    f"baseline. Now: DHCP {', '.join(dhcp) or '-'}; upstream "
                    f"{', '.join(up) or '-'}. {source}"
                ),
                "data": {
                    "changed": parts,
                    "dhcp": dhcp,
                    "upstream": up,
                    "baseline": {k: base.get(k) or [] for k in ("dhcp", "upstream")},
                    "via": via,
                },
            }
        ]
    return []
