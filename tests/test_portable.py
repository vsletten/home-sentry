"""v3 portable collectors: OS parsers, native port scanner, zeroconf mDNS, bundled OUI.

Fixture text mirrors real macOS / Linux command output; every address and MAC is synthetic.
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from homesentry import discover, mdns, netinfo, portscan
from homesentry.store import Store

# ---- netinfo: macOS ------------------------------------------------------------
IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
anpi0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 9e:00:00:00:00:01
\tstatus: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 1c:f6:4c:00:00:01
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0x7
\tinet 10.99.0.152 netmask 0xffffff00 broadcast 10.99.0.255
\tstatus: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 1c:f6:4c:00:00:02
\tinet 192.168.77.23 netmask 0xffffff00 broadcast 192.168.77.255
\tstatus: active
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 36:00:00:00:00:00
\tinet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
\tstatus: active
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
\tinet 100.64.0.9 --> 100.64.0.9 netmask 0xffffffff
"""
ROUTE_GET = """\
   route to: default
destination: default
       mask: default
    gateway: 10.99.0.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""
ARP_AN = """\
? (10.99.0.1) at 60:3d:26:0:0:10 on en0 ifscope [ethernet]
? (10.99.0.61) at f8:a2:6d:f6:3:9f on en0 ifscope [ethernet]
? (10.99.0.152) at 1c:f6:4c:0:0:1 on en0 ifscope permanent [ethernet]
? (10.99.0.240) at (incomplete) on en0 ifscope [ethernet]
? (10.99.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.77.1) at 0:11:22:33:44:55 on en1 ifscope [ethernet]
"""


def test_mac_normalization_pads_macos_and_windows_forms():
    assert netinfo.norm_mac("f8:a2:6d:f6:3:9f") == "f8:a2:6d:f6:03:9f"
    assert netinfo.norm_mac("F8-A2-6D-F6-03-9F") == "f8:a2:6d:f6:03:9f"
    assert netinfo.norm_mac("(incomplete)") == ""
    assert netinfo.norm_mac("1:2:3") == ""


def test_darwin_ifconfig_route_and_contexts():
    ifs = netinfo.parse_ifconfig(IFCONFIG)
    assert ifs["en0"] == {
        "ether": "1c:f6:4c:00:00:01",
        "inet": "10.99.0.152",
        "prefixlen": 24,
        "status": "active",
    }
    route = netinfo.parse_route_get(ROUTE_GET)
    assert route == {"gateway": "10.99.0.1", "interface": "en0"}
    ctxs = netinfo.darwin_contexts_from(
        "en0", ifs, {"en0": "10.99.0.1", "en1": "192.168.77.1", "bridge0": ""}
    )
    assert [c["iface"] for c in ctxs] == ["en0", "en1"]  # bridge0/utun/lo/anpi are not legs
    assert ctxs[0] == {
        "iface": "en0",
        "local_ip": "10.99.0.152",
        "cidr": "10.99.0.0/24",
        "gateway": "10.99.0.1",
        "mac": "1c:f6:4c:00:00:01",
    }
    assert ctxs[1]["gateway"] == "192.168.77.1"


def test_darwin_arp_filters_iface_incomplete_broadcast_multicast():
    assert netinfo.parse_arp_an(ARP_AN, "en0") == {
        "10.99.0.1": "60:3d:26:00:00:10",
        "10.99.0.61": "f8:a2:6d:f6:03:9f",
        "10.99.0.152": "1c:f6:4c:00:00:01",
    }
    assert netinfo.parse_arp_an(ARP_AN, "en1") == {"192.168.77.1": "00:11:22:33:44:55"}


def test_linux_contexts_default_first_and_skip_virtual():
    routes = [{"dst": "default", "gateway": "10.99.0.1", "dev": "enp1s0"}]
    addrs = [
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1", "prefixlen": 16}]},
        {"ifname": "enx001", "addr_info": [{"local": "192.168.4.20", "prefixlen": 24}]},
        {"ifname": "enp1s0", "addr_info": [{"local": "10.99.0.220", "prefixlen": 24}]},
        {"ifname": "tailscale0", "addr_info": [{"local": "100.64.0.1", "prefixlen": 32}]},
    ]
    macs = {"enp1s0": "D8:43:AE:00:00:01", "enx001": "00:e0:4c:00:00:02"}
    ctxs = netinfo.linux_contexts_from(routes, addrs, macs, {"enx001": "192.168.4.1"})
    assert [(c["iface"], c["cidr"], c["gateway"]) for c in ctxs] == [
        ("enp1s0", "10.99.0.0/24", "10.99.0.1"),
        ("enx001", "192.168.4.0/24", "192.168.4.1"),
    ]
    assert ctxs[0]["mac"] == "d8:43:ae:00:00:01"
    with pytest.raises(RuntimeError):
        netinfo.linux_contexts_from([], addrs, macs, {})


def test_linux_neigh_drops_failed_ipv6_and_multicast():
    js = json.dumps(
        [
            {"dst": "10.99.0.1", "lladdr": "60:3D:26:00:00:10", "state": ["REACHABLE"]},
            {"dst": "10.99.0.9", "lladdr": "60:3d:26:00:00:11", "state": ["FAILED"]},
            {"dst": "fe80::1", "lladdr": "60:3d:26:00:00:12", "state": ["STALE"]},
            {"dst": "10.99.0.250", "lladdr": "01:00:5e:00:00:fb", "state": ["NOARP"]},
            {"dst": "10.99.0.7", "state": ["INCOMPLETE"]},
        ]
    )
    assert discover.parse_neigh(js) == {"10.99.0.1": "60:3d:26:00:00:10"}


def test_unknown_platform_says_so(monkeypatch):
    monkeypatch.setattr(netinfo, "platform", lambda: "plan9")
    with pytest.raises(RuntimeError, match="plan9"):
        netinfo.lan_contexts()


def test_arp_sweep_caps_huge_networks(monkeypatch):
    poked = []
    monkeypatch.setattr(discover, "poke", lambda hosts: poked.append(len(hosts)))
    monkeypatch.setattr(discover.time, "sleep", lambda s: None)
    monkeypatch.setattr(netinfo, "neighbors", lambda iface: {})
    discover.arp_sweep("10.0.0.0/8", "en0")
    assert poked == [discover.SWEEP_MAX_HOSTS] * 2


# ---- bundled OUI -----------------------------------------------------------------
def test_bundled_oui_names_vendors_without_nmap(monkeypatch):
    monkeypatch.setattr(discover, "OUI_PATHS", [])
    monkeypatch.setattr(discover, "_oui", None)
    assert discover.oui_vendor("1c:f6:4c:00:00:01") == "Apple"
    assert discover.oui_vendor("f8:a2:6d:00:00:01") == "Canon"  # not "CANON"
    assert discover.oui_vendor("e4:d1:24:00:00:01") == "Mojo Networks"
    assert discover.oui_vendor("02:00:00:00:00:01") is None  # locally administered


# ---- port scanner: parsers -----------------------------------------------------
def test_ssh_banner_to_nmap_style_product():
    assert portscan.ssh_product("SSH-2.0-OpenSSH_8.1") == "OpenSSH 8.1 protocol 2.0"
    assert (
        portscan.ssh_product("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20")
        == "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20 protocol 2.0"
    )
    assert portscan.ssh_product("SSH-2.0-dropbear_2020.81") == "Dropbear sshd 2020.81 protocol 2.0"


def test_http_parse_server_title_and_error_page_signature():
    raw = (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.21.0\r\nContent-Type: text/html\r\n\r\n"
        b"<html><head><title>\n  TOS   Loading </title></head></html>"
    )
    r = portscan.parse_http(raw)
    assert r["server"] == "nginx/1.21.0" and r["title"] == "TOS Loading"
    assert portscan.http_product(r) == "nginx 1.21.0"
    err = b"HTTP/1.1 404 Not Found\r\n\r\n<hr><center>nginx/1.21.0</center>"
    assert portscan.http_product(portscan.parse_http(err)) == "nginx 1.21.0"
    assert portscan.product_from_server("Apache/2.4.41 (Ubuntu)") == "Apache httpd 2.4.41 (Ubuntu)"
    canon = portscan.parse_http(b"HTTP/1.1 200 OK\r\nServer: CANON HTTP Server\r\n\r\n")
    assert portscan.http_product(canon) == "Canon printer web interface"


def test_vnc_and_mysql_banners():
    assert portscan.describe_banner(5900, b"RFB 003.889\n") == ("vnc", "Apple remote desktop vnc")
    assert portscan.describe_banner(5900, b"RFB 003.008\n") == ("vnc", "VNC protocol 3.8")
    hs = b"\x4a\x00\x00\x00\x0a10.11.6-MariaDB\x00rest"
    assert portscan.describe_banner(3306, hs) == ("mysql", "MariaDB 10.11.6-MariaDB")


def test_dns_version_bind_roundtrip():
    q = portscan.dns_version_query()
    assert struct.unpack(">H", q[:2])[0] == len(q) - 2
    question = q[2 + 12 :]
    txt = b"dnsmasq-2.83"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(txt) + 1) + bytes([len(txt)]) + txt
    msg = struct.pack(">HHHHHH", 0x4853, 0x8400, 1, 1, 0, 0) + question + answer
    assert portscan.parse_dns_txt(struct.pack(">H", len(msg)) + msg) == "dnsmasq-2.83"
    refused = struct.pack(">HHHHHH", 0x4853, 0x8405, 1, 0, 0, 0) + question
    assert portscan.parse_dns_txt(struct.pack(">H", len(refused)) + refused) == ""


def _smb_resp(command: int, words: bytes, data: bytes, flags2: int = 0) -> bytes:
    hdr = b"\xffSMB" + bytes([command]) + b"\x00" * 4 + b"\x98" + struct.pack("<H", flags2)
    hdr += b"\x00" * 20
    msg = hdr + bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


def test_smb1_negotiate_and_session_reveal_samba_version():
    words = struct.pack("<HBHHIIIIQhB", 0, 3, 50, 1, 16644, 65536, 0xABCD, 0xE3FC, 0, 0, 8)
    neg = portscan.parse_smb_negotiate(_smb_resp(0x72, words, b"\x11" * 8 + b"WORKGROUP\x00"))
    assert neg == {"smb1": True, "session_key": 0xABCD, "domain": "WORKGROUP"}
    sess = portscan.parse_smb_session(
        _smb_resp(0x73, b"\x00\x00\x00\x00\x00\x00", b"Windows 6.1\x00Samba 4.6.2\x00WG\x00")
    )
    assert sess == {"os": "Windows 6.1", "lanman": "Samba 4.6.2", "domain": "WG"}
    assert portscan.smb_detail(neg, sess) == "Samba smbd 4.6.2 workgroup: WG"
    # the threat engine's banner regex must still read it
    from homesentry import threat

    comps = threat.components(
        [{"source": "ports", "key": "open_port", "value": "445/tcp microsoft-ds Samba smbd 4.6.2"}]
    )
    assert [(c["name"], c["version"]) for c in comps] == [("Samba", "4.6.2")]


def test_smb_unicode_session_strings_are_aligned():
    data = b"\x00" + "Windows 6.1\x00Samba 4.15.6\x00".encode("utf-16le")
    sess = portscan.parse_smb_session(_smb_resp(0x73, b"\x00" * 6, data, flags2=0x8000))
    assert sess["lanman"] == "Samba 4.15.6"


def test_smb2_only_server_discloses_nothing():
    msg = b"\xfeSMB" + b"\x00" * 60
    neg = portscan.parse_smb_negotiate(b"\x00" + struct.pack(">I", len(msg))[1:] + msg)
    assert neg == {"smb1": False, "smb2": True}
    assert portscan.smb_detail(neg, {}) == ""


def test_nbss_session_request_encodes_names():
    req = portscan.nbss_session_request()
    assert req[:2] == b"\x81\x00" and struct.unpack(">H", req[2:4])[0] == len(req) - 4
    assert req[4] == 0x20 and len(req) == 4 + 34 * 2


def test_afp_status_parse():
    name, mtype = b"NAS-1", b"Netatalk3.1.14"
    body = bytearray(12)
    body[10:] = bytes([len(name)]) + name
    mt_off = len(body)
    body += bytes([len(mtype)]) + mtype
    ver_off = len(body)
    body += b"\x02" + b"\x06AFP3.3" + b"\x06AFP3.4"
    struct.pack_into(">HH", body, 0, mt_off, ver_off)
    resp = struct.pack(">BBHIII", 1, 3, 1, 0, len(body), 0) + bytes(body)
    assert portscan.parse_afp_status(resp) == "Netatalk 3.1.14 name: NAS-1; protocol 3.4"


# ---- port scanner: behavior ------------------------------------------------------
def test_printer_raw_ports_never_receive_a_byte(monkeypatch):
    """An HTTP probe to 9100 prints a page of garbage. Only the connect scan may touch it."""

    async def boom(*a, **k):
        raise AssertionError("probe connected to a raw-print port")

    monkeypatch.setattr(portscan, "_connect", boom)
    for port in (9100, 9101, 9107, 515):
        got = asyncio.run(portscan.probe("10.99.0.61", port))
        assert got[0][2].startswith(f"{port}/tcp ")


def test_loopback_scan_open_closed_and_banners():
    async def run():
        async def ssh(r, w):
            w.write(b"SSH-2.0-OpenSSH_9.9p1\r\n")
            await w.drain()
            w.close()

        async def web(r, w):
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.59\r\n\r\n<title>Cam</title>")
            await w.drain()
            w.close()

        s1 = await asyncio.start_server(ssh, "127.0.0.1", 0)
        s2 = await asyncio.start_server(web, "127.0.0.1", 0)
        p1, p2 = (s.sockets[0].getsockname()[1] for s in (s1, s2))
        closed = s1.sockets[0].getsockname()[1] + 1 if p2 != p1 + 1 else p2 + 1
        try:
            return p1, p2, await portscan._scan(["127.0.0.1"], [p1, p2, closed], 32, True)
        finally:
            s1.close()
            s2.close()

    p1, p2, res = asyncio.run(run())
    got = sorted(v for _, _, v in res["127.0.0.1"])
    assert got == sorted(
        [f"{p1}/tcp unknown OpenSSH 9.9p1 protocol 2.0", f"{p2}/tcp http lighttpd 1.4.59", "Cam"]
    ) or got == sorted(
        [f"{p1}/tcp ssh OpenSSH 9.9p1 protocol 2.0", f"{p2}/tcp http lighttpd 1.4.59", "Cam"]
    )


def test_port_list_keeps_top100_coverage_and_exposure_ports():
    from homesentry import threat

    for p in (21, 22, 23, 80, 111, 139, 443, 445, 548, 554, 631, 2049, 3389, 5900, 8080, 9100):
        assert p in portscan.PORTS
    assert {int(p) for p in threat.EXPOSURE} <= set(portscan.PORTS)


def test_engine_selection(monkeypatch):
    monkeypatch.delenv("HOMESENTRY_PORTSCAN", raising=False)
    assert discover.port_engine() == "native"
    monkeypatch.setenv("HOMESENTRY_PORTSCAN", "nmap")
    monkeypatch.setattr(discover.shutil, "which", lambda t: None)
    assert discover.port_engine() == "native"  # asked for nmap, none installed: still scans


# ---- mDNS (zeroconf) -----------------------------------------------------------
class FakeInfo:
    name = "Living\\032Room._airplay._tcp.local."
    server = "Living-Room.local."
    properties = {b"model": b"AppleTV6,2", b"flag": None, b"": None}

    def parsed_addresses(self):
        return ["10.99.0.40", "fe80::1"]


def test_zeroconf_info_matches_avahi_evidence_shape():
    got = mdns.info_sightings("_airplay._tcp.local.", FakeInfo())
    assert got == {
        "10.99.0.40": {
            ("mdns", "service", "_airplay._tcp"),
            ("mdns", "name", "Living Room"),
            ("mdns", "host", "Living-Room.local"),
            ("mdns", "txt:_airplay._tcp", '"model=AppleTV6,2" "flag"'),
        }
    }


def test_rotating_companion_link_txt_is_not_stored():
    class Companion(FakeInfo):
        name = "Mac._companion-link._tcp.local."
        properties = {b"rpBA": b"11:22:33:44:55:66"}

    got = mdns.info_sightings("_companion-link._tcp.local.", Companion())["10.99.0.40"]
    assert not any(k.startswith("txt:") for _, k, _ in got)


def test_mdns_falls_back_to_avahi_when_zeroconf_cannot_run(monkeypatch):
    monkeypatch.setattr(mdns, "browse", lambda ip, s: None)
    monkeypatch.setattr(discover.shutil, "which", lambda t: None)
    assert discover.mdns("en0", local_ip="10.99.0.2") == {}


# ---- store migration -----------------------------------------------------------
def test_store_migrates_nmap_port_evidence_and_drops_rotating_txt(tmp_path):
    st = Store(tmp_path / "inv.db")
    did = st.upsert_seen("60:3d:26:00:00:01", "10.99.0.1", None, None)
    st.add_evidence(did, "nmap", "open_port", "22/tcp ssh OpenSSH 8.8 protocol 2.0")
    st.add_evidence(did, "mdns", "txt:_companion-link._tcp", '"rpBA=x"')
    st.add_evidence(did, "mdns", "service", "_ssh._tcp")
    st.db.close()
    st = Store(tmp_path / "inv.db")
    ev = {(e["source"], e["key"]) for e in st.evidence(did)}
    assert ("ports", "open_port") in ev and ("nmap", "open_port") not in ev
    assert ("mdns", "txt:_companion-link._tcp") not in ev and ("mdns", "service") in ev
