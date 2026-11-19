"""Outside-in without a VPS: router-reported exposure (UPnP IGD, NAT-PMP, CGNAT), IPv6
per-device checks, the reflector service and the opt-in passive lookup. All synthetic."""

from __future__ import annotations

import json
import struct

import httpx
import pytest
from fastapi.testclient import TestClient

from homesentry import exposure, outside, reflector, threat
from homesentry.store import Store

LOC = "http://192.168.77.1:5000/rootDesc.xml"
DESC = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device>
<serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
<controlURL>http://10.0.0.9/evil</controlURL></service></serviceList>
</device></deviceList></device></deviceList></device></root>"""


def soap_ok(fields):
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    env = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
    return f'{env}<u:R xmlns:u="urn:x">{inner}</u:R></s:Body></s:Envelope>'


MAPPINGS = [
    {"NewProtocol": "TCP", "NewExternalPort": "32400", "NewInternalClient": "192.168.77.20",
     "NewInternalPort": "32400", "NewEnabled": "1", "NewLeaseDuration": "0",
     "NewPortMappingDescription": "Plex Media Server"},
    {"NewProtocol": "UDP", "NewExternalPort": "3074", "NewInternalClient": "192.168.77.30",
     "NewInternalPort": "3074", "NewEnabled": "1", "NewPortMappingDescription": "Xbox",
     "NewLeaseDuration": "3600"},
]  # fmt: skip


def fake_router(external="203.0.113.7"):
    calls = []

    def handler(req: httpx.Request):
        calls.append((req.method, str(req.url), req.headers.get("soapaction")))
        if req.method == "GET":
            return httpx.Response(200, text=DESC)
        action = req.headers["soapaction"].split("#")[1].strip('"')
        assert action.startswith("Get"), "only read-only actions may ever be sent"
        if action == "GetExternalIPAddress":
            return httpx.Response(200, text=soap_ok({"NewExternalIPAddress": external}))
        if action == "GetStatusInfo":
            return httpx.Response(200, text=soap_ok({"NewConnectionStatus": "Connected"}))
        i = int(req.content.decode().split("<NewPortMappingIndex>")[1].split("<")[0])
        if i < len(MAPPINGS):
            return httpx.Response(200, text=soap_ok(MAPPINGS[i]))
        return httpx.Response(500, text=soap_ok({"errorCode": "713"}))

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_classify_external():
    assert exposure.classify_external("100.72.1.9") == "cgnat"
    assert exposure.classify_external("192.168.1.2") == "private"
    assert exposure.classify_external("8.8.8.8") == "public"
    assert exposure.classify_external(None) == "unknown"


def test_parse_igd_keeps_control_urls_on_the_describing_host():
    got = exposure.parse_igd(DESC, LOC)
    assert got == [
        ("urn:schemas-upnp-org:service:WANIPConnection:1", "http://192.168.77.1:5000/ctl/IPConn")
    ]


def test_read_igd_lists_mappings_read_only():
    client, calls = fake_router()
    res = exposure.read_igd(LOC, client)
    assert res["external_ip"] == "203.0.113.7" and res["status"] == "Connected"
    assert [(m["proto"], m["external_port"], m["internal_ip"]) for m in res["mappings"]] == [
        ("TCP", 32400, "192.168.77.20"),
        ("UDP", 3074, "192.168.77.30"),
    ]
    assert all("evil" not in url for _, url, _ in calls)


def test_router_report_stores_the_wan_class_never_the_address(monkeypatch):
    client, _ = fake_router("100.80.0.5")
    monkeypatch.setattr(exposure, "igd_locations", lambda **k: {"192.168.77.1": {LOC}})
    ctx = {"cidr": "192.168.77.0/24", "gateway": "192.168.77.1", "local_ip": "192.168.77.2"}
    rep, ext = exposure.router_report(ctx, client)
    assert rep["wan"] == "cgnat" and ext == "100.80.0.5"
    assert "100.80.0.5" not in json.dumps(rep)


def test_natpmp_parse():
    pkt = struct.pack("!BBHI", 0, 128, 0, 99) + bytes([198, 51, 100, 4])
    assert exposure.parse_natpmp(pkt) == "198.51.100.4"
    assert exposure.parse_natpmp(struct.pack("!BBHI", 0, 128, 3, 0) + b"\0" * 4) is None


def test_v6_neighbor_parsers_keep_only_global_addresses():
    ndp = (
        "Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\n"
        "2001:db8:1:2::10                3c:6:30:aa:bb:cc   en0   23h59m58s S\n"
        "2600:1700:1:2::10               3c:6:30:aa:bb:cc   en0   23h59m58s S\n"
        "fe80::1%en0                     0:11:22:33:44:55   en0   permanent R  R\n"
    )
    assert exposure.parse_ndp(ndp, "en0") == {"2600:1700:1:2::10": "3c:06:30:aa:bb:cc"}
    js = json.dumps([
        {"dst": "2600:1700:1:2::20", "lladdr": "AA:BB:CC:00:00:01", "state": ["STALE"]},
        {"dst": "fd00::5", "lladdr": "aa:bb:cc:00:00:02", "state": ["REACHABLE"]},
        {"dst": "2600:1700:1:2::21", "lladdr": "aa:bb:cc:00:00:03", "state": ["FAILED"]},
    ])  # fmt: skip
    assert exposure.parse_ip6_neigh(js) == {"2600:1700:1:2::20": "aa:bb:cc:00:00:01"}
    one = exposure.one_per_device(
        {"2600:1::aaaa:bbbb:cccc:dddd": "m1", "2600:1::211:22ff:fe33:4455": "m1", "2600:1::5": "m2"}
    )
    assert one == {"m1": "2600:1::211:22ff:fe33:4455", "m2": "2600:1::5"}


def test_findings_forward_cgnat_and_upnp():
    plex = {"proto": "TCP", "external_port": 32400, "internal_port": 32400, "wan": "public",
            "description": "Plex Media Server"}  # fmt: skip
    (f,) = outside.forward_findings(plex)
    assert f["severity"] == "high" and "Router forwards TCP 32400" in f["title"]
    (f,) = outside.forward_findings({**plex, "internal_port": 3389, "external_port": 3389})
    assert f["severity"] == "critical"
    (f,) = outside.forward_findings({**plex, "wan": "cgnat"})
    assert f["severity"] == "low" and "carrier-grade NAT" in f["detail"]
    (f,) = outside.forward_findings({**plex, "proto": "UDP"})
    assert f["severity"] == "low"
    rep = {"wan": "cgnat", "igd": [{"mappings": [plex]}], "at": "now"}
    titles = [f["title"] for f in outside.router_findings(rep)]
    assert titles == [
        "Carrier-grade NAT: the internet can't reach you over IPv4",
        "UPnP port opening is on (1 open)",
    ]
    assert outside.router_findings({"wan": "public", "igd": []}) == []


def test_run_and_record_routes_findings_to_the_right_devices(monkeypatch):
    st = Store(":memory:")
    gw = st.upsert_seen("00:11:22:00:00:01", "192.168.77.1", None, None, network="192.168.77.0/24")
    nas = st.upsert_seen(
        "00:11:22:00:00:20", "192.168.77.20", None, None, network="192.168.77.0/24"
    )
    tv = st.upsert_seen("00:11:22:00:00:40", "192.168.77.40", None, None, network="192.168.77.0/24")
    ctx = {"iface": "en0", "cidr": "192.168.77.0/24", "gateway": "192.168.77.1", "local_ip": "x"}
    from homesentry import discover

    monkeypatch.setattr(discover, "lan_contexts", lambda: [ctx])
    client, _ = fake_router()
    monkeypatch.setattr(exposure, "igd_locations", lambda **k: {"192.168.77.1": {LOC}})
    real = exposure.router_report
    monkeypatch.setattr(exposure, "router_report", lambda c: real(c, client))
    monkeypatch.setattr(
        exposure, "v6_neighbors", lambda i: {"2600:1700:1:2::40": "00:11:22:00:00:40"}
    )
    seen = {}

    def fake_probe(conf, ports, runner=None, v6=None):
        seen["v6"] = v6
        return {"open": [], "scanned": len(ports), "seconds": 1.0, "family": "ipv4",
                "v6": [{"addr": "2600:1700:1:2::40", "open": [8080]}]}  # fmt: skip

    monkeypatch.setattr(outside, "load_conf", lambda: {"PROBE_SSH": "box"})
    monkeypatch.setattr(outside, "run_probe", fake_probe)
    out = outside.run_and_record(st, log=lambda m: None, rethreat=False)
    assert out["layers"] == ["router", "active"] and seen["v6"] == ["2600:1700:1:2::40"]

    def titles(did):
        return [
            f["title"] for f in threat.assess_device(st.device(did), st.evidence(did), {}, {}, [])
        ]

    assert "Router forwards TCP 32400 from the internet to this device" in titles(nas)
    assert "TCP 8080 reachable from the internet over IPv6" in titles(tv)
    g = titles(gw)
    assert "UPnP port opening is on (2 open)" in g and any("0 of" in t for t in g)
    assert "203.0.113.7" not in json.dumps([dict(e) for e in st.evidence(gw)])
    # next run: the Plex mapping is gone -> its finding goes too
    MAPPINGS_BACKUP = list(MAPPINGS)
    MAPPINGS.clear()
    try:
        outside.run_and_record(st, log=lambda m: None, rethreat=False)
    finally:
        MAPPINGS.extend(MAPPINGS_BACKUP)
    assert not any("Router forwards" in t for t in titles(nas))


@pytest.fixture
def doc_ranges_public(monkeypatch):
    """Tests use documentation ranges; let the reflector treat them as public addresses."""
    import ipaddress

    doc = [ipaddress.ip_network(n) for n in ("203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32")]
    monkeypatch.setattr(
        reflector,
        "is_public",
        lambda a: a.is_global or any(a in n for n in doc if n.version == a.version),
    )


def test_reflector_scans_only_the_requester(doc_ranges_public):
    scanned = []

    async def fake_scan(target, ports, sem):
        scanned.append(target)
        return [443] if target.endswith("::1") or target == "203.0.113.50" else []

    t = [1000.0]
    app = reflector.create_app(scan=fake_scan, clock=lambda: t[0])

    def client(ip):
        return TestClient(app, client=(ip, 50000))

    r = client("203.0.113.50").post("/v1/check", json={"extra": ["198.51.100.1", "2600:1::9"]})
    assert r.status_code == 200 and r.json()["open"] == [443] and r.json()["extra"] == []
    assert scanned == ["203.0.113.50"]  # extras are ignored for IPv4: nobody else gets scanned
    assert client("203.0.113.50").post("/v1/check").status_code == 429
    t[0] += reflector.COOLDOWN + 1
    assert client("203.0.113.50").post("/v1/check").status_code == 200
    assert client("192.168.1.5").post("/v1/check").status_code == 403
    scanned.clear()
    r = client("2600:1700:1:2::1").post(
        "/v1/check",
        json={"extra": ["2600:1700:1:2::40", "2600:1700:1:3::40", "fd00::1", "x"]},
    )
    assert scanned == ["2600:1700:1:2::1", "2600:1700:1:2::40"]  # same /64 only
    assert client("2600:1700:1:2::99").post("/v1/check").status_code == 429  # same /64 bucket


def test_reflector_proxy_header_trusted_only_from_loopback(monkeypatch, doc_ranges_public):
    async def fake_scan(target, ports, sem):
        return []

    monkeypatch.setenv("REFLECTOR_TRUST_PROXY", "1")
    app = reflector.create_app(scan=fake_scan)
    hdr = {"x-forwarded-for": "198.51.100.77"}
    r = TestClient(app, client=("127.0.0.1", 1)).post("/v1/check", headers=hdr)
    assert r.json()["seen_ip"] == "198.51.100.77"
    r = TestClient(app, client=("203.0.113.9", 1)).post("/v1/check", headers=hdr)
    assert r.json()["seen_ip"] == "203.0.113.9"  # a direct client can't pick its target


def test_reflector_client_flags_vpn_and_passive_lookup():
    (f,) = outside.vpn_findings({"vpn": True, "at": "now"})
    assert "VPN" in f["title"]
    fs = outside.passive_findings({"known": True, "ports": [3389, 443], "at": "now"})
    assert [f["severity"] for f in fs] == ["critical", "high"]
    assert outside.passive_findings({"known": False, "at": "now"})[0]["severity"] == "info"


def test_internetdb_never_sends_or_keeps_the_ip(monkeypatch):
    real = exposure._internetdb  # the conftest fence wraps the public name only
    urls = []

    def handler(req):
        urls.append(str(req.url))
        return httpx.Response(
            200, json={"ip": "203.0.113.7", "ports": [443], "hostnames": ["h.example"], "vulns": []}
        )

    got = real(httpx.Client(transport=httpx.MockTransport(handler)))
    assert urls == ["https://internetdb.shodan.io/"]
    assert (
        got["ports"] == [443]
        and "203.0.113.7" not in json.dumps(got)
        and "h.example" not in json.dumps(got)
    )


def test_home_ports_used_without_nmap(monkeypatch):
    monkeypatch.setattr(outside, "NMAP_SERVICES", [])
    ports = outside.top_ports()
    assert 32400 in ports and 3389 in ports and len(ports) >= 140
