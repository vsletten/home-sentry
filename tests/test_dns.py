"""DNS resolver watch: lease parsers per OS, classification, baseline/finding logic, the
timeline event, and the privacy line (no address in a title). Addresses are synthetic
(10.99.0.0/24 LAN; 185.12.64.x stands in for "some public resolver nobody has heard of")."""

from __future__ import annotations

import json

import pytest

from homesentry import dns, netinfo, threat, watch, wizard
from homesentry.store import Store

GW, CIDR = "10.99.0.1", "10.99.0.0/24"
ODD = ["185.12.64.1", "185.12.64.2"]  # routable, in no resolver table: the alarming case

NMCLI = """GENERAL.DEVICE:eth0
DHCP4.OPTION[1]:dhcp_lease_time = 86400
DHCP4.OPTION[2]:dhcp_server_identifier = 10.99.0.1
DHCP4.OPTION[5]:domain_name_servers = 10.99.0.1 75.75.75.75
DHCP4.OPTION[6]:routers = 10.99.0.1
DHCP6.OPTION[1]:dhcp6_name_servers = 2001\\:558\\:feed\\:\\:1 2001\\:558\\:feed\\:\\:2
"""
RESOLVECTL = """Global:
Link 2 (eth0): 10.99.0.1 2001:558:feed::1
Link 3 (wlan0): 1.1.1.1
Link 5 (tailscale0): 100.100.100.100
"""
RESOLV_STUB = (
    "# This is /run/systemd/resolve/stub-resolv.conf\nnameserver 127.0.0.53\noptions edns0\n"
)
RESOLV_REAL = "search lan\nnameserver 10.99.0.1\nnameserver 75.75.75.75\n"
IPCONFIG = """op = BOOTREPLY
htype = 1
yiaddr = 10.99.0.52
siaddr = 10.99.0.1
Options count is 8
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 10.99.0.1
lease_time (uint32): 0x15180
subnet_mask (ip): 255.255.255.0
router (ip_mult): {10.99.0.1}
domain_name_server (ip_mult): {10.99.0.1, 75.75.75.75}
domain_name (string): hsd1.xx.example.net
end (none):
"""
SCUTIL = """DNS configuration

resolver #1
  search domain[0] : hsd1.xx.example.net
  nameserver[0] : 10.99.0.1
  nameserver[1] : 75.75.75.75
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 9.9.9.9
  if_index : 14 (en0)
"""


def test_parsers_per_os_tool():
    assert dns.parse_nmcli(NMCLI) == [
        "10.99.0.1",
        "75.75.75.75",
        "2001:558:feed::1",
        "2001:558:feed::2",
    ]
    assert dns.parse_resolvectl(RESOLVECTL, "eth0") == ["10.99.0.1", "2001:558:feed::1"]
    assert dns.parse_resolvectl(RESOLVECTL, "nope") == [
        "10.99.0.1",
        "2001:558:feed::1",
        "1.1.1.1",
        "100.100.100.100",
    ]
    assert dns.parse_resolv_conf(RESOLV_STUB) == []  # stub => ask resolvectl instead
    assert dns.parse_resolv_conf(RESOLV_REAL) == ["10.99.0.1", "75.75.75.75"]
    assert dns.parse_ipconfig_packet(IPCONFIG) == ["10.99.0.1", "75.75.75.75"]
    assert dns.parse_scutil(SCUTIL) == ["10.99.0.1", "75.75.75.75"]  # resolver #1 only
    assert dns.parse_nmcli("") == [] and dns.parse_scutil("") == []


def test_collect_prefers_the_lease_itself_then_falls_back(monkeypatch):
    calls = []

    def linux_run(cmd, timeout=30):
        calls.append(cmd[0])
        return {"nmcli": "", "resolvectl": RESOLVECTL}.get(cmd[0])

    monkeypatch.setattr(netinfo, "platform", lambda: "linux")
    got = dns.collect({"iface": "eth0"}, run=linux_run)
    assert got == {"servers": ["10.99.0.1", "2001:558:feed::1"], "via": "resolvectl"}
    assert calls == ["nmcli", "resolvectl"]

    monkeypatch.setattr(netinfo, "platform", lambda: "darwin")
    got = dns.collect({"iface": "en0"}, run=lambda cmd, timeout=30: IPCONFIG)
    assert got == {"servers": ["10.99.0.1", "75.75.75.75"], "via": "dhcp (ipconfig)"}
    assert dns.collect({"iface": "en0"}, run=lambda cmd, timeout=30: None) is None


def test_classification_and_wording():
    cls = {ip: dns.classify(ip, GW, CIDR)[0] for ip in (GW, "10.99.0.53", "75.75.75.75")}
    assert cls == {GW: "gateway", "10.99.0.53": "lan", "75.75.75.75": "known"}
    assert dns.classify("2001:558:feed::1")[1] == "Comcast/Xfinity"
    assert dns.classify("45.90.28.200")[1] == "NextDNS"  # per-account address in a known block
    assert dns.classify("100.100.100.100")[0] == "tailscale"
    assert dns.classify("127.0.0.53")[0] == "loopback"
    assert dns.classify("203.0.113.9")[0] == "reserved"  # documentation range is not routable
    assert dns.classify("bogus")[0] == "invalid"
    assert all(dns.classify(ip)[0] == "public" for ip in ODD)
    assert dns.describe([GW, "75.75.75.75", "75.75.76.76"], GW, CIDR) == (
        "your gateway + Comcast/Xfinity (2)"
    )
    assert dns.describe([], GW, CIDR) == "none"
    assert dns.fingerprint(["b", "a"]) == dns.fingerprint(["a", "b"]) != dns.fingerprint(["a"])


def test_normal_house_has_no_finding_and_unknown_resolver_alarms_on_first_sight():
    normal = {"dhcp": [GW], "upstream": ["75.75.75.75", "75.75.76.76"], "via": "dhcp (nmcli)"}
    assert dns.findings(normal, normal, GW, CIDR) == []
    assert dns.findings(normal, None, GW, CIDR) == []  # first scan: baseline, no noise
    hijacked = {"dhcp": [GW], "upstream": ODD, "via": "dhcp (nmcli)"}
    (f,) = dns.findings(hijacked, hijacked, GW, CIDR)  # baseline == current: still flagged
    assert f["severity"] == "high" and f["kind"] == "config"
    assert f["title"].startswith("DNS points at an unrecognized public resolver (set ")
    assert "gateway forwards" in f["detail"] and ODD[0] in f["detail"]
    assert not any(ip in f["title"] for ip in ODD + [GW])
    via_dhcp = {"dhcp": [ODD[0]], "upstream": [], "via": "dhcp (nmcli)"}
    (g,) = dns.findings(via_dhcp, None, GW, CIDR)
    assert "every device" in g["detail"] and g["title"] != f["title"]  # per-set fingerprint


def test_change_to_recognized_resolvers_is_medium_and_keyed_per_set():
    base = {"dhcp": [GW], "upstream": ["75.75.75.75", "75.75.76.76"]}
    cur = {"dhcp": [GW], "upstream": ["1.1.1.1", "1.0.0.1"], "via": "dhcp (nmcli)"}
    (f,) = dns.findings(cur, base, GW, CIDR)
    assert f["severity"] == "medium"
    assert f["title"].startswith("DNS resolvers changed from the baseline (set ")
    assert "Cloudflare (2)" in f["detail"] and "Comcast/Xfinity (2)" in f["detail"]
    assert f["data"]["changed"] == ["upstream"]
    other = dict(cur, upstream=["9.9.9.9"])
    assert dns.findings(other, base, GW, CIDR)[0]["title"] != f["title"]
    # order changes and a part the baseline never had are not changes
    assert dns.findings(dict(cur, upstream=["75.75.76.76", "75.75.75.75"]), base, GW, CIDR) == []
    assert dns.findings(cur, {"dhcp": [GW]}, GW, CIDR) == []
    assert dns.is_dns_fkey(watch.finding_key(f)) and not dns.is_dns_fkey("config:UPnP is enabled")


def test_record_keeps_unread_parts_and_baselines_each_part_once(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("00:11:22:00:00:01", GW, None, "Technicolor", network=CIDR)
    cur = dns.record(st, did, dhcp=[GW], via="dhcp (nmcli)", upstream=None)
    assert cur == {"dhcp": [GW], "upstream": [], "via": "dhcp (nmcli)"}
    assert dns.stored(st.evidence(did), "baseline") == {"dhcp": [GW]}
    # the gateway was read this time: upstream appears and gets its own first-sight baseline
    cur = dns.record(st, did, dhcp=[GW], via="dhcp (nmcli)", upstream=["75.75.75.75"])
    assert dns.stored(st.evidence(did), "baseline") == {"dhcp": [GW], "upstream": ["75.75.75.75"]}
    # a scan that couldn't read either part changes nothing
    cur = dns.record(st, did, dhcp=None, via=None, upstream=None)
    assert cur == {"dhcp": [GW], "upstream": ["75.75.75.75"], "via": "dhcp (nmcli)"}
    # an actual change is stored, the baseline is not
    dns.record(st, did, dhcp=[GW], via="dhcp (nmcli)", upstream=["1.1.1.1"])
    assert dns.stored(st.evidence(did))["upstream"] == ["1.1.1.1"]
    assert dns.stored(st.evidence(did), "baseline")["upstream"] == ["75.75.75.75"]
    assert len([e for e in st.evidence(did) if e["source"] == "dns"]) == 2  # one row per key
    dns.rebaseline(st, did)
    assert dns.stored(st.evidence(did), "baseline") == {"dhcp": [GW], "upstream": ["1.1.1.1"]}


def test_threat_pass_reads_the_evidence_and_wizard_never_sees_it(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("00:11:22:00:00:01", GW, None, "Technicolor", network=CIDR)
    st.set_identity(did, {"device_type": "gateway"}, "auto", 0.9)
    dns.record(st, did, dhcp=[GW], via="dhcp (nmcli)", upstream=ODD)
    fs = threat.assess_device(st.device(did), st.evidence(did), {}, {}, [])
    assert [f["severity"] for f in fs if "DNS" in f["title"]] == ["high"]
    brief = wizard.evidence_brief(st.device(did), st.evidence(did))
    assert "dns." not in brief and ODD[0] not in brief


def test_timeline_event_on_change_with_severity_by_what_it_changed_to():
    dev = {
        "mac": "m",
        "ip": GW,
        "online": 1,
        "firmware": None,
        "retired": None,
        "device_type": "gateway",
        "confirmed": 0,
        "network": CIDR,
        "vendor": "V",
    }
    empty = {"devices": {1: dev}, "ports": {}, "port_scanned": {}, "findings": {}}
    before = empty | {"dns": {1: {"dhcp": [GW], "upstream": ["75.75.75.75"]}}}
    # first sight: no "dns" in before -> no event (baseline), like the first port scan
    assert watch.diff(empty | {"dns": {}}, before, ports_scanned=False) == []
    tame = empty | {"dns": {1: {"dhcp": [GW], "upstream": ["1.1.1.1", "1.0.0.1"]}}}
    (e,) = watch.diff(before, tame, ports_scanned=False)
    assert (e["kind"], e["severity"]) == ("dns_changed", "medium")
    assert e["title"] == "Gateway now forwards DNS to different servers"
    assert "Comcast/Xfinity" in e["detail"] and "Cloudflare (2)" in e["detail"]
    assert e["data"] == {"old": ["75.75.75.75"], "new": ["1.1.1.1", "1.0.0.1"], "which": "upstream"}
    bad = empty | {"dns": {1: {"dhcp": [ODD[0]], "upstream": ["75.75.75.75"]}}}
    (e,) = watch.diff(before, bad, ports_scanned=False)
    assert (e["kind"], e["severity"]) == ("dns_changed", "high")
    assert e["title"] == "DHCP now hands out different DNS servers"
    assert ODD[0] not in e["title"] and "doesn't recognize" in e["detail"]
    # unknown this scan (gateway not read) keeps the old value upstream: nothing to diff
    same_order = empty | {"dns": {1: {"dhcp": [GW], "upstream": ["75.75.75.75"]}}}
    assert watch.diff(before, same_order, ports_scanned=False) == []


def test_event_and_finding_titles_never_carry_addresses():
    cur = {"dhcp": [GW, ODD[0]], "upstream": ["2001:558:feed::1", ODD[1]], "via": "scutil"}
    titles = [f["title"] for f in dns.findings(cur, {"dhcp": ["1.1.1.1"]}, GW, CIDR)]
    titles += [
        f["title"]
        for f in dns.findings(
            {"dhcp": ["1.1.1.1"], "upstream": [], "via": "x"}, {"dhcp": [GW]}, GW, CIDR
        )
    ]
    assert titles
    import re

    for t in titles:
        assert not re.search(r"\d+\.\d+\.\d+\.\d+", t) and "::" not in t, t


# ---- end to end: a scan records it, a change raises event + finding, accept re-baselines ----
@pytest.fixture
def house(tmp_path, monkeypatch):
    from homesentry import discover, intel

    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    ctx = {
        "cidr": CIDR,
        "iface": "eth9",
        "gateway": GW,
        "local_ip": "10.99.0.30",
        "mac": "00:11:22:00:00:30",
    }
    macs = {GW: "00:11:22:00:00:01", "10.99.0.30": "00:11:22:00:00:30"}
    monkeypatch.setattr(discover, "lan_contexts", lambda: [ctx])
    monkeypatch.setattr(discover, "lan_context", lambda: ctx)
    monkeypatch.setattr(discover, "arp_sweep", lambda c, i: dict(macs))
    monkeypatch.setattr(discover, "reverse_dns", lambda ips: {})
    monkeypatch.setattr(discover, "mdns", lambda iface, seconds=8, local_ip=None: {})
    monkeypatch.setattr(discover, "ssdp", lambda seconds=4.0, local_ip=None: {})
    monkeypatch.setattr(discover, "tailscale_peers", lambda: {})
    monkeypatch.setattr(discover, "oui_vendor", lambda mac: "TestCo")
    monkeypatch.setattr(intel, "kev", lambda: {})
    monkeypatch.setattr(intel, "nvd_product", lambda *a, **k: [])
    monkeypatch.setattr(intel, "eol_cycles", lambda p: [])
    lease = {"servers": [GW], "via": "dhcp (nmcli)"}
    monkeypatch.setattr(dns, "collect", lambda ctx, run=None: lease)
    return Store(tmp_path / "inventory.db"), lease


def test_scan_records_baseline_then_change_then_accept_rebaselines(house):
    from fastapi.testclient import TestClient

    from homesentry.scan import run_scan
    from homesentry.web.app import create_app

    st, lease = house
    quiet = lambda m: None  # noqa: E731
    s1 = run_scan(st, gateway=False, log=quiet)
    assert s1["dns"] == {"dhcp": "your gateway", "upstream": None, "via": "dhcp (nmcli)"}
    gw = next(d for d in st.devices() if d["ip"] == GW)
    assert dns.stored(st.evidence(gw["id"]), "baseline") == {"dhcp": [GW]}
    assert not [e for e in s1["event_list"] if e["kind"] == "dns_changed"]

    lease["servers"] = [ODD[0]]  # the gateway starts handing out a stranger's resolver
    s2 = run_scan(st, gateway=False, log=quiet)
    kinds = {e["kind"]: e for e in s2["event_list"]}
    assert kinds["dns_changed"]["severity"] == "high"
    assert kinds["finding_new"]["title"].startswith("New finding: DNS points at an unrecognized")
    assert s2["score"] < s1["score"]
    fk = watch.finding_key(st.findings(gw["id"])[0])

    # the owner says "that's my resolver": accepted, and the current set is the new baseline
    client = TestClient(create_app(st))
    r = client.post(
        f"/device/{gw['id']}/accept",
        data={"fkey": fk, "note": "my own resolver"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert dns.stored(st.evidence(gw["id"]), "baseline") == {"dhcp": [ODD[0]]}
    assert (gw["id"], fk) in st.accepted()
    s3 = run_scan(st, gateway=False, log=quiet)
    assert s3["score"] >= s1["score"] - 1  # accepted risks don't count
    assert not [e for e in s3["event_list"] if e["kind"] == "dns_changed"]

    lease["servers"] = [ODD[1]]  # ...but a *different* stranger alarms again
    s4 = run_scan(st, gateway=False, log=quiet)
    new = [f for f in st.findings(gw["id"]) if "DNS" in f["title"]]
    assert new and (gw["id"], watch.finding_key(new[0])) not in st.accepted()
    assert any(e["kind"] == "dns_changed" and e["severity"] == "high" for e in s4["event_list"])

    # the plan maps it to the DNS playbook, not to a generic review
    from homesentry import plan

    acts = [a for a in plan.build(st)["actions"] if a["playbook"] == "dns-resolvers"]
    assert acts and gw["id"] in acts[0]["device_ids"]
    # and the gateway page shows the finding, the Ask snapshot scrubs the addresses
    assert client.get(f"/device/{gw['id']}").status_code == 200
    from homesentry import agent

    snap = json.dumps(agent.snapshot(st))
    assert ODD[1] not in snap and "DNS points at" in snap


def test_gateway_pass_feeds_upstream_into_the_dns_record(house, monkeypatch):
    from homesentry import gateway
    from homesentry.scan import run_scan

    st, lease = house
    cfgp = __import__("homesentry").config_dir()
    cfgp.mkdir(parents=True, exist_ok=True)
    env = cfgp / "gateway.env"
    env.write_text("GATEWAY_USER=admin\nGATEWAY_PASS=pw\n")
    env.chmod(0o600)
    cfg = {
        "model": "CGA0000COM",
        "vendor": "Technicolor",
        "firmware": "fw1",
        "clients": [],
        "wifi": [],
        "port_forwarding": {"enabled": False, "rules": []},
        "wan_dns": ["75.75.75.75", "75.75.76.76"],
    }

    class FakeReader:
        def __init__(self, host, client=None):
            pass

        def read(self, user, password):
            return dict(cfg)

    monkeypatch.setattr(gateway, "RdkbReader", FakeReader)
    s = run_scan(st, gateway=True, log=lambda m: None)
    assert s["dns"]["upstream"] == "Comcast/Xfinity (2)" and "wan_dns" not in s["gateway"]
    gw = next(d for d in st.devices() if d["ip"] == GW)
    assert dns.stored(st.evidence(gw["id"]))["upstream"] == ["75.75.75.75", "75.75.76.76"]
    # the next scan without a gateway read keeps the upstream set; nothing is "changed"
    s2 = run_scan(st, gateway=False, log=lambda m: None)
    assert s2["dns"]["upstream"] == "Comcast/Xfinity (2)"
    assert not [e for e in s2["event_list"] if e["kind"] == "dns_changed"]
    assert st.findings(gw["id"]) == []
