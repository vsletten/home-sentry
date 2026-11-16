import datetime as dt
import json
import sqlite3

import httpx

from homesentry import discover, intel, threat
from homesentry.store import Store


def ev(*triples):
    return [{"source": s, "key": k, "value": v} for s, k, v in triples]


def cve(cid, score, *matches):
    return {
        "id": cid,
        "descriptions": [{"lang": "en", "value": f"{cid} summary"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": list(matches)}]}],
    }


def cm(criteria, **bounds):
    return {"vulnerable": True, "criteria": criteria, **bounds}


SSH = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"


def test_vkey_orders_openssh_style_versions():
    assert threat.vkey("9.6p1") < threat.vkey("9.8")
    assert threat.vkey("8.8") < threat.vkey("8.8p1") < threat.vkey("8.9")
    assert threat.vkey("2.83") > threat.vkey("2.9")  # numeric, not lexical


def test_components_from_banners():
    comps = threat.components(
        ev(
            ("ports", "open_port", "22/tcp ssh OpenSSH 8.8 protocol 2.0"),
            ("ports", "open_port", "22/tcp ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.20 Ubuntu Linux"),
            ("ports", "open_port", "53/tcp domain dnsmasq 2.83"),
            ("ports", "open_port", "139/tcp netbios-ssn Samba smbd 3.X - 4.X workgroup: W"),
            ("ssdp", "server", "Linux/2.6.18.8-Pace-1.318.2.x, UPnP/1.0 DIRECTV JHUPnP/1.0"),
        )
    )
    got = {(c["name"], c["version"], c["backported"]) for c in comps}
    assert ("OpenSSH", "8.8", False) in got
    assert ("OpenSSH", "9.6p1", True) in got
    assert ("dnsmasq", "2.83", False) in got
    assert ("Linux kernel", "2.6.18.8", False) in got
    assert not any(c["name"] == "Samba" for c in comps)  # "3.X - 4.X" is not a version


def test_cve_range_and_exact_matching():
    cves = [
        cve("CVE-A", 8.1, cm(SSH, versionStartIncluding="8.5", versionEndExcluding="9.8")),
        cve("CVE-B", 5.0, cm(SSH, versionEndExcluding="8.0")),
        cve("CVE-C", 6.0, cm("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*")),
        cve("CVE-D", 9.0, cm(SSH)),  # "all versions": no signal, skipped
        cve("CVE-E", 7.0, cm("cpe:2.3:a:other:openssh:*:*:*:*:*:*:*:*", versionEndExcluding="99")),
        cve("CVE-F", 4.0, cm("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*")),
    ]
    ids = {h["id"] for h in threat.cve_matches(cves, "openbsd", "openssh", "9.6p1")}
    assert ids == {"CVE-A", "CVE-C", "CVE-F"}
    ids = {h["id"] for h in threat.cve_matches(cves, "openbsd", "openssh", "7.4")}
    assert ids == {"CVE-B"}


def test_kernel_eol():
    cycles = [
        {"cycle": "5.4", "eol": "2025-12-03"},
        {"cycle": "6.12", "eol": "2030-12-01"},
        {"cycle": "3.2", "eol": "2018-05-31"},
    ]
    today = dt.date(2026, 11, 9)
    assert "predates" in (threat.kernel_eol("2.6.18.8", cycles, today) or "")
    assert "2025-12-03" in (threat.kernel_eol("5.4.0", cycles, today) or "")
    assert threat.kernel_eol("6.12.3", cycles, today) is None


def test_assess_device_severity_rules():
    evidence = ev(
        ("ports", "open_port", "23/tcp telnet BusyBox telnetd"),
        ("ports", "open_port", "22/tcp ssh OpenSSH 8.8 protocol 2.0"),
        ("ssdp", "server", "Linux/2.6.18 UPnP/1.0"),
    )
    nvd = {
        ("openbsd", "openssh"): [
            cve("CVE-KEV", 8.1, cm(SSH, versionStartIncluding="8.5", versionEndExcluding="9.8")),
            cve("CVE-LOW", 3.1, cm(SSH, versionEndExcluding="9.0")),
        ]
    }
    kev = {"CVE-KEV": {}}
    fs = threat.assess_device(
        {"device_type": "set-top-box"}, evidence, kev, nvd, [{"cycle": "4.19", "eol": "2024-12-05"}]
    )
    by_kind = {f["kind"]: f for f in fs}
    assert by_kind["cve"]["severity"] == "critical"  # KEV hit
    assert by_kind["cve"]["data"]["cves"][0]["id"] == "CVE-KEV"
    assert by_kind["eol"]["severity"] == "high"
    assert by_kind["exposure"]["title"] == "Telnet is open"
    assert fs[0]["severity"] == "critical"  # sorted worst first


def test_remote_access_on_own_computer_is_info_and_distro_ssh_is_info():
    evidence = ev(
        ("ports", "open_port", "5900/tcp vnc Apple remote desktop vnc"),
        ("ports", "open_port", "22/tcp ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.20"),
    )
    nvd = {("openbsd", "openssh"): [cve("CVE-X", 9.8, cm(SSH, versionEndExcluding="9.8"))]}
    fs = threat.assess_device({"device_type": "computer"}, evidence, {}, nvd, [])
    assert {f["severity"] for f in fs} == {"info"}


def test_nvd_query_never_contains_a_version(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    monkeypatch.setattr(intel, "NVD_GAP", 0)
    seen = []

    def handler(req: httpx.Request):
        seen.append(str(req.url))
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 1,
                "totalResults": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-1"}}],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    out = intel.nvd_product("thekelleys", "dnsmasq", client=client)
    assert out == [{"id": "CVE-1"}]
    assert len(seen) == 1 and "cpe%3A2.3%3Aa%3Athekelleys%3Adnsmasq&" in seen[0]
    assert intel.nvd_product("thekelleys", "dnsmasq", client=client) == out  # cached
    assert len(seen) == 1


def test_parse_tailscale_keeps_only_private_direct_paths():
    js = json.dumps(
        {
            "Peer": {
                "a": {
                    "HostName": "Victor's MacBook Pro",
                    "OS": "macOS",
                    "CurAddr": "10.9.9.49:2079",
                },
                "b": {"HostName": "vps", "OS": "linux", "CurAddr": "203.0.113.5:41641"},
                "c": {"HostName": "phone", "OS": "iOS", "CurAddr": ""},
            }
        }
    )
    r = discover.parse_tailscale(js)
    assert r == {
        "10.9.9.49": [("tailscale", "name", "Victor's MacBook Pro"), ("tailscale", "os", "macOS")]
    }


def test_store_migrates_v0_database(tmp_path):
    p = tmp_path / "old.db"
    db = sqlite3.connect(p)
    db.execute(
        "CREATE TABLE devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, ip TEXT,"
        " hostname TEXT, oui_vendor TEXT, label TEXT, device_type TEXT, make TEXT,"
        " model TEXT, firmware TEXT, confidence REAL DEFAULT 0, id_source TEXT,"
        " confirmed INTEGER DEFAULT 0, notes TEXT, first_seen REAL, last_seen REAL)"
    )
    db.execute("INSERT INTO devices(mac, ip) VALUES('aa:bb:cc:00:00:09', '10.0.0.9')")
    db.commit()
    db.close()
    st = Store(p)
    did = st.upsert_seen("aa:bb:cc:00:00:09", "10.0.0.9", None, None, network="10.0.0.0/24")
    assert st.device(did)["network"] == "10.0.0.0/24"
    st.replace_findings(
        did,
        [
            {"severity": "low", "kind": "exposure", "title": "t"},
            {"severity": "high", "kind": "eol", "title": "k"},
        ],
    )
    assert [f["severity"] for f in st.findings(did)] == ["high", "low"]


def test_kev_on_own_computer_caps_at_medium_with_kev_note():
    evidence = ev(("ports", "open_port", "22/tcp ssh OpenSSH 10.3 protocol 2.0"))
    nvd = {("openbsd", "openssh"): [cve("CVE-K", 8.1, cm(SSH, versionEndExcluding="10.6"))]}
    kev = {"CVE-K": {"dateAdded": "2026-11-09", "vulnerabilityName": "OpenSSH bug"}}
    pc = threat.assess_device({"device_type": "computer"}, evidence, kev, nvd, [])
    nas = threat.assess_device({"device_type": "nas"}, evidence, kev, nvd, [])
    assert pc[0]["severity"] == "medium" and "OS updates" in pc[0]["detail"]
    assert nas[0]["severity"] == "critical" and "2026-11-09" in nas[0]["detail"]


def test_tailscale_peer_behind_a_non_apple_nat_box_is_not_used_as_identity():
    from homesentry import identify

    peer = [("tailscale", "name", "Victor's MacBook Pro"), ("tailscale", "os", "macOS")]
    behind = discover.attribute_tailscale(peer, "Mojo Networks", random_mac=False)
    assert behind == [("tailscale", "nat_for", "Victor's MacBook Pro (macos)")]
    g = identify.guess(ev(*behind), "Mojo Networks")
    assert g["device_type"] == "router" and g["make"] != "Apple"
    # an Apple NIC (or a randomized MAC) can really be the Mac itself
    assert discover.attribute_tailscale(peer, "Apple, Inc.", random_mac=False) == peer
    assert discover.attribute_tailscale(peer, None, random_mac=True) == peer
    linux = [("tailscale", "name", "vps"), ("tailscale", "os", "linux")]
    assert discover.attribute_tailscale(linux, "Dell", random_mac=False) == linux


def test_double_nat_finding_for_non_gateway_router():
    e = ev(("probe", "nat", "peer traffic TTL 63 via this box"))
    fs = threat.assess_device({"device_type": "router"}, e, {}, {}, [])
    assert any(f["title"] == "Runs its own NAT network (double NAT)" for f in fs)
    assert not threat.assess_device({"device_type": "gateway"}, e, {}, {}, [])
