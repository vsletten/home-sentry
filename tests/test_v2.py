"""v2: monitoring/timeline, posture score + plan, map, Ask privacy, notify, doctor, web.

All fixtures are synthetic (10.99.0.0/24, 00:11:22:* MACs): never paste real scan data.
"""

import json
import os
import time
import warnings

import pytest

from homesentry import agent, discover, doctor, intel, netmap, notify, plan, watch
from homesentry.scan import run_scan
from homesentry.store import Store

warnings.filterwarnings("ignore", category=DeprecationWarning)

GW, NAS, PC, NEWBIE = "10.99.0.1", "10.99.0.20", "10.99.0.30", "10.99.0.40"
MACS = {
    GW: "00:11:22:00:00:01",
    NAS: "00:11:22:00:00:20",
    PC: "00:11:22:00:00:30",
    NEWBIE: "00:11:22:00:00:40",
}


class FakeNet:
    """Stands in for every collector in discover.* so run_scan runs for real, offline."""

    def __init__(self, monkeypatch):
        self.up = {GW, NAS, PC}
        self.svc: dict | None = None
        self.peers: dict = {}
        ctx = {
            "cidr": "10.99.0.0/24",
            "iface": "eth9",
            "gateway": GW,
            "local_ip": PC,
            "mac": MACS[PC],
        }
        monkeypatch.setattr(discover, "lan_contexts", lambda: [ctx])
        monkeypatch.setattr(discover, "lan_context", lambda: ctx)
        monkeypatch.setattr(discover, "arp_sweep", lambda c, i: {ip: MACS[ip] for ip in self.up})
        monkeypatch.setattr(discover, "reverse_dns", lambda ips: {})
        monkeypatch.setattr(discover, "mdns", lambda iface, seconds=8: {})
        monkeypatch.setattr(discover, "ssdp", lambda seconds=4.0, local_ip=None: {})
        monkeypatch.setattr(discover, "service_scan", lambda ips, top_ports=100: self.svc)
        monkeypatch.setattr(discover, "tailscale_peers", lambda: self.peers)
        monkeypatch.setattr(discover, "oui_vendor", lambda mac: "TestCo")
        monkeypatch.setattr(intel, "kev", lambda: {})
        monkeypatch.setattr(intel, "nvd_product", lambda *a, **k: [])
        monkeypatch.setattr(intel, "eol_cycles", lambda p: [])


def scan(st, **kw):
    return run_scan(st, gateway=False, log=lambda m: None, **kw)


def kinds(summary):
    return [(e["kind"], e["title"]) for e in summary["event_list"]]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    return tmp_path


# ---- monitoring pipeline (integration) ------------------------------------------------
def test_scan_pipeline_baseline_new_device_ports_findings_offline(home, monkeypatch):
    net = FakeNet(monkeypatch)
    st = Store(home / "inventory.db")
    s1 = scan(st)
    assert kinds(s1) == [("baseline", "Baseline inventory: 3 devices")]
    assert s1["score"] <= 100 and s1["grade"] in "ABCDF"
    nas = next(d for d in st.devices() if d["ip"] == NAS)
    st.set_identity(nas["id"], {"label": "NAS", "device_type": "nas"}, "user", 1.0, True)

    net.up.add(NEWBIE)
    net.svc = {NAS: [("nmap", "open_port", "2049/tcp nfs")]}
    s2 = scan(st, ports=True)  # first port scan = port baseline: no port events yet
    assert ("new_device", "New device joined the network") in kinds(s2)
    assert not [k for k, _ in kinds(s2) if k.startswith("port_")]
    assert ("finding_new", "New finding: NFS share reachable") in kinds(s2)

    net.svc = {NAS: [("nmap", "open_port", "23/tcp telnet")]}
    s3 = scan(st, ports=True)
    k3 = kinds(s3)
    assert ("port_opened", "Port 23/tcp opened") in k3
    assert ("port_closed", "Port 2049/tcp closed") in k3
    assert ("finding_new", "New finding: Telnet is open") in k3
    assert ("finding_resolved", "Resolved: NFS share reachable") in k3
    sev = {e["kind"]: e["severity"] for e in s3["event_list"]}
    assert sev["port_opened"] == "medium" and sev["port_closed"] == "info"

    net.svc = None  # nmap failed: must NOT read as "every port closed"
    s4 = scan(st, ports=True)
    assert s4["ports"] is False
    assert not [k for k, _ in kinds(s4) if k.startswith(("port_", "finding_resolved"))]
    assert any(e["value"].startswith("23/tcp") for e in st.evidence(nas["id"]))

    net.up.discard(NAS)  # confirmed infrastructure going dark is news; a laptop isn't
    s5 = scan(st)
    assert ("device_offline", "Went offline") in kinds(s5)
    assert st.device(nas["id"])["online"] == 0
    net.up.discard(NEWBIE)
    assert not [e for e in scan(st)["event_list"] if e["kind"] == "device_offline"]

    stored = st.events(limit=100)
    assert len(stored) == sum(len(s["event_list"]) for s in (s1, s2, s3, s4, s5))
    assert all("NAS" not in e["title"] for e in stored)  # titles never embed names


def test_scan_lock_blocks_concurrent_scans(home, monkeypatch):
    FakeNet(monkeypatch)
    st = Store(home / "inventory.db")
    with watch.scan_lock():
        with pytest.raises(watch.ScanBusy):
            scan(st)
    scan(st)  # lock released


def test_watch_schedules_slow_passes_only_when_due(home, monkeypatch):
    FakeNet(monkeypatch).svc = {}  # nmap ran, nothing open (a failed nmap is retried next tick)
    st = Store(home / "inventory.db")
    calls = []
    import homesentry.scan as scanmod

    real = scanmod.run_scan
    monkeypatch.setattr(
        scanmod, "run_scan", lambda store, **kw: calls.append(kw) or real(store, **kw)
    )
    monkeypatch.setattr("homesentry.outside.load_conf", lambda: None)
    watch.run_watch(st, notify=False, log=lambda m: None)
    watch.run_watch(st, notify=False, log=lambda m: None)
    assert calls[0]["ports"] is True and calls[1]["ports"] is False  # 12h cadence
    assert calls[0]["extra"]["trigger"] == "timer"


def test_finding_key_survives_cve_count_changes():
    a = {"kind": "cve", "title": "OpenSSH 8.1: 35 CVE leads"}
    b = {"kind": "cve", "title": "OpenSSH 8.1: 36 CVE leads"}
    c = {"kind": "cve", "title": "OpenSSH 9.9: 3 CVE leads"}
    assert watch.finding_key(a) == watch.finding_key(b) != watch.finding_key(c)


def test_escalation_and_reappearance_events():
    dev = {
        "mac": "m",
        "ip": "x",
        "online": 1,
        "firmware": "1.0",
        "retired": None,
        "device_type": "nas",
        "confirmed": 1,
        "vendor": "V",
    }
    f = {"device_id": 1, "severity": "high", "title": "T", "kind": "cve"}
    before = {
        "devices": {1: dev | {"retired": 1.0}},
        "ports": {},
        "port_scanned": {},
        "findings": {"1|cve:T": f},
    }
    after = {
        "devices": {1: dev | {"firmware": "2.0"}},
        "ports": {},
        "port_scanned": {},
        "findings": {"1|cve:T": f | {"severity": "critical"}},
    }
    ks = {e["kind"]: e for e in watch.diff(before, after, ports_scanned=False)}
    assert ks["reappeared"]["severity"] == "high"
    assert ks["finding_escalated"]["severity"] == "critical"
    assert ks["firmware_changed"]["data"] == {"old": "1.0", "new": "2.0"}


# ---- Tailscale attribution (v2 fix) ---------------------------------------------------
PEER = [("tailscale", "name", "Pat's MacBook"), ("tailscale", "os", "macOS")]


def test_mac_on_usb_ethernet_dongle_is_the_peer_not_a_nat_box():
    assert discover.attribute_tailscale(PEER, "Ugreen Group Limited", False) == PEER
    me = [("mdns", "host", "Pats-MacBook.local")]
    assert discover.attribute_tailscale(PEER, "Weird NIC Co", False, self_reports=me) == PEER
    apple = [("mdns", "service", "_companion-link._tcp")]
    assert discover.attribute_tailscale(PEER, "Weird NIC Co", False, self_reports=apple) == PEER
    nat = discover.attribute_tailscale(PEER, "Mojo Networks", False, self_reports=[])
    assert nat == [("tailscale", "nat_for", "Pat's MacBook (macos)")]


def test_stale_nat_verdict_is_cleared_without_a_fresh_sighting():
    from homesentry.scan import _stale_nat

    prior = [{"source": "tailscale", "key": "nat_for", "value": "Pat's MacBook (macos)"}]
    assert _stale_nat(prior, "Ugreen Group Limited", False, [])
    assert not _stale_nat(prior, "Mojo Networks", False, [])


# ---- score + plan ---------------------------------------------------------------------
def seed(st: Store) -> dict[str, int]:
    ids = {}
    for name, ip, dtype, make in (
        ("Gateway", GW, "gateway", "Technicolor"),
        ("NAS", NAS, "nas", "TerraMaster"),
        ("Wi-Fi", "10.99.0.49", "router", "Arista (Mojo Networks)"),
        ("Laptop", PC, "computer", "Apple"),
        ("Laptop 2", "10.99.0.31", "computer", "Apple"),
    ):
        did = st.upsert_seen(f"00:11:22:00:01:{len(ids):02x}", ip, None, "TestCo")
        st.set_identity(did, {"label": name, "device_type": dtype, "make": make}, "user", 1.0, True)
        ids[name] = did

    def F(sev, kind, title, detail=""):
        return {"severity": sev, "kind": kind, "title": title, "detail": detail}

    st.replace_findings(
        ids["NAS"],
        [
            F("critical", "cve", "OpenSSH 8.8: 32 CVE leads"),
            F("medium", "exposure", "NFS share reachable"),
            F("low", "exposure", "AFP file sharing open"),
        ],
    )
    st.replace_findings(
        ids["Wi-Fi"],
        [
            F("critical", "cve", "OpenSSH 8.1: 35 CVE leads"),
            F("low", "config", "Runs its own NAT network (double NAT)"),
        ],
    )
    st.replace_findings(
        ids["Gateway"],
        [
            F("low", "config", "Dormant port forward 'x'", "TCP 11434-11434 → 10.99.0.220"),
            F("info", "outside", "Outside-in: 0 of 1004 TCP ports reachable"),
        ],
    )
    st.replace_findings(ids["Laptop"], [F("medium", "cve", "OpenSSH 10.3: 21 CVE leads")])
    st.replace_findings(ids["Laptop 2"], [F("medium", "cve", "OpenSSH 10.3: 21 CVE leads")])
    return ids


def test_plan_maps_findings_to_playbooks_and_ranks(home):
    st = Store(home / "inventory.db")
    ids = seed(st)
    p = plan.build(st)
    by_pb = {a["playbook"]: a for a in p["actions"]}
    # whole-device playbook claims every finding on the cloud-managed AP, incl. double NAT
    assert len(by_pb["cloud-managed-wifi"]["findings"]) == 2
    assert by_pb["cloud-managed-wifi"]["guide"] == "wifi-cutover"
    assert "double-nat" not in by_pb
    assert by_pb["nas-update"]["device_ids"] == [ids["NAS"]]
    assert {"nfs-restrict", "afp-off", "dormant-forward"} <= set(by_pb)
    comp = by_pb["computers-updates"]  # household grouping across devices
    assert comp["household"] and sorted(comp["device_ids"]) == sorted(
        [ids["Laptop"], ids["Laptop 2"]]
    )
    assert all(a["gain"] > 0 for a in p["actions"])  # smooth saturation: every fix counts
    assert p["projected"] == sorted(p["projected"]) and p["projected"][0] > p["score"]
    assert by_pb["dormant-forward"]["quick_win"]
    t = plan.render_title(by_pb["nas-update"], {ids["NAS"]: "NAS"}.get)
    assert t == "Update the operating system on NAS"


def test_isp_wifi_router_and_ap_are_one_project(home):
    st = Store(home / "inventory.db")
    ids = seed(st)
    ap = st.upsert_seen("00:11:22:00:02:01", "10.99.0.240", None, "Mojo Networks")
    st.set_identity(
        ap,
        {"label": "AP", "device_type": "router", "make": "Arista (Mojo Networks)"},
        "user",
        1.0,
        True,
    )
    st.replace_findings(
        ap, [{"severity": "critical", "kind": "cve", "title": "OpenSSH 8.1: 35 CVE leads"}]
    )
    wifi = [a for a in plan.build(st)["actions"] if a["playbook"] == "cloud-managed-wifi"]
    assert len(wifi) == 1 and sorted(wifi[0]["device_ids"]) == sorted([ids["Wi-Fi"], ap])
    assert "(2 devices)" in plan.render_title(wifi[0], str)


def test_accepting_risk_raises_score_and_is_keyed_stably(home):
    st = Store(home / "inventory.db")
    ids = seed(st)
    before = plan.score(st)["score"]
    st.accept_risk(ids["Wi-Fi"], "cve:OpenSSH 8.1", "ISP-owned; replacing next month")
    assert plan.score(st)["score"] > before
    st.replace_findings(
        ids["Wi-Fi"],
        [{"severity": "critical", "kind": "cve", "title": "OpenSSH 8.1: 36 CVE leads"}],
    )
    assert len(plan.build(st)["accepted"]) == 1  # new CVE count, same accepted finding


def test_grades_and_bounds(home):
    assert [plan.grade(s) for s in (100, 90, 89, 70, 60, 0)] == ["A", "A", "B", "C", "D", "F"]
    st = Store(home / "inventory.db")
    assert plan.score(st) == {"score": 100, "grade": "A"}


def test_local_playbooks_override_shipped(home):
    (home / "kb").mkdir()
    (home / "kb" / "playbooks.yaml").write_text(
        "- id: mine\n  match: {kind: [exposure], title: NFS}\n  title: My NFS fix on {device}\n"
    )
    st = Store(home / "inventory.db")
    seed(st)
    assert "mine" in {a["playbook"] for a in plan.build(st)["actions"]}


# ---- Ask HomeSentry: privacy -----------------------------------------------------------
class CaptureLLM:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def chat_json(self, messages):
        self.calls.append(messages)
        return {"answer": self.answer, "followups": ["What about [D1]?"]}

    def read_images(self, images, hint=""):
        return ""


def test_ask_never_sends_names_ips_macs_or_hostnames(home):
    st = Store(home / "inventory.db")
    ids = seed(st)
    did = st.upsert_seen("00:11:22:aa:bb:cc", "10.99.0.77", "pats-ipad.lan", "Apple, Inc.")
    st.set_identity(did, {"label": "Pat's iPad", "device_type": "tablet"}, "user", 1.0, True)
    st.add_events(
        [
            {
                "kind": "new_device",
                "severity": "medium",
                "device_id": did,
                "title": "New device joined the network",
                "detail": "first seen at 10.99.0.77",
            }
        ]
    )
    llm = CaptureLLM(f"**Fix** [D{ids['NAS']}] first. [D{did}] is fine.")
    ans = agent.ask(st, llm, "Is Pat's iPad (10.99.0.77, 00:11:22:aa:bb:cc) safe? And the NAS?")
    wire = json.dumps(llm.calls)
    for secret in (
        "Pat's",
        "10.99.0.77",
        "00:11:22:aa:bb:cc",
        "pats-ipad",
        "10.99.0.220",
        "10.99.0.20",
        "Laptop",
    ):
        assert secret not in wire, secret
    assert f"[D{did}]" in wire and f"[D{ids['NAS']}]" in wire
    html = str(agent.render(ans["answer"], agent.names_for(st)))
    assert f'href="/device/{did}">Pat&#x27;s iPad</a>' in html and "<b>Fix</b>" in html


def test_render_escapes_and_ignores_unknown_handles():
    out = str(agent.render("<script>x</script> [D999]\n- item", {1: "<b>evil</b>"}))
    assert "<script>" not in out and "[D999]" in out and "<li>item</li>" in out
    assert "&lt;b&gt;evil" in str(agent.render("[D1]", {1: "<b>evil</b>"}))


# ---- map --------------------------------------------------------------------------------
def test_map_shows_hidden_network_and_escapes(home):
    st = Store(home / "inventory.db")
    ids = seed(st)
    st.add_evidence(ids["Wi-Fi"], "tailscale", "nat_for", "Pat's <MacBook> (macos)")
    m = netmap.model(st)
    wifi = next(n for n in m["nodes"] if n["id"] == ids["Wi-Fi"])
    assert wifi["hidden"] == ["Pat's <MacBook>"] and wifi["worst"] == "critical"
    assert m["gateway"]["id"] == ids["Gateway"]
    svg = str(netmap.svg(m))
    assert "hidden network" in svg and "&lt;MacBook&gt;" in svg and "<MacBook>" not in svg
    assert svg.count('href="/device/') == len(m["nodes"]) + 1


def test_label_fit_matches_measured_font_widths():
    # widths measured in Chromium (bold 13px): Docsis-Gateway 102px, DIRECTV HR34/700 119px
    assert netmap._fit("Docsis-Gateway", 108, 13, bold=True) == "Docsis-Gateway"
    assert netmap._fit("DIRECTV HR34/700", 108, 13, bold=True).endswith("…")
    assert netmap._fit("DIRECTV HR34/700", 130, 13, bold=True) == "DIRECTV HR34/700"
    assert netmap._fit("<b>x</b>" * 9, 60, 11).startswith("&lt;b&gt;")


# ---- notify -------------------------------------------------------------------------------
def test_notify_off_by_default_and_threshold(home, monkeypatch, tmp_path):
    st = Store(home / "inventory.db")
    ids = seed(st)
    evs = [
        {"kind": "new_device", "severity": "medium", "device_id": ids["NAS"], "title": "New"},
        {"kind": "port_closed", "severity": "info", "device_id": ids["NAS"], "title": "Closed"},
    ]
    conf = notify.conf_path()  # conftest points config_dir() at a temp dir
    conf.parent.mkdir(parents=True)
    assert notify.send(st, evs, log=lambda m: None) == 0  # not configured: nothing sent
    conf.write_text("NOTIFY_URL=https://ntfy.example/topic\nNOTIFY_TOKEN=t0k\n")
    os.chmod(conf, 0o644)
    assert notify.send(st, evs, log=lambda m: None) == 0  # world-readable token: refuse
    os.chmod(conf, 0o600)
    sent = []

    class R:
        def raise_for_status(self):
            pass

    n = notify.send(
        st, evs, log=lambda m: None, poster=lambda url, **kw: sent.append((url, kw)) or R()
    )
    assert n == 1 and sent[0][0] == "https://ntfy.example/topic"
    body = sent[0][1]["content"].decode()
    assert "nas: New" in body and "Closed" not in body
    assert "NAS" not in body  # labels stay home unless NOTIFY_NAMES=1
    conf.write_text("NOTIFY_URL=https://ntfy.example/topic\nNOTIFY_NAMES=1\n")
    notify.send(st, evs, log=lambda m: None, poster=lambda url, **kw: sent.append((url, kw)) or R())
    assert "NAS: New" in sent[-1][1]["content"].decode()
    assert sent[0][1]["headers"]["Authorization"] == "Bearer t0k"
    assert "Authorization" not in sent[-1][1]["headers"]

    def boom(url, **kw):
        raise OSError("down")

    assert notify.send(st, evs, log=lambda m: None, poster=boom) == 0  # never raises


def test_tests_can_never_reach_the_owners_real_secrets():
    from pathlib import Path

    from homesentry import config_dir, data_dir, gateway, outside

    real = Path.home() / ".config" / "homesentry"
    for p in (config_dir(), gateway.env_path(), outside.conf_path(), notify.conf_path()):
        assert real not in (p, *p.parents), p
    assert Path.home() / ".local/share/homesentry" not in (data_dir(), *data_dir().parents)
    assert gateway.load_credentials() is None and outside.load_conf() is None


# ---- doctor ---------------------------------------------------------------------------------
def test_doctor_reports_and_fixes_data_dir_mode(home):
    os.chmod(home, 0o755)
    st = Store(home / "inventory.db")

    class P:
        stdout = "active\n"

    rows = {r["check"]: r for r in doctor.checks(st, runner=lambda *a, **k: P())}
    assert rows["data dir"]["status"] == "ok"  # data_dir() tightened it to 700
    assert (home.stat().st_mode & 0o777) == 0o700
    assert rows["unit homesentry.service"]["status"] == "ok"
    assert rows["last scan"]["status"] == "warn"


# ---- web --------------------------------------------------------------------------------------
def test_web_v2_pages_accept_flow_ask_and_health(home):
    from fastapi.testclient import TestClient

    from homesentry.web.app import create_app

    st = Store(home / "inventory.db")
    ids = seed(st)
    llm = CaptureLLM(f"Start with [D{ids['NAS']}].")
    c = TestClient(create_app(st, llm))
    for path in (
        "/",
        "/plan",
        "/map",
        "/timeline",
        "/timeline?only=good",
        "/ask",
        "/report",
        "/guides",
        f"/device/{ids['NAS']}",
    ):
        assert c.get(path).status_code == 200, path
    assert c.get("/healthz").status_code == 503  # never scanned
    st.record_scan(time.time(), {"hosts": 5})
    assert c.get("/healthz").json()["ok"] is True

    s0 = plan.score(st)["score"]
    key = next(a["key"] for a in plan.build(st)["actions"] if a["playbook"] == "cloud-managed-wifi")
    c.post("/plan/accept", data={"key": key, "note": "ISP gear, going back"})
    assert plan.score(st)["score"] > s0
    page = c.get("/plan").text
    assert "Accepted risks" in page and "ISP gear, going back" in page

    r = c.post("/ask", data={"q": "what first?"}, follow_redirects=True)
    assert r.status_code == 200 and f'href="/device/{ids["NAS"]}">NAS</a>' in r.text
    assert "What about" in r.text  # follow-up suggestion rendered (handle resolved locally)
    dev = c.get(f"/device/{ids['NAS']}").text
    assert "Explain" in dev and "/ask?q=" in dev
