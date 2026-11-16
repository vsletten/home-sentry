"""v6 desktop core: platform data paths, env file, session auth, in-process watch, and the
macOS Local Network permission check."""

from __future__ import annotations

import errno
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

import homesentry
from homesentry import netinfo, watch
from homesentry.store import Store
from homesentry.web import app as webapp


def test_platform_default_paths(monkeypatch, tmp_path):
    monkeypatch.delenv("HOMESENTRY_HOME", raising=False)
    monkeypatch.delenv("HOMESENTRY_CONFIG", raising=False)
    monkeypatch.setattr(homesentry.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert homesentry._default_data() == tmp_path / "Library/Application Support/HomeSentry"
    assert homesentry._default_config() == homesentry._default_data() / "config"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert homesentry._default_data() == tmp_path / ".local/share/homesentry"
    assert homesentry._default_config() == tmp_path / ".config/homesentry"


def test_env_file_loads_only_when_private_and_never_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("HOMESENTRY_CONFIG", str(tmp_path))
    f = tmp_path / "env"
    f.write_text("HS_TEST_A=one\nHS_TEST_B='two'\n# HS_TEST_C=no\n")
    os.chmod(f, 0o644)
    assert homesentry.load_env_file() == []  # world-readable secrets file: refuse
    os.chmod(f, 0o600)
    monkeypatch.setenv("HS_TEST_A", "real")
    monkeypatch.delenv("HS_TEST_B", raising=False)
    assert homesentry.load_env_file() == ["HS_TEST_B"]
    assert os.environ["HS_TEST_A"] == "real" and os.environ["HS_TEST_B"] == "two"
    monkeypatch.delenv("HS_TEST_B")


@pytest.fixture
def desktop(monkeypatch, tmp_path):
    monkeypatch.setenv("HOMESENTRY_TOKEN", "s3cret-token")
    app = webapp.create_app(Store(tmp_path / "inv.db"))
    return TestClient(app, base_url="http://127.0.0.1:8720")


def test_desktop_mode_requires_the_session(desktop):
    assert desktop.get("/").status_code == 401
    assert desktop.get("/auth?token=wrong").status_code == 401
    r = desktop.get("/auth?token=s3cret-token", follow_redirects=False)
    assert r.status_code == 303 and "hs_session" in r.headers["set-cookie"]
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower()
    assert desktop.get("/").status_code == 200  # cookie kept by the client
    api = desktop.get("/api/events", cookies={}, headers={"Authorization": "Bearer s3cret-token"})
    assert api.status_code == 200 and api.json()["events"] == []


def test_desktop_mode_rejects_foreign_host_dns_rebinding(desktop):
    desktop.get("/auth?token=s3cret-token")
    assert desktop.get("/", headers={"host": "evil.example:8720"}).status_code == 403


def test_appliance_mode_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.delenv("HOMESENTRY_TOKEN", raising=False)
    c = TestClient(webapp.create_app(Store(tmp_path / "inv.db")))
    assert c.get("/").status_code == 200


def test_events_api_filters_by_severity_and_since(desktop, tmp_path):
    desktop.get("/auth?token=s3cret-token")
    st = desktop.app.state.store
    t0 = time.time()
    st.add_events(
        [
            {"kind": "new_device", "severity": "medium", "title": "New device joined"},
            {"kind": "device_offline", "severity": "info", "title": "Went offline"},
        ]
    )
    got = desktop.get(f"/api/events?since={t0 - 1}").json()
    assert [e["title"] for e in got["events"]] == ["New device joined"]
    assert desktop.get(f"/api/events?since={time.time() + 10}").json()["events"] == []


def test_scheduler_ticks_and_survives_failures(monkeypatch, tmp_path):
    calls = []

    def fake(store, log=print):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        if len(calls) == 2:
            raise watch.ScanBusy("busy")

    monkeypatch.setattr(watch, "run_watch", fake)
    stop = watch.start_scheduler(Store(tmp_path / "i.db"), 0.001, 0, log=lambda m: None)
    deadline = time.time() + 3
    while len(calls) < 3 and time.time() < deadline:
        time.sleep(0.02)
    stop.set()
    assert len(calls) >= 3


def test_local_network_blocked_detection(monkeypatch):
    monkeypatch.setattr(netinfo, "platform", lambda: "darwin")
    assert netinfo.local_network_blocked("10.99.0.1", connect=lambda p: errno.EHOSTUNREACH)
    assert not netinfo.local_network_blocked("10.99.0.1", connect=lambda p: 0)
    assert not netinfo.local_network_blocked(
        "10.99.0.1", connect=lambda p: errno.ECONNREFUSED if p == 80 else errno.EHOSTUNREACH
    )
    assert not netinfo.local_network_blocked("10.99.0.1", connect=lambda p: errno.ETIMEDOUT)
    monkeypatch.setattr(netinfo, "platform", lambda: "linux")
    assert not netinfo.local_network_blocked("10.99.0.1", connect=lambda p: errno.EHOSTUNREACH)


def test_blocked_scan_keeps_inventory_online(monkeypatch, tmp_path):
    from homesentry import discover, scan

    st = Store(tmp_path / "inv.db")
    did = st.upsert_seen("00:11:22:00:00:05", "10.99.0.5", None, None, network="10.99.0.0/24")
    st.mark_presence(0)
    ctx = {"iface": "en0", "local_ip": "10.99.0.2", "cidr": "10.99.0.0/24", "gateway": "10.99.0.1"}
    monkeypatch.setattr(discover, "lan_contexts", lambda: [ctx])
    monkeypatch.setattr(discover, "tailscale_peers", lambda: {})
    monkeypatch.setattr(netinfo, "local_network_blocked", lambda gw: True)
    out = scan.run_scan(st, gateway=False, threats=False, log=lambda m: None)
    assert out["local_network_blocked"] and st.device(did)["online"] == 1


def test_launch_agent_plist_shape(tmp_path):
    import plistlib

    from homesentry import service

    pl = service.launch_agent("/Apps/hs", 30, tmp_path, None)
    assert pl["ProgramArguments"] == ["/Apps/hs", "serve", "--watch-every", "30"]
    assert pl["RunAtLoad"] and pl["KeepAlive"] == {"SuccessfulExit": False}
    assert plistlib.loads(plistlib.dumps(pl))["Label"] == "com.homesentry.agent"
    assert "--host" not in pl["ProgramArguments"]  # loopback unless asked
    assert service.launch_agent("/x", 15, tmp_path, "100.64.0.9")["ProgramArguments"][-2:] == [
        "--host",
        "100.64.0.9",
    ]


def test_ui_never_shows_a_grade_for_a_blind_or_empty_scan(monkeypatch, tmp_path):
    monkeypatch.delenv("HOMESENTRY_TOKEN", raising=False)
    st = Store(tmp_path / "inv.db")
    c = TestClient(webapp.create_app(st))
    html = c.get("/").text
    assert "No scan yet" in html
    st.record_scan(time.time(), {"local_network_blocked": True})
    html = c.get("/map").text
    assert "can&#39;t see your network" in html or "can't see your network" in html
    assert "Local Network" in html
