"""Remote sensors: a probe from another machine folds into the inventory like a local scan.

All addresses/MACs synthetic. The scenario mirrors a real house: a wired LAN the appliance
scans itself, and a Wi-Fi router (two MACs, one box) NATting a network only a sensor sees.
"""

from __future__ import annotations

import os

import pytest

from homesentry import netmap, scan, sensors, watch
from homesentry.store import Store

LAN, WIFI = "10.99.0.0/24", "172.31.9.0/24"
ROUTER_LAN_MAC, ROUTER_WIFI_MAC = "e4:d1:24:00:10:9f", "e4:d1:24:00:10:90"
SENSOR_WIRED, SENSOR_WIFI = "1c:f6:4c:00:00:01", "ca:00:00:00:00:08"


def probe_json(**over):
    p = {
        "probe_version": 2,
        "host": {"hostname": "test-mini"},
        "interfaces": [
            {"iface": "en0", "local_ip": "10.99.0.152", "cidr": LAN, "mac": SENSOR_WIRED},
            {"iface": "en1", "local_ip": "172.31.9.8", "cidr": WIFI, "mac": SENSOR_WIFI},
        ],
        "errors": {},
        "networks": [
            {
                "iface": "en1",
                "local_ip": "172.31.9.8",
                "cidr": WIFI,
                "gateway": "172.31.9.254",
                "mac": SENSOR_WIFI,
                "counts": {"arp": 4, "mdns": 1, "ssdp": 0, "ports": 2},
                "hosts": {
                    "172.31.9.8": {"mac": SENSOR_WIFI, "sightings": []},
                    "172.31.9.44": {
                        "mac": "b8:27:eb:00:00:44",
                        "ptr": None,
                        "sightings": [
                            [
                                "ports",
                                "open_port",
                                "22/tcp ssh OpenSSH 7.9p1 Raspbian 10+deb10u1 protocol 2.0",
                            ],
                            ["tailscale", "name", "should-be-dropped"],
                        ],
                    },
                    "172.31.9.26": {
                        "mac": "ca:00:00:00:00:26",
                        "sightings": [
                            ["mdns", "service", "_airplay._tcp"],
                            ["mdns", "name", "B222FD990C56@den"],
                            ["mdns", "txt:_raop._tcp", '"am=AppleTV14,1" "md=0,1,2"'],
                            ["ports", "open_port", "53/tcp domain dnsmasq 2.83"],
                        ],
                    },
                    "172.31.9.254": {"mac": ROUTER_WIFI_MAC, "sightings": []},
                },
            }
        ],
    }
    p.update(over)
    return p


@pytest.fixture
def house(tmp_path):
    st = Store(tmp_path / "inv.db")
    r = st.upsert_seen(ROUTER_LAN_MAC, "10.99.0.49", None, "Mojo Networks", network=LAN)
    st.set_identity(r, {"device_type": "router", "label": "Wi-Fi router"}, "auto", 0.6)
    m = st.upsert_seen(SENSOR_WIRED, "10.99.0.152", None, "Apple", network=LAN)
    st.set_identity(m, {"device_type": "computer", "label": "test-mini"}, "auto", 0.6)
    return st, r, m


def apply(st, probe):
    own = sensors.sensor_macs(probe)
    return [
        scan._apply_network(st, n, {}, [], lambda m: None, sensor_macs=own)
        for n in sensors.networks_from_probe(probe, "test-mini")
    ]


def test_probe_to_networks_drops_the_sensors_tailscale_view():
    (net,) = sensors.networks_from_probe(probe_json(), "test-mini")
    assert net["ctx"]["cidr"] == WIFI and net["via"] == "test-mini"
    assert net["svc"]["172.31.9.44"][0][0] == "ports"
    assert not any(s[0] == "tailscale" for ss in net["svc"].values() for s in ss)
    assert all(s[0] == "mdns" for ss in net["mdns"].values() for s in ss)
    p = probe_json()
    p["networks"][0]["counts"]["ports"] = None
    assert sensors.networks_from_probe(p, "x")[0]["svc"] is None  # not scanned != all closed


def test_same_box_and_apple_ids():
    assert sensors.same_box(ROUTER_LAN_MAC, ROUTER_WIFI_MAC)
    assert not sensors.same_box(ROUTER_LAN_MAC, "e4:d1:24:00:40:00")  # far apart
    assert not sensors.same_box(ROUTER_LAN_MAC, "00:11:22:00:10:90")  # other vendor
    assert not sensors.same_box("ca:00:00:00:00:01", "ca:00:00:00:00:02")  # random MACs
    ids = sensors.apple_ids(
        [
            ("mdns", "name", "AE542F427B5C@Test MacBook"),
            ("mdns", "txt:_airplay._tcp", '"acl=0" "deviceid=5E:72:46:67:27:86"'),
            ("ports", "open_port", "AE542F427B5C@nope"),
        ]
    )
    assert ids == {"AE542F427B5C", "5E7246672786"}


def test_sensor_network_lands_with_aliases_identity_and_threats(house):
    st, router, mini = house
    (summary,) = apply(st, probe_json())
    assert summary["hosts"] == 2  # the sensor's own Wi-Fi and the router's inner side aliased
    devs = {d["ip"]: d for d in st.devices()}
    assert "172.31.9.8" not in devs and "172.31.9.254" not in devs
    ev = {(e["key"], e["value"]) for e in st.evidence(router)}
    assert ("routes_network", WIFI) in ev
    assert ("also_at", f"172.31.9.8 on {WIFI}") in {
        (e["key"], e["value"]) for e in st.evidence(mini)
    }
    tv = devs["172.31.9.26"]
    assert (tv["make"], tv["device_type"], tv["model"]) == (
        "Apple",
        "streaming",
        "Apple TV 4K (3rd gen)",
    )
    assert tv["network"] == WIFI
    seen = {(e["source"], e["key"], e["value"]) for e in st.evidence(devs["172.31.9.44"]["id"])}
    assert ("sensor", "seen_by", "test-mini") in seen
    assert not any(s == "tailscale" for s, _, _ in seen)
    # threats: EOL OS is real; Apple TV's bundled dnsmasq is capped (Apple patches it silently)
    from homesentry import threat

    cycles = {"debian": [{"cycle": "10", "eol": "2024-06-30"}]}
    pi = threat.assess_device(
        st.device(devs["172.31.9.44"]["id"]), st.evidence(devs["172.31.9.44"]["id"]), {}, {}, [],
        cycles,
    )  # fmt: skip
    assert any(f["kind"] == "eol" and f["severity"] == "high" for f in pi)
    crit = "cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*"
    nvd = {
        ("thekelleys", "dnsmasq"): [
            {
                "id": "CVE-2099-0001",
                "descriptions": [{"lang": "en", "value": "x"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": crit,
                                        "versionEndExcluding": "2.90",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        ]
    }
    fs = threat.assess_device(st.device(tv["id"]), st.evidence(tv["id"]), {}, nvd, [])
    cves = [f for f in fs if f["kind"] == "cve"]
    assert cves and all(f["severity"] == "medium" for f in cves), cves


def test_same_mac_on_two_networks_is_one_device(house):
    st, _, _ = house
    lap = st.upsert_seen("1c:f6:4c:00:00:77", "10.99.0.28", None, "Apple", network=LAN)
    st.add_evidence(lap, "mdns", "name", "AE542F427B5C@Test MacBook")
    p = probe_json()
    p["networks"][0]["hosts"]["172.31.9.28"] = {
        "mac": "ca:00:00:00:00:28",
        "sightings": [["mdns", "name", "AE542F427B5C@Test MacBook"]],
    }
    apply(st, p)
    assert "172.31.9.28" not in {d["ip"] for d in st.devices()}
    assert any(e["key"] == "also_at" for e in st.evidence(lap))


def test_presence_is_judged_per_scanned_network(house, monkeypatch):
    st, router, _ = house
    apply(st, probe_json())
    pi = next(d for d in st.devices() if d["ip"] == "172.31.9.44")
    import time

    later = time.time() + 5
    st.mark_presence(later, networks=[LAN])  # the sensor slept: its network isn't judged
    assert st.device(pi["id"])["online"] in (None, 1)
    assert st.device(router)["online"] == 0  # LAN was scanned and the router didn't answer
    st.mark_presence(later, networks=[LAN, WIFI])
    assert st.device(pi["id"])["online"] == 0


def test_first_sight_of_a_network_is_one_event_not_a_device_storm(house):
    st, _, _ = house
    before = watch.snapshot(st)
    apply(st, probe_json())
    st.mark_presence(0, networks=[WIFI])
    evs = watch.diff(before, watch.snapshot(st), ports_scanned=False)
    kinds = [e["kind"] for e in evs]
    assert kinds.count("network_new") == 1 and "new_device" not in kinds
    assert "(2 devices)" in next(e["title"] for e in evs if e["kind"] == "network_new")
    # the next device on that (now known) network is news again
    before = watch.snapshot(st)
    p = probe_json()
    p["networks"][0]["hosts"]["172.31.9.99"] = {"mac": "00:11:22:00:00:99", "sightings": []}
    apply(st, p)
    st.mark_presence(0, networks=[WIFI])
    assert [e["kind"] for e in watch.diff(before, watch.snapshot(st), False)] == ["new_device"]


def test_map_draws_the_sensor_network_inside_its_router(house):
    st, router, _ = house
    apply(st, probe_json())
    m = netmap.model(st)
    r = next(n for n in m["nodes"] if n["id"] == router)
    assert r["routed"] == WIFI and {c["ip"] for c in r["inside"]} == {"172.31.9.44", "172.31.9.26"}
    assert not any(n["ip"].startswith("172.31.9.") for n in m["nodes"])  # not duplicated
    svg = str(netmap.svg(m))
    assert WIFI in svg and "/device/" in svg


def test_conf_requires_600_and_quotes_remote_command(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_CONFIG", str(tmp_path))
    f = tmp_path / "sensors.env"
    f.write_text("SENSORS=mini-a, mini-b\nSENSOR_SSH_AGENT=/run/agent\n")
    os.chmod(f, 0o644)
    with pytest.raises(PermissionError):
        sensors.load_conf()
    os.chmod(f, 0o600)
    conf = sensors.load_conf()
    assert conf["hosts"] == ["mini-a", "mini-b"] and conf["agent"] == "/run/agent"
    cmd = sensors.remote_command(conf, ["10.99.0.0/24"], ports=True)
    assert cmd.endswith("homesentry probe --json --skip 10.99.0.0/24 --ports")


def test_unreachable_sensor_is_reported_not_fatal(monkeypatch):
    import subprocess

    class R:
        stdout, stderr, returncode = "", "ssh: connect to host x port 22: Host is down\n", 255

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R())
    got = sensors.run_one("x", {"agent": None, "path": "/bin"}, [], False)
    assert got == {"host": "x", "error": "ssh: connect to host x port 22: Host is down"}


def test_late_recognized_twin_folds_the_duplicate_and_hostname_merges_apple(house):
    st, _, _ = house
    lap = st.upsert_seen("1c:f6:4c:00:00:77", "10.99.0.28", None, "Apple", network=LAN)
    st.set_identity(lap, {"make": "Apple", "device_type": "computer"}, "auto", 0.6)
    st.add_evidence(lap, "mdns", "host", "Test-MacBook.local")
    p = probe_json()
    # first pass: the laptop's Wi-Fi said nothing on mDNS -> a separate unknown record
    p["networks"][0]["hosts"]["172.31.9.28"] = {"mac": "ca:00:00:00:00:28", "sightings": []}
    apply(st, p)
    dup = next(d for d in st.devices() if d["ip"] == "172.31.9.28")
    # next pass it announces its host name: same Mac -> duplicate retired, twin noted
    p["networks"][0]["hosts"]["172.31.9.28"]["sightings"] = [["mdns", "host", "Test-MacBook.local"]]
    apply(st, p)
    assert "172.31.9.28" not in {d["ip"] for d in st.devices()}
    assert st.device(dup["id"])["retired"]
    assert any(e["key"] == "also_at" for e in st.evidence(lap))
    # generic host names never merge
    from homesentry import sensors as s_

    assert not s_.mdns_hosts(
        [("mdns", "host", "Android.local"), ("mdns", "host", "iPhone-2.local")]
    )
