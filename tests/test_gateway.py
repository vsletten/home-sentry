"""Gateway reader tests. Synthetic HTML shaped like the RDK-B (*.jst) UI; no real values."""

import os

import httpx
import pytest

from homesentry import gateway, threat, wizard
from homesentry.store import Store


def field(label, value):
    return (
        f'<div class="form-row"><span class="readonlyLabel">{label}:</span> '
        f'<span class="value">\n {value}</span></div>'
    )


HARDWARE = (
    field("Model", "CGA0000COM")
    + field("Vendor", "Technicolor")
    + field("Hardware Revision", "2.1")
    + field("Serial Number", "999999999")
)
SOFTWARE = field("eMTA &amp; DOCSIS Software Version", "Prod_1.0") + field(
    "Software Image Name", "CGA0000COM_1.2p3_PROD"
)
STATUS = (
    field("Wireless Network (Wi-Fi 2.4 GHz)", "Inactive")
    + field("Security", "WPA2-PSK (AES)")
    + field("Wireless Network (Wi-Fi 5 GHz)", "Active")
    + field("Security", "WEP")
)


def client_row(name, ip, mac, online=True, reserved=False):
    h = "host-name" if online else "offline-device-host-name"
    r = "dhcp-or-reserved" if online else "offline-device-dhcp-reserve"
    return (
        f'<tr><td headers="{h}"><a class="label device-name private"><u>{name}</u></a>'
        f'<div class="device-info"><dl><dd><b>IPV4 Address</b><br/></dd>{ip}'
        f"<dd><b>MAC Address</b><br/></dd>{mac}<dd><b>Comments</b><br/></dd></dl></div></td>"
        f'<td headers="{r}">{"Reserved IP" if reserved else "DHCP"}</td></tr>'
    )


CLIENTS = (
    "<table>"
    + client_row("Kids-PC", "10.9.9.33", "AA:BB:CC:00:00:01")
    + client_row("aa:bb:cc:00:00:02", "10.9.9.40", "AA:BB:CC:00:00:02")
    + client_row("XboxOne", "10.9.9.73", "AA:BB:CC:00:00:03", online=False, reserved=True)
    + "</table>"
)


def radios(checked):
    return "".join(
        f'<input type="radio" name="firewall_level" value="{v}" id="x" '
        f"{'checked' if v == checked else ''} />"
        for v in ("high", "medium", "low")
    )


def pf(enabled, active):
    return (
        '$("#pf_switch").radioswitch({\n id: "forwarding-switch",\n state: '
        f'{"true" if enabled else "false"} ? "on" : "off"\n}});'
        "<table><tr><td headers='service-name' class='port_data'>ollama</td>"
        "<td headers='service-type'>TCP/UDP</td><td headers='start-port'>11434</td>"
        "<td headers='end-port'>11434</td><td headers='server-ip'>10.9.9.220</td>"
        f'<td headers=\'active\'><input type="checkbox" id="PortActive_1" '
        f"{'checked' if active else ''} /></td>"
        "<td class='delete'><a href=\"actionHandler/ajax_port_forwarding.jst?del=1\">x</a>"
        "</td></tr></table>"
    )


PAGES = {
    "hardware.jst": HARDWARE,
    "software.jst": SOFTWARE,
    "connection_status.jst": STATUS,
    "connected_devices_computers.jst": CLIENTS,
    "firewall_settings_ipv4.jst": radios("low"),
    "firewall_settings_ipv6.jst": '<input type="radio" name="firewall_level" value="Default"'
    ' id="firewall_level_default" checked />',
    "port_forwarding.jst": pf(False, False),
    "dmz.jst": "var jsEnableDMZ = false;",
    "device_discovery.jst": "var jsEnableUPnP = true;\nvar jsEnableZero = false;",
    "remote_management.jst": "var HTTPS = false;",
}
LOGIN_PAGE = (
    '<form action="check.jst" method="post"><input name="username"/>'
    '<input type="password" name="password"/></form>'
)


def fake_gateway(pages=PAGES, password="pw", log=None):
    log = [] if log is None else log

    def handler(req: httpx.Request):
        path = req.url.path.lstrip("/")
        log.append((req.method, path, str(req.url.query)))
        if req.method == "POST":
            assert path == "check.jst", f"POST to {path}"
            body = req.content.decode()
            ok = "password=" + password in body
            return httpx.Response(
                302, headers={"location": "at_a_glance.jst" if ok else "index.jst?status=fail"}
            )
        if path == "":
            return httpx.Response(200, text=LOGIN_PAGE)
        if path == "home_loggedout.jst":
            return httpx.Response(200, text="bye")
        assert path in pages, f"reader requested non-allowlisted page {path}"
        return httpx.Response(200, text=pages[path])

    client = httpx.Client(base_url="https://gw", transport=httpx.MockTransport(handler))
    return gateway.RdkbReader("gw", client=client), log


def test_reader_parses_everything_and_skips_identifiers():
    reader, log = fake_gateway()
    cfg = reader.read("Admin", "pw")
    assert (cfg["model"], cfg["vendor"], cfg["hw_rev"]) == ("CGA0000COM", "Technicolor", "2.1")
    assert cfg["firmware"] == "CGA0000COM_1.2p3_PROD" and cfg["docsis"] == "Prod_1.0"
    assert "999999999" not in repr(cfg)  # serial never collected
    assert cfg["wifi"] == [
        {"band": "2.4 GHz", "active": False, "security": "WPA2-PSK (AES)"},
        {"band": "5 GHz", "active": True, "security": "WEP"},
    ]
    assert cfg["firewall_v4"] == "low" and cfg["firewall_v6"] == "Default"
    assert cfg["port_forwarding"] == {
        "enabled": False,
        "rules": [
            {
                "name": "ollama",
                "proto": "TCP/UDP",
                "start": "11434",
                "end": "11434",
                "target": "10.9.9.220",
                "active": False,
            }
        ],
    }
    assert (cfg["dmz"], cfg["upnp"], cfg["zeroconf"], cfg["remote_mgmt_https"]) == (
        False,
        True,
        False,
        False,
    )
    by_mac = {c["mac"]: c for c in cfg["clients"]}
    assert by_mac["aa:bb:cc:00:00:01"]["hostname"] == "Kids-PC"
    assert by_mac["aa:bb:cc:00:00:02"]["hostname"] is None  # MAC-as-name => unnamed
    x = by_mac["aa:bb:cc:00:00:03"]
    assert (x["online"], x["reserved"], x["ip"]) == (False, True, "10.9.9.73")


def test_reader_only_touches_allowlist_and_never_the_delete_link():
    reader, log = fake_gateway()
    reader.read("admin", "pw")
    posts = [p for m, p, _ in log if m == "POST"]
    gets = [p for m, p, _ in log if m == "GET"]
    assert posts == ["check.jst"]
    assert set(gets) <= set(gateway.PAGES) | {"", "home_loggedout.jst"}
    assert not any("actionHandler" in p or "del=" in q for _, p, q in log)
    assert gets[-1] == "home_loggedout.jst"  # always logs out
    with pytest.raises(gateway.GatewayError):
        reader._get("actionHandler/ajax_port_forwarding.jst?del=1")
    with pytest.raises(gateway.GatewayError):
        reader._get("restore_reboot.jst")


def test_login_failure_is_one_attempt_and_no_password_in_error():
    reader, log = fake_gateway(password="right")
    with pytest.raises(gateway.GatewayError) as e:
        reader.read("admin", "wrong-secret")
    assert "wrong-secret" not in str(e.value)
    assert sum(1 for m, *_ in log if m == "POST") == 1


def test_credentials_file_must_be_private(tmp_path):
    p = tmp_path / "gateway.env"
    p.write_text("GATEWAY_USER=admin\nGATEWAY_PASS='s3cret'\n")
    os.chmod(p, 0o644)
    with pytest.raises(gateway.GatewayError):
        gateway.load_credentials(p)
    os.chmod(p, 0o600)
    assert gateway.load_credentials(p) == ("admin", "s3cret")
    assert gateway.load_credentials(tmp_path / "missing") is None


def test_config_findings():
    base = gateway.parse_all(PAGES)
    titles = {f["title"]: f["severity"] for f in gateway.config_findings(base)}
    assert titles["Dormant port forward 'ollama'"] == "low"
    assert titles["UPnP is enabled"] == "medium"
    assert titles["Gateway IPv4 firewall at Minimum (Low)"] == "low"
    assert titles["Gateway Wi-Fi 5 GHz uses weak security (WEP)"] == "high"
    assert "DMZ host enabled" not in titles
    live = dict(
        base,
        port_forwarding=gateway.parse_port_forwarding(pf(True, True)),
        dmz=True,
        firewall_v6="None",
    )
    t2 = {f["title"]: f["severity"] for f in gateway.config_findings(live)}
    assert t2["Port forward 'ollama' is live"] == "critical"
    assert t2["DMZ host enabled"] == "critical"
    assert t2["Gateway IPv6 firewall is permissive"] == "high"


def test_gateway_config_flows_into_threats_but_not_to_the_llm(tmp_path):
    import json

    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("aa:bb:cc:00:00:10", "10.9.9.1", None, "Technicolor")
    cfg = {k: v for k, v in gateway.parse_all(PAGES).items() if k != "clients"}
    st.add_evidence(did, "gateway_cfg", "config", json.dumps(cfg))
    st.add_evidence(did, "gateway", "model", "CGA0000COM")
    fs = threat.assess_device(st.device(did), st.evidence(did), {}, {}, [])
    assert any(f["kind"] == "config" and "ollama" in f["title"] for f in fs)
    brief = wizard.evidence_brief(st.device(did), st.evidence(did))
    assert "CGA0000COM" in brief and "10.9.9.220" not in brief and "gateway_cfg" not in brief


def test_upsert_known_marks_offline_and_never_bumps_last_seen(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_known("aa:bb:cc:00:00:20", "10.9.9.73", "XboxOne", "Microsoft", "10.9.9.0/24")
    d = st.device(did)
    assert d["last_seen"] is None and d["hostname"] == "XboxOne"
    seen = st.upsert_seen("aa:bb:cc:00:00:20", "10.9.9.73", None, None)
    assert seen == did and st.device(did)["last_seen"]
    assert st.upsert_known("aa:bb:cc:00:00:20", None, None, None, None) == did


def test_hostname_hints():
    from homesentry import identify

    def g(name):
        return identify.guess([{"source": "gateway", "key": "dhcp_name", "value": name}], None)

    assert (g("DIRECTV-H25-ABCDEF12")["make"], g("DIRECTV-H25-ABCDEF12")["model"]) == (
        "DIRECTV",
        "H25",
    )
    assert g("XboxOne")["device_type"] == "game-console"
    assert g("HP-Z4-G4-Workstation")["model"] == "Z4-G4"
