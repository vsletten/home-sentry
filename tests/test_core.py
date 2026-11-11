import json

import yaml

from homesentry import discover, identify, kb, wizard
from homesentry.llm import parse_json_reply
from homesentry.store import Store

UPNP_XML = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
<friendlyName>DIRECTV HR34/700</friendlyName><manufacturer>DIRECTV</manufacturer>
<modelDescription>DIRECTV HR34/700 Receiver</modelDescription><modelName>HR34</modelName>
<modelNumber>700</modelNumber><serialNumber>SECRET123</serialNumber></device></root>"""

AVAHI = (
    "=;enp12s0;IPv4;Studio\\032Mac;_companion-link._tcp;local;studio-mac.local;10.99.0.152;"
    '49153;"rpBA=XX"\n'
    "=;enp12s0;IPv4;Studio\\032Mac;_device-info._tcp;local;studio-mac.local;10.99.0.152;0;"
    '"model=Macmini9,1"\n'
    "=;docker0;IPv4;ignored;_ssh._tcp;local;x.local;172.17.0.2;22;\n"
)

NMAP_XML = """<nmaprun><host><address addr="10.99.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd"/>
<script id="http-title" output="Technicolor CGA4131COM"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>"""


def ev(*triples):
    return [{"source": s, "key": k, "value": v} for s, k, v in triples]


def test_parse_oui_and_random_mac():
    table = discover.parse_oui("# c\n603D26 Technicolor CH USA\nBAD\n")
    assert table == {"603D26": "Technicolor CH USA"}
    assert discover.is_random_mac("da:00:11:22:33:44")
    assert not discover.is_random_mac("60:3d:26:00:00:01")


def test_parse_neigh_filters_failed_and_v6():
    js = json.dumps(
        [
            {"dst": "10.99.0.1", "lladdr": "60:3d:26:00:00:01", "state": ["REACHABLE"]},
            {"dst": "10.99.0.9", "state": ["FAILED"]},
            {"dst": "fe80::1", "lladdr": "aa:bb:cc:dd:ee:ff", "state": ["STALE"]},
        ]
    )
    assert discover.parse_neigh(js) == {"10.99.0.1": "60:3d:26:00:00:01"}


def test_parse_upnp_never_keeps_serial():
    s = discover.parse_upnp_description(UPNP_XML)
    assert ("ssdp", "modelName", "HR34") in s
    assert not any("SECRET" in v for _, _, v in s)


def test_parse_avahi_unescapes_and_filters_iface():
    r = discover.parse_avahi(AVAHI, "enp12s0")
    assert list(r) == ["10.99.0.152"]
    assert ("mdns", "name", "Studio Mac") in r["10.99.0.152"]


def test_parse_nmap_xml_open_ports_only():
    r = discover.parse_nmap_xml(NMAP_XML)
    assert ("nmap", "open_port", "80/tcp http lighttpd") in r["10.99.0.1"]
    assert ("nmap", "http_title", "Technicolor CGA4131COM") in r["10.99.0.1"]
    assert len(r["10.99.0.1"]) == 2


def test_guess_from_upnp():
    g = identify.guess(ev(*discover.parse_upnp_description(UPNP_XML)), "Pace plc")
    assert (g["make"], g["model"], g["device_type"]) == ("DIRECTV", "HR34", "set-top-box")
    assert g["confidence"] >= 0.6


def test_guess_apple_from_mdns():
    sights = discover.parse_avahi(AVAHI, "enp12s0")["10.99.0.152"]
    g = identify.guess(ev(*sights), "Apple, Inc.")
    assert g["make"] == "Apple" and g["model"] == "Macmini9,1" and g["device_type"] == "computer"


def test_guess_gateway_and_oui_cleanup():
    g = identify.guess([], "Technicolor CH USA Inc.", is_gateway=True)
    assert g["device_type"] == "router" and g["make"] == "Technicolor CH USA"


def test_kb_learn_then_match(tmp_path):
    evidence = ev(
        ("ssdp", "modelName", "HR34"),
        ("ssdp", "modelName", "MediaRenderer"),
        ("arp", "mac_randomized", "yes"),
    )
    path = kb.learn(
        {"make": "DIRECTV", "model": "HR34", "device_type": "set-top-box", "firmware": "0x1234"},
        evidence,
        out_dir=tmp_path,
    )
    entry = yaml.safe_load(path.read_text())
    assert entry["match"] == {"ssdp_model": ["HR34"]}  # generic model name dropped
    assert entry["firmware_seen"] == ["0x1234"]
    hit = kb.match(kb.load([tmp_path]), kb.facts_from_evidence(ev(("ssdp", "modelName", "hr34"))))
    assert hit and hit["model"] == "HR34"
    g = identify.guess(ev(("ssdp", "modelName", "HR34")), None, kb_entries=kb.load([tmp_path]))
    assert g["make"] == "DIRECTV" and g["confidence"] >= 0.9


def test_store_confirmed_identity_is_sticky(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("aa:bb:cc:00:00:01", "10.0.0.5", None, "Acme")
    assert st.set_identity(did, {"make": "Acme"}, "auto", 0.3)
    assert st.set_identity(did, {"make": "Rescan"}, "auto", 0.2)  # auto refreshes auto
    st.set_identity(did, {"make": "Real"}, "user", 1.0, confirmed=True)
    assert not st.set_identity(did, {"make": "Auto"}, "auto", 0.99)
    assert st.device(did)["make"] == "Real"
    assert st.upsert_seen("aa:bb:cc:00:00:01", "10.0.0.6", None, None) == did


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def chat_json(self, messages):
        self.calls.append(messages)
        return self.reply

    def read_images(self, images, hint=""):
        return "unused"


def test_wizard_turn_redacts_and_applies(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_HOME", str(tmp_path))
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("60:3d:26:00:00:01", "10.99.0.1", None, "Technicolor CH USA")
    st.add_evidence(did, "ssdp", "modelName", "CGA4131COM")
    llm = FakeLLM(
        {
            "message": "That's a Comcast gateway.",
            "identity": {
                "device_type": "gateway",
                "make": "Technicolor",
                "model": "null",
                "firmware": None,
            },
            "label_fields": {"model_number": "CGA4131COM"},
            "confidence": 0.8,
            "next": {"kind": "photo", "ask": "Shoot the label"},
        }
    )
    reply = wizard.run_turn(st, llm, did, "it's the xfinity box")
    sent = json.dumps(llm.calls[0])
    assert "60:3d:26" not in sent and "10.99.0.1" not in sent  # no MAC/IP leaves the box
    assert "CGA4131COM" in sent
    assert reply["next"]["kind"] == "photo"
    d = st.device(did)
    assert (d["make"], d["model"], d["id_source"]) == ("Technicolor", "CGA4131COM", "wizard")
    assert wizard.latest_proposal(st, did)["confidence"] == 0.8


def test_parse_json_reply_tolerates_fences():
    assert parse_json_reply('```json\n{"a": 1}\n```') == {"a": 1}


def test_samba_fake_mac_model_is_not_apple():
    sights = ev(
        ("mdns", "txt:_device-info._tcp", '"model=MacSamba"'), ("mdns", "name", "TNAS-A057")
    )
    g = identify.guess(sights, "Shenzhen Something")
    assert g["make"] == "TerraMaster" and g["device_type"] == "nas"
    assert "mdns_model" not in kb.facts_from_evidence(sights)


def test_auto_rescan_replaces_older_auto_guess(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("aa:bb:cc:00:00:02", "10.0.0.7", None, None)
    st.set_identity(did, {"make": "Apple"}, "auto", 0.57)
    assert st.set_identity(did, {"make": "TerraMaster"}, "auto", 0.4)
    st.set_identity(did, {"make": "Wiz"}, "wizard", 0.7)
    assert not st.set_identity(did, {"make": "Auto"}, "auto", 0.5)


def test_printer_from_ports():
    g = identify.guess(
        ev(
            ("nmap", "open_port", "9100/tcp jetdirect"),
            ("nmap", "open_port", "443/tcp http Canon printer web interface"),
        ),
        "Canon",
    )
    assert g["device_type"] == "printer" and g["make"] == "Canon"


def test_ollama_client_sends_think_and_falls_back(monkeypatch):
    import httpx

    from homesentry.llm import OllamaClient

    bodies = []

    def fake_post(url, json, headers, timeout):
        bodies.append(dict(json))
        if "think" in json:
            return httpx.Response(
                400, json={"error": "think not supported"}, request=httpx.Request("POST", url)
            )
        return httpx.Response(
            200, json={"message": {"content": '{"ok": 1}'}}, request=httpx.Request("POST", url)
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.delenv("HOMESENTRY_THINK", raising=False)
    c = OllamaClient(api_key="k")
    assert c.model == "glm-5.3" and c.vision_model == "glm-5.3-flash"
    assert c.chat_json([{"role": "user", "content": "hi"}]) == {"ok": 1}
    assert bodies[0]["think"] == "low" and "think" not in bodies[1]
    assert "think" not in bodies[0] or bodies[0]["model"] == "glm-5.3"


def test_kb_learns_only_model_specific_rules(tmp_path):
    hr34 = ev(
        ("ssdp", "modelName", "HR34"),
        ("ssdp", "modelDescription", "DIRECTV Plus HD DVR"),
        ("nmap", "http_title", "Did not follow redirect to http://10.9.9.20:8181"),
    )
    path = kb.learn({"make": "DIRECTV", "model": "HR34"}, hr34, out_dir=tmp_path)
    text = path.read_text()
    assert "10.9.9.20" not in text and "Plus HD DVR" not in text
    other_box = ev(
        ("ssdp", "modelName", "MediaRenderer"), ("ssdp", "modelDescription", "DIRECTV Plus HD DVR")
    )
    assert kb.match(kb.load([tmp_path]), kb.facts_from_evidence(other_box)) is None


def test_stale_rule_types_in_old_kb_files_are_inert(tmp_path):
    (tmp_path / "x.yaml").write_text(
        "make: X\nmodel: Y\nmatch:\n  ssdp_description: [Shared Family Text]\n"
    )
    facts = {"ssdp_description": {"Shared Family Text"}}
    assert kb.match(kb.load([tmp_path]), facts) is None
