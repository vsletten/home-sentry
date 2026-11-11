import json
import subprocess
import sys

from homesentry import outside, threat
from homesentry.store import Store


def test_remote_script_targets_ssh_client_and_never_echoes_it(tmp_path):
    """Run the real REMOTE script locally against a listening socket on 127.0.0.1."""
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    dead = closed.getsockname()[1]
    closed.close()
    env = {"SSH_CLIENT": "127.0.0.1 50000 22", "PATH": "/usr/bin:/bin"}
    r = subprocess.run(
        [sys.executable, "-", str(port), str(dead)],
        input=outside.REMOTE,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    srv.close()
    res = json.loads(r.stdout)
    assert res["open"] == [port] and res["scanned"] == 2 and res["family"] == "ipv4"
    assert "127.0.0.1" not in r.stdout


def test_run_probe_builds_ssh_command_without_any_ip():
    seen = {}

    def runner(cmd, input, **kw):
        seen["cmd"], seen["input"] = cmd, input
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"open": [], "scanned": 2, "seconds": 0.1, "family": "ipv4"}\n',
            stderr="",
        )

    conf = {"PROBE_SSH": "ci-vps", "PROBE_SSH_AGENT": "/run/agent"}
    res = outside.run_probe(conf, [22, 443], runner=runner)
    assert seen["cmd"][:2] == ["ssh", "-o"] and "IdentityAgent=/run/agent" in seen["cmd"]
    assert seen["cmd"][-3:] == ["-", "22", "443"]
    assert not any(c.count(".") == 3 and c.replace(".", "").isdigit() for c in seen["cmd"])
    assert res["probe"] == "ci-vps" and "at" in res


def test_outside_findings_severity():
    fs = outside.findings(
        {"open": [11434, 8080], "scanned": 1000, "probe": "ci-vps", "family": "ipv4", "at": "now"}
    )
    sev = {f["title"]: f["severity"] for f in fs}
    assert sev["TCP 11434 reachable from the internet"] == "critical"
    assert sev["TCP 8080 reachable from the internet"] == "high"
    clean = outside.findings({"open": [], "scanned": 1000, "probe": "ci-vps", "at": "now"})
    assert clean[0]["severity"] == "info" and "0 of 1000" in clean[0]["title"]


def test_top_ports_includes_always_list():
    ports = outside.top_ports(50)
    assert set(outside.ALWAYS) <= set(ports) and ports == sorted(ports)


def test_outside_result_flows_into_gateway_findings(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_seen("aa:bb:cc:00:00:31", "10.9.9.1", None, None)
    st.add_evidence(
        did,
        "outside",
        "result",
        json.dumps({"open": [7547], "scanned": 10, "probe": "p", "family": "ipv4", "at": "t"}),
    )
    fs = threat.assess_device(st.device(did) or {}, st.evidence(did), {}, {}, [])
    assert any(f["kind"] == "outside" and "7547" in f["title"] for f in fs)


def test_retire_hides_blocks_gateway_resurrection_and_unretires_on_sighting(tmp_path):
    st = Store(tmp_path / "t.db")
    did = st.upsert_known("aa:bb:cc:00:00:40", "10.9.9.81", "cluster-01", None, "10.9.9.0/24")
    st.replace_findings(did, [{"severity": "high", "kind": "eol", "title": "x"}])
    st.retire(did)
    assert all(d["id"] != did for d in st.devices())
    assert st.is_retired("aa:bb:cc:00:00:40") and st.findings(did) == []
    assert any(d["id"] == did for d in st.devices(include_retired=True))
    # seen live on the wire again => restored, with a note why
    assert st.upsert_seen("aa:bb:cc:00:00:40", "10.9.9.81", None, None) == did
    assert not st.is_retired("aa:bb:cc:00:00:40")
    assert any(e["key"] == "reappeared_after_retire" for e in st.evidence(did))
