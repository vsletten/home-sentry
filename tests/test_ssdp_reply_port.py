"""SSDP searches leave from a fixed port so a stateful firewall can admit the unicast replies."""

import socket

import pytest

from homesentry import discover


class FakeSocket:
    def __init__(self, busy=()):
        self.busy, self.bound, self.opts, self.sent = set(busy), None, [], []

    def settimeout(self, _t):
        pass

    def setsockopt(self, *a):
        self.opts.append(a)

    def bind(self, addr):
        if addr[1] in self.busy:
            raise OSError(98, "Address already in use")
        self.bound = (addr[0], addr[1] or 54321)

    def getsockname(self):
        return self.bound

    def sendto(self, data, addr):
        self.sent.append(addr)

    def recvfrom(self, _n):
        raise TimeoutError

    def close(self):
        pass


@pytest.fixture
def fake(monkeypatch):
    holder = {}

    def make(*_a, **_k):
        holder["s"] = FakeSocket(holder.get("busy", ()))
        return holder["s"]

    monkeypatch.setattr(discover.socket, "socket", make)
    return holder


def test_search_leaves_from_the_default_fixed_port(fake, monkeypatch):
    monkeypatch.delenv("HOMESENTRY_SSDP_PORT", raising=False)
    assert discover.ssdp(seconds=0.01) == {}
    s = fake["s"]
    assert s.bound == ("", 1901)
    assert not any(o[:2] == (socket.SOL_SOCKET, socket.SO_REUSEADDR) for o in s.opts)
    assert s.sent == [("239.255.255.250", 1900)]


def test_env_overrides_port_and_zero_means_ephemeral(fake, monkeypatch):
    monkeypatch.setenv("HOMESENTRY_SSDP_PORT", "41900")
    discover.ssdp(seconds=0.01)
    assert fake["s"].bound == ("", 41900)
    monkeypatch.setenv("HOMESENTRY_SSDP_PORT", "0")
    discover.ssdp(seconds=0.01)
    assert fake["s"].bound == ("", 54321)


def test_busy_port_falls_back_to_ephemeral_with_a_warning(fake, monkeypatch, capsys):
    monkeypatch.delenv("HOMESENTRY_SSDP_PORT", raising=False)
    fake["busy"] = {1901}
    discover.ssdp(seconds=0.01)
    assert fake["s"].bound == ("", 54321)
    assert "reply port 1901 unavailable" in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["70000", "-1", "abc", "19.01"])
def test_invalid_port_setting_warns_and_uses_default(bad, monkeypatch, capsys):
    monkeypatch.setenv("HOMESENTRY_SSDP_PORT", bad)
    assert discover.ssdp_reply_port() == 1901
    assert "ignoring invalid HOMESENTRY_SSDP_PORT" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("responder", "location", "ok"),
    [
        ("10.1.10.185", "http://10.1.10.185:49152/desc.xml", True),
        ("10.1.10.185", "https://10.1.10.185/desc.xml", True),
        ("10.1.10.185", "http://127.0.0.1:8000/admin", False),  # forged: points at this host
        ("10.1.10.185", "http://10.1.10.241/desc.xml", False),  # not the responder
        ("10.1.10.185", "http://localhost/desc.xml", False),  # names never match an IP
        ("10.1.10.185", "file:///etc/passwd", False),
        ("10.1.10.185", "ftp://10.1.10.185/x", False),
        ("8.8.8.8", "http://8.8.8.8/desc.xml", False),  # not a private LAN address
        ("169.254.1.2", "http://169.254.1.2/desc.xml", False),  # link-local
        ("10.1.10.185", "not a url", False),
    ],
)
def test_location_must_be_the_responding_lan_device(responder, location, ok):
    assert discover.safe_ssdp_location(responder, location) is ok


def test_forged_location_is_never_fetched(fake, monkeypatch):
    replies = [
        (
            b"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:9119/api\r\nSERVER: x\r\n\r\n",
            ("10.1.10.185", 1900),
        ),
    ]

    class Replying(FakeSocket):
        def recvfrom(self, _n):
            if replies:
                return replies.pop()
            raise TimeoutError

    monkeypatch.setattr(discover.socket, "socket", lambda *_a, **_k: Replying())
    fetched = []
    monkeypatch.setattr(discover.httpx.Client, "get", lambda self, url: fetched.append(url))
    out = discover.ssdp(seconds=0.05)
    assert fetched == []
    assert out == {"10.1.10.185": [("ssdp", "server", "x")]}
