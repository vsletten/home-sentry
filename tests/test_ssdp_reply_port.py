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
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in s.opts
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


def test_out_of_range_port_is_rejected(monkeypatch):
    monkeypatch.setenv("HOMESENTRY_SSDP_PORT", "70000")
    with pytest.raises(ValueError):
        discover.ssdp_reply_port()
