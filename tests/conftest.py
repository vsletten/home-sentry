"""Every test runs fenced off from the owner's real data and real credentials.

HomeSentry reads live secrets (gateway admin password, probe SSH alias, notify token) from
config_dir(). A test that reached them would log in to real hardware: so both dirs are
pointed at a fresh temp dir for every test, unconditionally.
"""

import pytest


@pytest.fixture(autouse=True)
def _fence(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp("fence")
    monkeypatch.setenv("HOMESENTRY_CONFIG", str(root / "config"))
    monkeypatch.setenv("HOMESENTRY_HOME", str(root / "data"))
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
