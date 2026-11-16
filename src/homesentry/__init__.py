"""HomeSentry: local-first home network security prototype."""

import os
import sys
from pathlib import Path

__version__ = "0.5.0"


def _default_data() -> Path:
    if sys.platform == "darwin":  # where Mac apps keep their data (and Time Machine backs it up)
        return Path.home() / "Library" / "Application Support" / "HomeSentry"
    if sys.platform.startswith("win"):
        return (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "HomeSentry"
        )
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "homesentry"


def _default_config() -> Path:
    if sys.platform == "darwin" or sys.platform.startswith("win"):
        return _default_data() / "config"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "homesentry"


def data_dir() -> Path:
    """Where private, local-only state lives (inventory DB, photos, learned KB)."""
    d = Path(os.environ.get("HOMESENTRY_HOME") or _default_data())
    d.mkdir(parents=True, exist_ok=True)
    if d.stat().st_mode & 0o077:  # inventory, photos and evidence are private to the owner
        d.chmod(0o700)
    return d


def config_dir() -> Path:
    """Where the owner's secrets live (gateway/probe/notify/LLM env files). Never created
    here: absent files simply mean 'not configured'. HOMESENTRY_CONFIG overrides (tests)."""
    return Path(os.environ.get("HOMESENTRY_CONFIG") or _default_config())


def load_env_file() -> list[str]:
    """Load <config>/env (OLLAMA_API_KEY, HOMESENTRY_*) into the environment if present and
    private (mode 600). Real environment variables win. systemd passes this file itself; the
    desktop app and launchd don't, so the CLI reads it. Returns the keys it set."""
    p = config_dir() / "env"
    if not p.is_file() or (os.name == "posix" and p.stat().st_mode & 0o077):
        return []
    set_ = []
    for line in p.read_text().splitlines():
        k, sep, v = line.strip().partition("=")
        k = k.strip()
        if sep and k and not k.startswith("#") and k not in os.environ:
            os.environ[k] = v.strip().strip("'\"")
            set_.append(k)
    return set_
