"""HomeSentry: local-first home network security prototype."""

import os
from pathlib import Path

__version__ = "0.3.0"


def data_dir() -> Path:
    """Where private, local-only state lives (inventory DB, photos, learned KB)."""
    d = Path(os.environ.get("HOMESENTRY_HOME", Path.home() / ".local/share/homesentry"))
    d.mkdir(parents=True, exist_ok=True)
    if d.stat().st_mode & 0o077:  # inventory, photos and evidence are private to the owner
        d.chmod(0o700)
    return d


def config_dir() -> Path:
    """Where the owner's secrets live (gateway/probe/notify/LLM env files). Never created
    here: absent files simply mean 'not configured'. HOMESENTRY_CONFIG overrides (tests)."""
    return Path(os.environ.get("HOMESENTRY_CONFIG", Path.home() / ".config/homesentry"))
