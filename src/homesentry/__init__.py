"""HomeSentry: local-first home network security prototype."""

import os
from pathlib import Path

__version__ = "0.1.0"


def data_dir() -> Path:
    """Where private, local-only state lives (inventory DB, photos, learned KB)."""
    d = Path(os.environ.get("HOMESENTRY_HOME", Path.home() / ".local/share/homesentry"))
    d.mkdir(parents=True, exist_ok=True)
    return d
