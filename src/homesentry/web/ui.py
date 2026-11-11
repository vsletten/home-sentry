"""Shared Jinja environment for the web UI and offline renders (report)."""

from __future__ import annotations

import time
from functools import cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__

HERE = Path(__file__).parent
ICONS = {
    "router": "📡",
    "modem": "📶",
    "gateway": "📡",
    "set-top-box": "📺",
    "streaming": "📺",
    "tv": "🖥️",
    "media": "🎞️",
    "nas": "🗄️",
    "camera": "📷",
    "smart-home": "🏠",
    "alarm_hub": "🚨",
    "speaker": "🔊",
    "printer": "🖨️",
    "computer": "💻",
    "phone": "📱",
    "tablet": "📱",
    "appliance": "🧊",
    "network": "🔀",
    "apple": "🍎",
    "game-console": "🎮",
}


def icon(t: str | None) -> str:
    return ICONS.get(t or "", "❔")


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    if s < 0:
        return "just now"
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s // n}{unit} ago"
    return "just now"


@cache
def env() -> Environment:
    e = Environment(
        loader=FileSystemLoader(HERE / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    e.globals.update(icon=icon, ago=ago, version=__version__)
    return e
