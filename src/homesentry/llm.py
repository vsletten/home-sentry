"""Minimal Ollama chat client (Ollama Cloud by default; a local Ollama works unchanged)."""

from __future__ import annotations

import base64
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Protocol

import httpx

DEFAULT_BASE = "https://ollama.com"
DEFAULT_MODEL = "kimi-k3"  # vision + tools on Ollama Cloud; override with HOMESENTRY_MODEL


class LLM(Protocol):
    def chat_json(self, messages: list[dict[str, Any]]) -> dict[str, Any]: ...


class OllamaClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 240,
    ):
        self.base = (base_url or os.environ.get("HOMESENTRY_LLM_BASE", DEFAULT_BASE)).rstrip("/")
        self.key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        self.model = model or os.environ.get("HOMESENTRY_MODEL", DEFAULT_MODEL)
        self.timeout = timeout

    def chat_json(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        body = {"model": self.model, "messages": messages, "stream": False, "format": "json"}
        r = httpx.post(f"{self.base}/api/chat", json=body, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return parse_json_reply(r.json()["message"]["content"])


def parse_json_reply(text: str) -> dict[str, Any]:
    """Tolerate code fences / chatter around the JSON object."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise ValueError(f"model did not return JSON: {text[:200]}") from None
        return json.loads(m.group(0))


def encode_image(path: Path, max_px: int = 1600) -> str:
    """Base64 JPEG, downscaled so phone photos stay cheap. Falls back to raw bytes."""
    raw = path.read_bytes()
    try:
        from PIL import Image, ImageOps

        img = ImageOps.exif_transpose(Image.open(io.BytesIO(raw))).convert("RGB")
        img.thumbnail((max_px, max_px))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=85)
        raw = buf.getvalue()
    except Exception:  # noqa: BLE001 - unknown format (e.g. HEIC); let the model try
        pass
    return base64.b64encode(raw).decode()
