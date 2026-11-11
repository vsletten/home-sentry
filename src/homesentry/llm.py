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
# Two roles: a reasoning model (no vision needed) and a cheap vision model that only reads photos.
DEFAULT_MODEL = "glm-5.3"  # HOMESENTRY_MODEL
DEFAULT_VISION_MODEL = "glm-5.3-flash"  # HOMESENTRY_VISION_MODEL; must have 'vision' capability
# Reasoning depth for the wizard: "low" measured ~2s/turn on glm-5.3 with the same verdicts
# as full thinking. HOMESENTRY_THINK = low|medium|high|true|false|"" ("" = model default).
DEFAULT_THINK = "low"

READER_PROMPT = """You are reading photos for a home-network device inventory. Transcribe \
everything legible that helps identify the device: brand, product name, model number, \
FCC ID, IC ID, hardware/firmware/software versions, UPC/barcode digits, and any on-screen \
text (settings or About screens, admin web pages). If there is no label, describe the \
device briefly (form factor, ports, logos, LEDs). Write [serial] instead of any serial \
number, MAC address, account number or password. Mark unreadable parts as [unreadable]. \
Plain text, terse lines, no commentary."""


class LLM(Protocol):
    def chat_json(self, messages: list[dict[str, Any]]) -> dict[str, Any]: ...

    def read_images(self, images: list[Path], hint: str = "") -> str: ...


class OllamaClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        vision_model: str | None = None,
        timeout: float = 240,
    ):
        self.base = (base_url or os.environ.get("HOMESENTRY_LLM_BASE", DEFAULT_BASE)).rstrip("/")
        self.key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        self.model = model or os.environ.get("HOMESENTRY_MODEL", DEFAULT_MODEL)
        self.vision_model = vision_model or os.environ.get(
            "HOMESENTRY_VISION_MODEL", DEFAULT_VISION_MODEL
        )
        self.think = _parse_think(os.environ.get("HOMESENTRY_THINK", DEFAULT_THINK))
        self.timeout = timeout

    def _chat(
        self, model: str, messages: list[dict[str, Any]], json_mode: bool, think: Any = None
    ) -> str:
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
        if json_mode:
            body["format"] = "json"
        if think is not None:
            body["think"] = think
        url = f"{self.base}/api/chat"
        r = httpx.post(url, json=body, headers=headers, timeout=self.timeout)
        if r.status_code == 400 and "think" in body:  # model doesn't take that think level
            body.pop("think")
            r = httpx.post(url, json=body, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["message"]["content"]

    def chat_json(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Reasoning turn. Text only: photos arrive pre-transcribed by read_images()."""
        return parse_json_reply(self._chat(self.model, messages, json_mode=True, think=self.think))

    def read_images(self, images: list[Path], hint: str = "") -> str:
        msg = {
            "role": "user",
            "content": READER_PROMPT + (f"\nOwner's note: {hint}" if hint else ""),
            "images": [encode_image(p) for p in images],
        }
        return self._chat(self.vision_model, [msg], json_mode=False).strip()


def _parse_think(v: str) -> Any:
    v = v.strip().lower()
    if v == "":
        return None
    return {"true": True, "false": False}.get(v, v)


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
