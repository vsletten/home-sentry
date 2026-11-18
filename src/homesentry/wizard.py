"""AI-guided identification wizard: network evidence + owner's words + photos -> identity.

One turn = owner says/shows something -> model returns a structured guess plus the ONE
most useful next question or photo. Owner confirms when it's right; confirmation feeds
the KB so the next device like it is recognized automatically.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import kb as kblib
from .llm import LLM
from .store import Store

SYSTEM = """You are the device-identification assistant inside HomeSentry, a local-first \
home network security tool. Your job: pin down exactly what a device is (type, make, \
model, model/hardware number, firmware version) so it can be matched against \
vulnerability and end-of-life data. You get the network evidence we collected plus \
whatever the owner tells or shows you: photos of rating labels, barcodes/UPC, the box, \
the device itself, settings/About screens, router admin pages.

How to work:
- Reason from ALL evidence. Network self-reports (UPnP, mDNS) are usually honest; MAC \
vendor (OUI) often names the chip/module maker, not the brand.
- Ask for ONE thing at a time: the single most valuable next photo or answer. Best \
targets: rating label (model no., FCC ID, HW version), Settings > About screen \
(firmware), the admin web page status screen, the retail box/UPC.
- Firmware version matters most for security. Once make/model are solid, go after it.
- Never ask for passwords. Do not repeat serial numbers, MACs or account numbers back.
- If the photo is unreadable or conflicts with the network evidence, say so plainly.
- Keep messages short, direct, a little wry. No filler.

Reply with ONE JSON object, no prose outside it:
{
  "message": "what you say to the owner (1-3 sentences)",
  "identity": {"device_type": "router|modem|gateway|set-top-box|streaming|tv|nas|camera|\
smart-home|speaker|printer|computer|phone|tablet|appliance|network|other|null",
               "make": "string|null", "model": "string|null", "firmware": "string|null"},
  "label_fields": {"model_number": null, "fcc_id": null, "hw_version": null, "upc": null},
  "confidence": 0.0,
  "next": {"kind": "photo|question|none", "ask": "the one thing you want next"}
}"""

PRIVATE_KEYS = {"mac_randomized"}  # kept local but summarized, never raw


def evidence_brief(device: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    """What the model sees about the device. No MAC, IP, or serials: OUI vendor only."""
    lines = []
    if device.get("oui_vendor"):
        lines.append(f"MAC vendor (OUI): {device['oui_vendor']}")
    if any(e["key"] == "mac_randomized" for e in evidence):
        lines.append("MAC is randomized/private (likely phone, tablet or laptop)")
    if device.get("hostname"):
        lines.append(f"DNS name: {device['hostname']}")
    for e in evidence:
        if e["key"] in PRIVATE_KEYS or e["source"] in ("auto", "gateway_cfg", "dns"):
            continue
        lines.append(f"{e['source']}.{e['key']}: {e['value']}")
    cur = {k: device.get(k) for k in ("device_type", "make", "model", "firmware", "label")}
    lines.append(f"Current best guess: {json.dumps(cur)} (confidence {device.get('confidence')})")
    return "\n".join(lines[:80]) or "No network evidence (manually added device)."


def run_turn(
    store: Store, llm: LLM, device_id: int, text: str, images: list[Path] | None = None
) -> dict[str, Any]:
    device = store.device(device_id)
    if device is None:
        raise KeyError(device_id)
    images = images or []
    said = text
    if images:  # vision model reads, reasoning model thinks; transcript persists in history
        transcript = llm.read_images(images, hint=text)
        said = (f"{text}\n\n" if text else "") + f"[Photo transcript]\n{transcript}"
    store.add_turn(device_id, "user", said or "(empty)", [str(p) for p in images])

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {
            "role": "user",
            "content": "Network evidence:\n" + evidence_brief(device, store.evidence(device_id)),
        },
    ]
    for t in store.turns(device_id)[-13:]:  # conversation incl. this turn, text only
        messages.append({"role": t["role"], "content": t["content"]})

    reply = llm.chat_json(messages)
    store.add_turn(device_id, "assistant", json.dumps(reply))

    ident = reply.get("identity") or {}
    conf = float(reply.get("confidence") or 0)
    fields = {k: v for k, v in ident.items() if v and v != "null"}
    lf = reply.get("label_fields") or {}
    if lf.get("model_number") and not fields.get("model"):
        fields["model"] = lf["model_number"]
    store.set_identity(device_id, fields, "wizard", conf)
    return reply


def confirm(store: Store, device_id: int, fields: dict[str, Any]) -> Path | None:
    """Owner says: this is right. Lock it in and teach the KB."""
    store.set_identity(device_id, fields, "user", 1.0, confirmed=True)
    device = store.device(device_id) or {}
    return kblib.learn(device, store.evidence(device_id))


def latest_proposal(store: Store, device_id: int) -> dict[str, Any] | None:
    for t in reversed(store.turns(device_id)):
        if t["role"] == "assistant":
            try:
                return json.loads(t["content"])
            except json.JSONDecodeError:
                return None
    return None
