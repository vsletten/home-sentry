"""Ask HomeSentry: a household-level security analyst over the whole inventory.

Privacy design (the same line as the wizard, applied to the whole house):
  - Devices are sent as opaque handles ([D7]) with type/make/model/firmware, NIC vendor and
    findings. Never names/labels, hostnames, IPs, MACs or serials.
  - The owner's question is rewritten before it leaves: any device name or address they
    typed becomes its handle; leftover addresses are redacted.
  - The reply refers to devices by handle; handles are turned back into names locally when
    rendering. The model never learns what anything in the house is called.
"""

from __future__ import annotations

import ast
import datetime as dt
import html
import json
import re
import time
from typing import Any

from markupsafe import Markup

from . import plan
from .llm import LLM
from .store import Store

SYSTEM = """You are the security analyst inside HomeSentry, a local-first home network \
security appliance. You answer the owner's questions about THEIR house using the snapshot \
below: devices, findings, recent changes, the ranked action plan and the posture score.

Rules:
- Refer to devices ONLY by their handle in square brackets, exactly as given, e.g. [D7]. \
Never invent handles. The owner sees them as real device names.
- Ground every claim in the snapshot. If the snapshot can't answer, say so and say what \
would (a port scan, a label photo in the wizard, the gateway status page).
- CVE findings come from service banners: they are leads to confirm, not proven breaches. \
Say so when it matters. Severity "critical" means CISA lists a matching CVE as actively \
exploited somewhere, not that this device was attacked.
- Be concrete: what it means, how worried to be, the exact next step. Prefer the plan's \
actions and their order. Short paragraphs, "- " bullets, **bold** for the key point.
- Direct and a little wry. No filler, no generic security lectures.
- Never ask for passwords. Never claim you changed anything: HomeSentry is read-only.

Reply with ONE JSON object and nothing else:
{"answer": "your reply", "followups": ["up to 3 short follow-up questions"]}"""

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b", re.I)
IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
HANDLE = re.compile(r"\[D(\d+)\]")


def scrub(text: str | None) -> str:
    t = text or ""
    for rx, rep in ((MAC, "[mac]"), (EMAIL, "[email]"), (IPV6, "[ipv6]"), (IPV4, "[ip]")):
        t = rx.sub(rep, t)
    return t


def ref(device_id: int) -> str:
    return f"[D{device_id}]"


def _role(evidence: list[dict[str, Any]], d: dict[str, Any]) -> str:
    if d.get("device_type") == "gateway":
        return "gateway (routes the LAN)"
    hidden = [e for e in evidence if (e["source"], e["key"]) in {("tailscale", "nat_for")}]
    natted = hidden or any(e["source"] == "probe" and e["key"] == "nat" for e in evidence)
    if natted:
        return "runs its own NAT network (clients behind it are hidden)"
    return "on the LAN"


def snapshot(store: Store, days: int = 14) -> dict[str, Any]:
    """Everything the analyst may know, already stripped of identifying details."""
    p = plan.build(store)
    acc = store.accepted()
    devices = []
    for d in store.devices():
        ev = store.evidence(d["id"])
        fs = [
            {
                "severity": f["severity"],
                "kind": f["kind"],
                "title": scrub(f["title"]),
                "why": scrub((f["detail"] or "")[:300]),
                "accepted_risk": (d["id"], plan.finding_key(f)) in acc,
            }
            for f in store.findings(d["id"])
            if f["severity"] != "info" or f["kind"] == "outside"
        ]
        devices.append(
            {
                "ref": ref(d["id"]),
                "type": d["device_type"],
                "make": d["make"],
                "model": d["model"],
                "firmware": d["firmware"],
                "nic_vendor": d["oui_vendor"],
                "confirmed_by_owner": bool(d["confirmed"]),
                "online": None if d.get("online") is None else bool(d["online"]),
                "role": _role(ev, d),
                "findings": fs,
            }
        )
    since = time.time() - days * 86400
    events = [
        {
            "when": dt.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M"),
            "severity": e["severity"],
            "what": scrub(e["title"]),
            "device": ref(e["device_id"]) if e["device_id"] else None,
        }
        for e in store.events(limit=30, since=since)
    ]
    actions = [
        {
            "rank": i + 1,
            "action": plan.render_title(a, ref),
            "score_gain": a["gain"],
            "effort_minutes": a["effort_min"],
            "who": a["who"],
            "worst_severity": a["worst"],
            "why": scrub(a["why"][:240]),
        }
        for i, a in enumerate(p["actions"][:10])
    ]
    last = store.last_scan()
    return {
        "today": dt.date.today().isoformat(),
        "posture": {
            "score": p["score"],
            "grade": p["grade"],
            "after_top_actions": p["projected"],
            "open_findings": p["counts"],
            "accepted_risks": len(p["accepted"]),
            "unidentified_devices": [ref(i) for i in p["unknown"]],
        },
        "last_scan": dt.datetime.fromtimestamp(last["finished"]).strftime("%Y-%m-%d %H:%M")
        if last
        else None,
        "devices": devices,
        "recent_changes": events,
        "action_plan": actions,
    }


def localize_question(store: Store, q: str) -> str:
    """Owner typed names/addresses -> handles, so they never leave the box."""
    out = q
    devs = sorted(store.devices(), key=lambda d: -len(d["label"] or ""))
    for d in devs:
        for token in (d["ip"], d["mac"], d["label"], d["hostname"]):
            if token and len(token) >= 3:
                out = re.sub(re.escape(token), ref(d["id"]), out, flags=re.I)
    return scrub(out)


def _unwrap(v: Any) -> Any:
    """Undo a model double-encoding a value: '"text"' -> 'text', "['a', 'b']" -> [...]."""
    for _ in range(2):
        if not isinstance(v, str):
            return v
        s = v.strip()
        if not (s[:1] in '"[{' and s[-1:] in '"]}') or len(s) < 2:
            return v
        try:
            v = json.loads(s)
        except ValueError:
            try:
                v = ast.literal_eval(s)  # literals only: never evaluates code
            except (ValueError, SyntaxError):
                return v
    return v


def normalize_reply(reply: Any) -> dict[str, Any]:
    """Tolerate the shapes real models return: double-encoded strings, stringified lists,
    {"answer": {"text": ...}}, or the reply under a different key."""
    reply = _unwrap(reply)
    if isinstance(reply, str):
        reply = {"answer": reply}
    if not isinstance(reply, dict):
        reply = {}
    ans = _unwrap(reply.get("answer"))
    if isinstance(ans, dict):
        ans = ans.get("text") or ans.get("answer") or ans.get("content")
    if isinstance(ans, list):
        ans = "\n\n".join(map(str, ans))
    if not (isinstance(ans, str) and ans.strip()):
        others = [v for k, v in reply.items() if k != "followups" and isinstance(v, str)]
        ans = max(others, key=len, default="")
    ans = str(ans).strip().replace("\\n", "\n")
    fups = _unwrap(reply.get("followups"))
    if isinstance(fups, str):
        fups = [fups] if fups.strip() else []
    if not isinstance(fups, list):
        fups = []
    return {"answer": ans, "followups": [str(x).strip() for x in fups if str(x).strip()][:3]}


def ask(store: Store, llm: LLM, question: str) -> dict[str, Any]:
    q = localize_question(store, question.strip())[:2000]
    history = store.ask_turns(limit=8)
    store.add_ask("user", q)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": "Household snapshot:\n" + json.dumps(snapshot(store))},
        {"role": "assistant", "content": '{"answer": "Snapshot received.", "followups": []}'},
    ]
    for t in history:
        messages.append({"role": t["role"], "content": t["content"]})
    messages.append({"role": "user", "content": q})
    answer = normalize_reply(llm.chat_json(messages))
    if not answer["answer"]:  # models occasionally return an empty body: one retry
        answer = normalize_reply(llm.chat_json(messages))
    answer["answer"] = answer["answer"] or "(no answer: try rephrasing)"
    store.add_ask("assistant", json.dumps(answer))
    return answer


# ---- rendering (local only) ------------------------------------------------------
def render(text: str, names: dict[int, str]) -> Markup:
    """Tiny, safe renderer: escape everything, then handles -> device links, **bold**,
    '- ' bullets and paragraphs."""

    def link(m: re.Match[str]) -> str:
        did = int(m.group(1))
        if did not in names:
            return html.escape(m.group(0))
        return f'<a class="dref" href="/device/{did}">{html.escape(names[did])}</a>'

    out, bullets = [], []

    def flush():
        if bullets:
            out.append("<ul>" + "".join(f"<li>{b}</li>" for b in bullets) + "</ul>")
            bullets.clear()

    for line in (text or "").splitlines():
        s = html.escape(line.strip())
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"\[D(\d+)\]", link, s)
        if not s:
            flush()
            continue
        if s.startswith(("- ", "* ", "• ")):
            bullets.append(s[2:])
        else:
            flush()
            out.append(f"<p>{s}</p>")
    flush()
    return Markup("".join(out))


def names_for(store: Store) -> dict[int, str]:
    return {
        d["id"]: d["label"] or d["model"] or d["make"] or d["ip"] or f"device {d['id']}"
        for d in store.devices(include_retired=True)
    }


def explain_prompt(device_id: int, finding_title: str) -> str:
    return (
        f'Explain the finding "{finding_title}" on {ref(device_id)}: what it means for me, '
        "how worried I should be, and exactly what to do about it."
    )
