"""Network map: a server-rendered SVG of the house (no JS, no CDN, works on a phone).

Internet  (outside-in badge)
   │
Gateway
   ├── Network & security │ Computers & phones │ Media & storage │ Everything else
   │      node ┐
   │      ╎ hidden network behind a NAT box ╎
"""

from __future__ import annotations

import html
import json
from typing import Any

from markupsafe import Markup

from .store import Store

LANES: list[tuple[str, set[str | None]]] = [
    ("Network & security", {"router", "network", "modem", "alarm_hub", "camera"}),
    ("Computers & phones", {"computer", "phone", "tablet", "game-console", "apple"}),
    ("Media & storage", {"nas", "set-top-box", "streaming", "tv", "media", "speaker"}),
]
OTHER = "Everything else"
NODE_W, NODE_H, GAP, LANE_W = 184, 58, 12, 212
SEV = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#9c4dcc",
    "high": "var(--bad)",
    "medium": "var(--warn)",
    "low": "#8aa4d6",
    None: "var(--ok)",
}


def _t(s: Any, n: int) -> str:
    s = str(s or "")
    return html.escape(s if len(s) <= n else s[: n - 1] + "…")


def _em(c: str) -> float:
    """Advance width of one char in em, calibrated against the UI's system sans (measured
    with getComputedTextLength in Chromium: lower 0.53, CAPS 0.635, digits 0.57, narrow
    punctuation 0.27). No font metrics server-side, so err slightly wide."""
    if c in "il.,:;|!'`ıjtfr ()[]-·/":
        return 0.29
    if c in "MW@%":
        return 0.9
    if c in "mw":
        return 0.8
    if c == "…" or ord(c) > 0x2000:
        return 0.82
    if c.isupper():
        return 0.62
    if c.isdigit():
        return 0.54
    return 0.54


def _fit(s: Any, px: float, size: float, bold: bool = False) -> str:
    """Truncate to fit `px` pixels at font `size`, ellipsis included. Escaped for SVG."""
    s, k = str(s or ""), size * (1.08 if bold else 1.0)
    if sum(map(_em, s)) * k <= px:
        return html.escape(s)
    out, w = "", _em("…") * k
    for c in s:
        if w + _em(c) * k > px:
            break
        out, w = out + c, w + _em(c) * k
    return html.escape(out.rstrip() + "…")


def lane_of(device_type: str | None) -> str:
    for name, types in LANES:
        if device_type in types:
            return name
    return OTHER


def _hidden(evidence: list[dict[str, Any]]) -> list[str] | None:
    peers = [e["value"] for e in evidence if e["source"] == "tailscale" and e["key"] == "nat_for"]
    measured = any(e["source"] == "probe" and e["key"] == "nat" for e in evidence)
    if not peers and not measured:
        return None
    names = [p.rsplit(" (", 1)[0] for p in peers]
    return sorted(set(names))


def model(store: Store, icon=lambda t: "❔") -> dict[str, Any]:
    """Pure data for the map (separately testable from drawing)."""
    worst: dict[int, str] = {}
    count: dict[int, int] = {}
    for f in store.findings():
        if f["severity"] == "info":
            continue
        did = f["device_id"]
        count[did] = count.get(did, 0) + 1
        if did not in worst or SEV.index(f["severity"]) < SEV.index(worst[did]):
            worst[did] = f["severity"]
    devices = store.devices()
    gw = next((d for d in devices if d["device_type"] == "gateway"), None)
    outside = None
    if gw:
        for e in store.evidence(gw["id"]):
            if e["source"] == "outside" and e["key"] == "result":
                r = json.loads(e["value"])
                outside = {"open": len(r.get("open", [])), "scanned": r.get("scanned")}
    # networks a sensor saw behind a router we know (the router's wired twin is the same box)
    routes: dict[str, int] = {}
    evid = {d["id"]: store.evidence(d["id"]) for d in devices}
    for d in devices:
        for e in evid[d["id"]]:
            if e["source"] == "sensor" and e["key"] == "routes_network":
                routes[e["value"]] = d["id"]
    nodes = []
    for d in devices:
        if gw and d["id"] == gw["id"]:
            continue
        nodes.append(
            {
                "network": d.get("network"),
                "id": d["id"],
                "label": d["label"] or d["model"] or d["make"] or d["ip"] or "Unknown",
                "sub": " · ".join(x for x in (d["make"], d["model"]) if x)
                or (d["oui_vendor"] or ""),
                "ip": d["ip"] or "",
                "icon": icon(d["device_type"]),
                "lane": lane_of(d["device_type"]),
                "worst": worst.get(d["id"]),
                "risks": count.get(d["id"], 0),
                "offline": d.get("online") == 0 or (d["mac"] and not d["last_seen"]),
                "confirmed": bool(d["confirmed"]),
                "hidden": _hidden(evid[d["id"]]),
                "inside": [],
            }
        )
    by_id = {n["id"]: n for n in nodes}
    for n in list(nodes):
        router = routes.get(n["network"] or "")
        if router and router != n["id"] and router in by_id:
            by_id[router]["inside"].append(n)
            by_id[router]["routed"] = n["network"]
            nodes.remove(n)
    for n in nodes:
        n["inside"].sort(key=lambda c: (SEV.index(c["worst"] or "info"), c["label"]))
        if n["inside"] and n["hidden"] is None:
            n["hidden"] = []
    order = {name: i for i, (name, _) in enumerate(LANES)} | {OTHER: len(LANES)}
    nodes.sort(key=lambda n: (order[n["lane"]], SEV.index(n["worst"] or "info"), n["label"]))
    return {
        "gateway": None
        if not gw
        else {
            "id": gw["id"],
            "label": gw["label"] or "Gateway",
            "sub": " · ".join(x for x in (gw["make"], gw["model"]) if x),
            "worst": worst.get(gw["id"]),
            "risks": count.get(gw["id"], 0),
            "icon": icon("gateway"),
        },
        "outside": outside,
        "nodes": nodes,
    }


def _node(n: dict[str, Any], x: float, y: float) -> str:
    color = SEV_COLOR.get(n["worst"], "var(--ok)")
    op = ' opacity="0.45"' if n.get("offline") else ""
    tip = html.escape(
        f"{n['label']} · {n.get('sub') or ''} · {n.get('ip') or ''}"
        + (f" · {n['risks']} risk(s), worst {n['worst']}" if n.get("risks") else " · no open risks")
        + (" · offline" if n.get("offline") else "")
    )
    badge = ""
    if n.get("risks"):
        badge = (
            f'<circle cx="{x + NODE_W - 14}" cy="{y + 14}" r="10" fill="{color}"/>'
            f'<text x="{x + NODE_W - 14}" y="{y + 18}" text-anchor="middle" class="bdg">'
            f"{n['risks']}</text>"
        )
    tick = (
        f'<text x="{x + NODE_W - 12}" y="{y + NODE_H - 9}" text-anchor="end" class="ok">✓</text>'
        if n.get("confirmed")
        else ""
    )
    sub = n.get("sub") or ("offline" if n.get("offline") else "")
    return (
        f'<a href="/device/{n["id"]}"><g class="node"{op}><title>{tip}</title>'
        f'<rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" rx="11" class="box"/>'
        f'<rect x="{x}" y="{y}" width="6" height="{NODE_H}" rx="3" fill="{color}"/>'
        f'<text x="{x + 26}" y="{y + 36}" text-anchor="middle" class="ico">{n["icon"]}</text>'
        f'<text x="{x + 46}" y="{y + 25}" class="lbl">'
        f"{_fit(n['label'], NODE_W - 46 - (30 if badge else 10), 13, bold=True)}</text>"
        f'<text x="{x + 46}" y="{y + 43}" class="sub">'
        f"{_fit(sub, NODE_W - 46 - (26 if tick else 10), 11)}</text>"
        f"{badge}{tick}</g></a>"
    )


def _pocket(n: dict[str, Any], x: float, y: float) -> tuple[list[str], float]:
    """The dashed 'hidden network' box under a NAT router: its devices, if a sensor has seen
    them (each a link, colored by risk), else what we can infer (Tailscale peers behind it)."""
    hx, hy, w = x + 34, y + 8, NODE_W - 16
    inside = n.get("inside") or []
    if inside:
        title = f"🙈 {n.get('routed') or 'hidden network'} · {len(inside)}"
        rows = len(inside)
    else:
        title = "🙈 hidden network (NAT)"
        lines = [f"• {h}" for h in (n["hidden"] or [])[:4]] + ["• + its own Wi-Fi clients"]
        rows = len(lines)
    hh = 30 + 17 * rows if inside else 30 + 15 * rows
    out = [
        f'<line x1="{hx + 14}" y1="{y}" x2="{hx + 14}" y2="{hy}" class="edge dash"/>'
        f'<rect x="{hx}" y="{hy}" width="{w}" height="{hh}" rx="10" class="hidden"/>'
        f'<text x="{hx + 10}" y="{hy + 18}" class="sub b">{_fit(title, w - 18, 11, True)}</text>'
    ]
    if inside:
        for i, c in enumerate(inside):
            ry = hy + 36 + 17 * i
            color = SEV_COLOR.get(c["worst"], "var(--ok)")
            op = ' opacity="0.45"' if c.get("offline") else ""
            risk = f" · {c['risks']}" if c.get("risks") else ""
            tip = html.escape(f"{c['label']} · {c.get('sub') or ''} · {c.get('ip') or ''}")
            out.append(
                f'<a href="/device/{c["id"]}"><g{op}><title>{tip}</title>'
                f'<circle cx="{hx + 14}" cy="{ry - 4}" r="4" fill="{color}"/>'
                f'<text x="{hx + 24}" y="{ry}" class="sub">'
                f"{_fit(c['icon'] + ' ' + c['label'] + risk, w - 34, 11)}</text></g></a>"
            )
    else:
        for i, line in enumerate(lines):
            out.append(
                f'<text x="{hx + 10}" y="{hy + 36 + 15 * i}" class="sub">'
                f"{_fit(line, NODE_W - 36, 11)}</text>"
            )
    return out, hy + hh


def svg(m: dict[str, Any]) -> Markup:
    lanes = [name for name, _ in LANES] + [OTHER]
    by_lane = {name: [n for n in m["nodes"] if n["lane"] == name] for name in lanes}
    lanes = [name for name in lanes if by_lane[name]] or [OTHER]
    width = max(len(lanes) * LANE_W + 24, 2 * LANE_W)
    cx = width / 2
    parts: list[str] = []
    # internet
    o = m.get("outside")
    parts.append(
        f'<ellipse cx="{cx}" cy="38" rx="92" ry="26" class="cloud"/>'
        f'<text x="{cx}" y="43" text-anchor="middle" class="lbl">🌍 Internet</text>'
    )
    if o:
        good = o["open"] == 0
        txt = (
            f"outside-in: 0 of {o['scanned']} ports open"
            if good
            else f"outside-in: {o['open']} port(s) reachable!"
        )
        parts.append(
            f'<text x="{cx + 10}" y="86" class="{"okt" if good else "badt"}">'
            f"{'🛡️' if good else '⚠️'} {html.escape(txt)}</text>"
        )
    gw = m.get("gateway")
    gy = 104
    parts.append(f'<line x1="{cx}" y1="64" x2="{cx}" y2="{gy}" class="edge"/>')
    if gw:
        parts.append(
            _node(gw | {"ip": "", "offline": False, "confirmed": False}, cx - NODE_W / 2, gy)
        )
    else:
        parts.append(
            f'<rect x="{cx - NODE_W / 2}" y="{gy}" width="{NODE_W}" height="{NODE_H}" rx="11" '
            f'class="box"/><text x="{cx}" y="{gy + 34}" text-anchor="middle" class="lbl">'
            "Gateway (unknown)</text>"
        )
    bus_y = gy + NODE_H + 30
    lane_x = {name: 12 + i * LANE_W + (LANE_W - NODE_W) / 2 for i, name in enumerate(lanes)}
    first_c = lane_x[lanes[0]] + 10
    last_c = lane_x[lanes[-1]] + 10
    parts.append(f'<line x1="{cx}" y1="{gy + NODE_H}" x2="{cx}" y2="{bus_y}" class="edge"/>')
    parts.append(
        f'<line x1="{min(first_c, cx)}" y1="{bus_y}" x2="{max(last_c, cx)}" '
        f'y2="{bus_y}" class="edge"/>'
    )
    bottom = bus_y
    for name in lanes:
        x = lane_x[name]
        trunk = x + 10
        y = bus_y + 30
        parts.append(
            f'<text x="{x + 18}" y="{y - 8}" class="lane">{html.escape(name.upper())} · '
            f"{len(by_lane[name])}</text>"
        )
        last_tick = y
        for n in by_lane[name]:
            ny = y + 8
            parts.append(_node(n, x + 18, ny))
            mid = ny + NODE_H / 2
            parts.append(f'<line x1="{trunk}" y1="{mid}" x2="{x + 18}" y2="{mid}" class="edge"/>')
            last_tick = mid
            y = ny + NODE_H
            if n["hidden"] is not None:
                parts_, y = _pocket(n, x, y)
                parts += parts_
            y += GAP
        parts.append(
            f'<line x1="{trunk}" y1="{bus_y}" x2="{trunk}" y2="{last_tick}" class="edge"/>'
        )
        bottom = max(bottom, y)
    height = bottom + 16
    style = (
        "<style>"
        ".box{fill:var(--card);stroke:var(--line);stroke-width:1.4}"
        ".node:hover .box{stroke:var(--acc);stroke-width:2}"
        ".cloud{fill:var(--chip);stroke:var(--line)}"
        ".edge{stroke:var(--mute);stroke-width:1.5;fill:none;opacity:.7}.dash{stroke-dasharray:4 4}"
        ".hidden{fill:none;stroke:var(--warn);stroke-width:1.4;stroke-dasharray:5 4}"
        "text{fill:var(--ink);font-family:system-ui,-apple-system,sans-serif}"
        ".lbl{font-size:13px;font-weight:650}.sub{font-size:11px;fill:var(--mute)}.b{font-weight:650}"
        ".ico{font-size:22px}.lane{font-size:10.5px;letter-spacing:.8px;fill:var(--mute);font-weight:650}"
        ".bdg{font-size:11px;font-weight:700;fill:#fff}.ok{fill:var(--ok);font-size:13px}"
        ".okt{fill:var(--ok);font-size:12px}.badt{fill:var(--bad);font-size:12px;font-weight:700}"
        "</style>"
    )
    return Markup(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'width="{width:.0f}" role="img" aria-label="Network map">{style}{"".join(parts)}</svg>'
    )
