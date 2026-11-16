"""Phone-friendly web UI: overview, plan, map, timeline, ask, report, device wizard."""

from __future__ import annotations

import datetime as dt
import hmac
import os
import re
import threading
import time
import traceback
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import __version__, agent, data_dir, netmap, plan, wizard
from ..llm import LLM, OllamaClient, parse_json_reply
from ..scan import run_scan
from ..store import Store
from ..watch import ScanBusy, finding_key
from . import ui

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
GOOD = {"finding_resolved", "firmware_changed", "port_closed", "device_online"}
SUGGESTIONS = [
    "What should I fix first, and why?",
    "Which device worries you most?",
    "What changed this week?",
    "Is anything reachable from the internet?",
]


def create_app(store: Store | None = None, llm: LLM | None = None) -> FastAPI:
    app = FastAPI(title="HomeSentry")
    app.state.store = store or Store(data_dir() / "inventory.db")
    app.state.llm = llm or OllamaClient()
    app.state.scan = {"running": False, "log": [], "error": None}
    tpl = Jinja2Templates(env=ui.env())
    install_session_auth(app, os.environ.get("HOMESENTRY_TOKEN") or None)

    def lan_status() -> dict[str, bool]:
        last = S().last_scan()
        blocked = bool(last and (last.get("summary") or {}).get("local_network_blocked"))
        return {"blocked": blocked, "empty": not S().devices()}

    tpl.env.globals["lan_status"] = lan_status

    def S() -> Store:
        return app.state.store

    def names() -> dict[int, str]:
        return agent.names_for(S())

    def guides_available() -> set[str]:
        gdir = data_dir() / "guides"
        return {p.stem for p in gdir.glob("*.html")} if gdir.is_dir() else set()

    def rendered_plan() -> dict[str, Any]:
        p = plan.build(S())
        n = names()
        for a in p["actions"]:
            a["rendered"] = plan.render_title(a, lambda i: n.get(i, "device"))
        return p

    def background(job) -> None:
        st = app.state.scan
        if st["running"]:
            return
        st.update(running=True, log=[], error=None)

        def work():
            try:
                job(st["log"].append)
            except ScanBusy:
                st["error"] = "the automatic scan is running right now; try again in a minute"
            except Exception as e:  # noqa: BLE001
                st["error"] = f"{e}"
                traceback.print_exc()
            finally:
                st["running"] = False

        threading.Thread(target=work, daemon=True).start()

    # ---- overview ---------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        devices = S().devices()
        findings = S().findings()
        by_dev: dict[int, list] = {}
        for f in findings:
            by_dev.setdefault(f["device_id"], []).append(f)
        for d in devices:
            fs = by_dev.get(d["id"], [])
            d["worst"] = fs[0]["severity"] if fs else None
            d["n_findings"] = sum(1 for f in fs if f["severity"] != "info")
        networks: dict[str, list] = {}
        for d in sorted(devices, key=lambda d: (SEV_RANK.get(d["worst"], 9), d["id"])):
            networks.setdefault(d.get("network") or "added by hand", []).append(d)
        p = rendered_plan()
        stats = {
            "total": len(devices),
            "online": sum(1 for d in devices if d.get("online")),
            "confirmed": sum(d["confirmed"] for d in devices),
            "unknown": len(p["unknown"]),
        }
        trend = [s["summary"]["score"] for s in S().scans(40) if "score" in s["summary"]]
        return tpl.TemplateResponse(
            request,
            "index.html",
            {
                "networks": networks,
                "stats": stats,
                "scan": app.state.scan,
                "last_scan": S().last_scan(),
                "plan": p,
                "trend": trend,
                "events": S().events(limit=5),
                "names": names(),
            },
        )

    @app.post("/scan")
    def scan(ports: Annotated[bool, Form()] = False):
        background(lambda log: run_scan(S(), ports=ports, log=log, extra={"trigger": "button"}))
        return RedirectResponse("/", status_code=303)

    @app.post("/threats")
    def threats():
        def job(log):
            from .. import threat

            threat.run(S(), log=log)

        background(job)
        return RedirectResponse("/", status_code=303)

    @app.post("/outside")
    def outside_check():
        def job(log):
            from .. import outside

            outside.run_and_record(S(), log=log)

        background(job)
        return RedirectResponse("/", status_code=303)

    # ---- plan ---------------------------------------------------------------------
    @app.get("/plan", response_class=HTMLResponse)
    def plan_page(request: Request):
        p = rendered_plan()
        acc = S().accepted()
        accepted = []
        for f in p["accepted"]:
            a = acc.get((f["device_id"], f["fkey"])) or {}
            accepted.append(f | {"note": a.get("note", ""), "accepted_at": a.get("ts")})
        return tpl.TemplateResponse(
            request,
            "plan.html",
            {
                "plan": p,
                "accepted": accepted,
                "names": names(),
                "devs": {d["id"]: d for d in S().devices(include_retired=True)},
                "guides": guides_available(),
            },
        )

    @app.post("/plan/accept")
    def plan_accept(key: Annotated[str, Form()], note: Annotated[str, Form()] = ""):
        a = next((a for a in plan.build(S())["actions"] if a["key"] == key), None)
        if a is None:
            raise HTTPException(404)
        for f in a["findings"]:
            S().accept_risk(f["device_id"], f["fkey"], note)
        return RedirectResponse("/plan", status_code=303)

    @app.post("/plan/unaccept")
    def plan_unaccept(device_id: Annotated[int, Form()], fkey: Annotated[str, Form()]):
        S().unaccept_risk(device_id, fkey)
        return RedirectResponse("/plan", status_code=303)

    # ---- map / timeline / report ------------------------------------------------------
    @app.get("/map", response_class=HTMLResponse)
    def map_page(request: Request):
        m = netmap.model(S(), ui.icon)
        lanes = {n["lane"] for n in m["nodes"]} or {"x"}
        return tpl.TemplateResponse(
            request,
            "map.html",
            {"svg": netmap.svg(m), "min_w": min(880, 212 * len(lanes) + 24)},
        )

    @app.get("/timeline", response_class=HTMLResponse)
    def timeline(request: Request, only: str | None = None):
        evs = S().events(limit=400)
        if only == "important":
            evs = [e for e in evs if e["severity"] in ("critical", "high", "medium")]
        elif only == "good":
            evs = [e for e in evs if e["kind"] in GOOD]
        days: list[tuple[str, list]] = []
        for e in evs:
            day = dt.datetime.fromtimestamp(e["ts"]).strftime("%A %d %B")
            if not days or days[-1][0] != day:
                days.append((day, []))
            days[-1][1].append(e)
        return tpl.TemplateResponse(
            request,
            "timeline.html",
            {"days": days, "names": names(), "only": only, "watch": _watch_cadence()},
        )

    @app.get("/report", response_class=HTMLResponse)
    def report_page():
        from .. import report

        return HTMLResponse(report.render(S()))

    # ---- ask ------------------------------------------------------------------------
    @app.get("/ask", response_class=HTMLResponse)
    def ask_page(request: Request, q: str | None = None, error: str | None = None):
        n = names()
        turns = []
        for t in S().ask_turns(limit=40):
            if t["role"] == "user":
                shown = re.sub(
                    r"\[D(\d+)\]", lambda m: n.get(int(m.group(1)), m.group(0)), t["content"]
                )
                turns.append({"role": "user", "shown": shown})
            else:
                try:
                    body = parse_json_reply(t["content"])
                except ValueError:
                    body = {"answer": t["content"]}
                turns.append({"role": "assistant", "html": agent.render(body.get("answer", ""), n)})
        last = S().ask_turns(limit=1)
        sugg = SUGGESTIONS
        if last and last[-1]["role"] == "assistant":
            try:
                sugg = parse_json_reply(last[-1]["content"]).get("followups") or SUGGESTIONS
            except ValueError:
                pass
        sugg = [
            re.sub(r"\[D(\d+)\]", lambda m: n.get(int(m.group(1)), "that device"), s) for s in sugg
        ]
        return tpl.TemplateResponse(
            request,
            "ask.html",
            {"turns": turns, "prefill": q, "suggestions": sugg[:4], "error": error},
        )

    @app.post("/ask")
    def ask_post(q: Annotated[str, Form()]):
        if not q.strip():
            return RedirectResponse("/ask", status_code=303)
        try:
            agent.ask(S(), app.state.llm, q)
        except Exception as e:  # noqa: BLE001
            return RedirectResponse(f"/ask?error={str(e)[:160]}#bottom", status_code=303)
        return RedirectResponse("/ask#bottom", status_code=303)

    @app.post("/ask/clear")
    def ask_clear():
        S().clear_ask()
        return RedirectResponse("/ask", status_code=303)

    # ---- devices --------------------------------------------------------------------
    @app.post("/devices/new")
    def new_device(label: Annotated[str, Form()]):
        did = S().create_manual(label.strip() or "Unnamed device")
        return RedirectResponse(f"/device/{did}", status_code=303)

    @app.get("/device/{device_id}", response_class=HTMLResponse)
    def device(request: Request, device_id: int, error: str | None = None):
        d = S().device(device_id)
        if not d:
            raise HTTPException(404)
        turns = S().turns(device_id)
        for t in turns:
            if t["role"] == "assistant":
                try:
                    t["parsed"] = parse_json_reply(t["content"])
                except ValueError:
                    t["parsed"] = {"message": t["content"]}
            t["photo_names"] = [Path(p).name for p in t["images"]]
        acc = S().accepted()
        findings = []
        for f in S().findings(device_id):
            k = finding_key(f)
            findings.append(
                f
                | {
                    "fkey": k,
                    "accepted": acc.get((device_id, k)),
                    "explain": agent.explain_prompt(device_id, f["title"]),
                }
            )
        return tpl.TemplateResponse(
            request,
            "device.html",
            {
                "d": d,
                "evidence": S().evidence(device_id),
                "turns": turns,
                "findings": findings,
                "proposal": wizard.latest_proposal(S(), device_id),
                "error": error,
                "events": S().events(limit=12, device_id=device_id),
                "names": names(),
            },
        )

    @app.post("/device/{device_id}/accept")
    def device_accept(
        device_id: int, fkey: Annotated[str, Form()], note: Annotated[str, Form()] = ""
    ):
        S().accept_risk(device_id, fkey, note)
        return RedirectResponse(f"/device/{device_id}", status_code=303)

    @app.post("/device/{device_id}/unaccept")
    def device_unaccept(device_id: int, fkey: Annotated[str, Form()]):
        S().unaccept_risk(device_id, fkey)
        return RedirectResponse(f"/device/{device_id}", status_code=303)

    @app.post("/device/{device_id}/wizard")
    async def wizard_turn(
        device_id: int,
        text: Annotated[str, Form()] = "",
        photos: Annotated[list[UploadFile] | None, File()] = None,
    ):
        if not S().device(device_id):
            raise HTTPException(404)
        saved = []
        pdir = data_dir() / "photos" / str(device_id)
        pdir.mkdir(parents=True, exist_ok=True)
        for up in photos or []:
            if not up.filename:
                continue
            ext = Path(up.filename).suffix.lower()[:6] or ".jpg"
            p = pdir / f"{int(time.time() * 1000)}{re.sub(r'[^.a-z0-9]', '', ext)}"
            p.write_bytes(await up.read())
            saved.append(p)
        if not text.strip() and not saved:
            return RedirectResponse(f"/device/{device_id}", status_code=303)
        try:
            wizard.run_turn(S(), app.state.llm, device_id, text.strip(), saved)
        except Exception as e:  # noqa: BLE001
            return RedirectResponse(f"/device/{device_id}?error={str(e)[:200]}", status_code=303)
        return RedirectResponse(f"/device/{device_id}#bottom", status_code=303)

    @app.post("/device/{device_id}/confirm")
    def confirm(
        device_id: int,
        label: Annotated[str, Form()] = "",
        device_type: Annotated[str, Form()] = "",
        make: Annotated[str, Form()] = "",
        model: Annotated[str, Form()] = "",
        firmware: Annotated[str, Form()] = "",
        notes: Annotated[str, Form()] = "",
    ):
        wizard.confirm(
            S(),
            device_id,
            {
                "label": label,
                "device_type": device_type,
                "make": make,
                "model": model,
                "firmware": firmware,
                "notes": notes,
            },
        )
        return RedirectResponse(f"/device/{device_id}", status_code=303)

    @app.post("/device/{device_id}/retire")
    def retire(device_id: int):
        S().retire(device_id)
        return RedirectResponse("/", status_code=303)

    # ---- guides / photos / health -------------------------------------------------------
    @app.get("/guides", response_class=HTMLResponse)
    def guides(request: Request):
        return tpl.TemplateResponse(request, "guides.html", {"guides": sorted(guides_available())})

    @app.get("/guides/{slug}")
    def guide(slug: str):
        # Runbooks dropped (or symlinked) into <data>/guides/. Strict slug, no paths.
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", slug):
            raise HTTPException(404)
        p = data_dir() / "guides" / f"{slug}.html"
        if not p.is_file():
            raise HTTPException(404)
        return FileResponse(p, media_type="text/html")

    @app.get("/photo/{device_id}/{name}")
    def photo(device_id: int, name: str):
        if not re.fullmatch(r"\d+\.[a-z0-9]{1,5}", name):
            raise HTTPException(404)
        p = data_dir() / "photos" / str(device_id) / name
        if not p.exists():
            raise HTTPException(404)
        return FileResponse(p)

    @app.get("/api/events")
    def api_events(since: float = 0.0, min_severity: str = "medium"):
        """New timeline events, for a desktop shell's native notifications (local only)."""
        rank = SEV_RANK.get(min_severity, 2)
        n = names()
        evs = [
            {
                "id": e["id"],
                "ts": e["ts"],
                "kind": e["kind"],
                "severity": e["severity"],
                "title": e["title"],
                "device": n.get(e["device_id"]) if e.get("device_id") else None,
                "device_id": e.get("device_id"),
            }
            for e in S().events(since=since)
            if SEV_RANK.get(e["severity"], 4) <= rank
        ]
        last = S().last_scan()
        return JSONResponse(
            {
                "events": evs,
                "now": time.time(),
                "scanning": app.state.scan["running"],
                "local_network_blocked": bool(
                    last and (last.get("summary") or {}).get("local_network_blocked")
                ),
            }
        )

    @app.get("/healthz")
    def healthz():
        last = S().last_scan()
        age = round(time.time() - last["finished"]) if last else None
        sc = plan.score(S())
        ok = age is not None and age < 6 * 3600
        return JSONResponse(
            {
                "ok": ok,
                "version": __version__,
                "last_scan_age_s": age,
                "devices": len(S().devices()),
                "score": sc["score"],
                "grade": sc["grade"],
            },
            status_code=200 if ok else 503,
        )

    return app


LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
COOKIE = "hs_session"


def install_session_auth(app: FastAPI, token: str | None) -> None:
    """Desktop mode (HOMESENTRY_TOKEN set): the UI answers only the app that started it.

    The shell opens /auth?token=...; we set an HttpOnly, SameSite=Strict cookie and every later
    request must carry it (or `Authorization: Bearer`). Only loopback Host headers are
    accepted, so a web page can't reach us through DNS rebinding. No token = appliance mode
    (bound to a tailnet IP), unchanged.
    """
    if not token:
        return

    def ok(value: str | None) -> bool:
        return bool(value) and hmac.compare_digest(value.encode(), token.encode())

    @app.middleware("http")
    async def gate(request: Request, call_next):
        host = (request.headers.get("host") or "").rsplit(":", 1)[0]
        if host not in LOCAL_HOSTS:
            return HTMLResponse("Forbidden host", status_code=403)
        if request.url.path == "/auth":
            if not ok(request.query_params.get("token")):
                return HTMLResponse("Bad or missing token", status_code=401)
            resp = RedirectResponse(request.query_params.get("next") or "/", status_code=303)
            resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
            return resp
        auth = request.headers.get("authorization", "")
        bearer = auth[7:] if auth.lower().startswith("bearer ") else None
        if not (ok(request.cookies.get(COOKIE)) or ok(bearer)):
            return HTMLResponse(
                "<h3>HomeSentry</h3><p>Open HomeSentry from its app icon.</p>", status_code=401
            )
        return await call_next(request)


def _watch_cadence() -> str | None:
    """Human cadence of the watch timer if installed (read from the unit file)."""
    unit = Path("~/.config/systemd/user/homesentry-watch.timer").expanduser()
    if not unit.exists():
        return None
    m = re.search(r"OnUnitActiveSec=(\S+)", unit.read_text())
    return m.group(1) if m else "on a timer"
