"""Phone-friendly web UI: inventory grid + per-device wizard with camera upload."""

from __future__ import annotations

import re
import threading
import time
import traceback
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import data_dir, wizard
from ..llm import LLM, OllamaClient, parse_json_reply
from ..scan import run_scan
from ..store import Store

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


def create_app(store: Store | None = None, llm: LLM | None = None) -> FastAPI:
    app = FastAPI(title="HomeSentry")
    app.state.store = store or Store(data_dir() / "inventory.db")
    app.state.llm = llm or OllamaClient()
    app.state.scan = {"running": False, "log": [], "error": None}
    tpl = Jinja2Templates(directory=HERE / "templates")
    tpl.env.globals.update(icon=lambda t: ICONS.get(t or "", "❔"), ago=_ago)

    def S() -> Store:
        return app.state.store

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        devices = S().devices()
        findings = S().findings()
        by_dev: dict[int, list] = {}
        for f in findings:
            by_dev.setdefault(f["device_id"], []).append(f)
        names = {d["id"]: d["label"] or d["ip"] or "device" for d in devices}
        for d in devices:
            fs = by_dev.get(d["id"], [])
            d["worst"] = fs[0]["severity"] if fs else None
            d["n_findings"] = sum(1 for f in fs if f["severity"] != "info")
        networks: dict[str, list] = {}
        for d in sorted(devices, key=lambda d: (SEV_RANK.get(d["worst"], 9), d["id"])):
            networks.setdefault(d.get("network") or "added by hand", []).append(d)
        top = [
            dict(f, device=names.get(f["device_id"]))
            for f in findings
            if f["severity"] in ("critical", "high", "medium")
        ][:8]
        stats = {
            "total": len(devices),
            "confirmed": sum(d["confirmed"] for d in devices),
            "unknown": sum(1 for d in devices if (d["confidence"] or 0) < 0.4),
            "risks": sum(1 for f in findings if f["severity"] in ("critical", "high")),
        }
        return tpl.TemplateResponse(
            request,
            "index.html",
            {
                "networks": networks,
                "stats": stats,
                "scan": app.state.scan,
                "last_scan": S().last_scan(),
                "top": top,
            },
        )

    @app.post("/scan")
    def scan(ports: Annotated[bool, Form()] = False):
        st = app.state.scan
        if not st["running"]:
            st.update(running=True, log=[], error=None)

            def work():
                try:
                    run_scan(S(), ports=ports, log=st["log"].append)
                except Exception as e:  # noqa: BLE001
                    st["error"] = f"{e}"
                    traceback.print_exc()
                finally:
                    st["running"] = False

            threading.Thread(target=work, daemon=True).start()
        return RedirectResponse("/", status_code=303)

    @app.post("/threats")
    def threats():
        st = app.state.scan
        if not st["running"]:
            st.update(running=True, log=[], error=None)

            def work():
                from .. import threat

                try:
                    threat.run(S(), log=st["log"].append)
                except Exception as e:  # noqa: BLE001
                    st["error"] = f"{e}"
                finally:
                    st["running"] = False

            threading.Thread(target=work, daemon=True).start()
        return RedirectResponse("/", status_code=303)

    @app.post("/outside")
    def outside_check():
        st = app.state.scan
        if not st["running"]:
            st.update(running=True, log=[], error=None)

            def work():
                from .. import outside

                try:
                    outside.run_and_record(S(), log=st["log"].append)
                except Exception as e:  # noqa: BLE001
                    st["error"] = f"{e}"
                finally:
                    st["running"] = False

            threading.Thread(target=work, daemon=True).start()
        return RedirectResponse("/", status_code=303)

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
        return tpl.TemplateResponse(
            request,
            "device.html",
            {
                "d": d,
                "evidence": S().evidence(device_id),
                "turns": turns,
                "findings": S().findings(device_id),
                "proposal": wizard.latest_proposal(S(), device_id),
                "error": error,
            },
        )

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

    @app.get("/photo/{device_id}/{name}")
    def photo(device_id: int, name: str):
        if not re.fullmatch(r"\d+\.[a-z0-9]{1,5}", name):
            raise HTTPException(404)
        p = data_dir() / "photos" / str(device_id) / name
        if not p.exists():
            raise HTTPException(404)
        return FileResponse(p)

    return app


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ago(ts: float | None) -> str:
    if not ts:
        return "never"
    s = int(time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s // n}{unit} ago"
    return "just now"
