"""SQLite inventory. Private, local-only: never committed, never sent anywhere."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY,
  mac TEXT UNIQUE,
  ip TEXT, hostname TEXT, oui_vendor TEXT,
  label TEXT, device_type TEXT, make TEXT, model TEXT, firmware TEXT,
  confidence REAL DEFAULT 0, id_source TEXT, confirmed INTEGER DEFAULT 0,
  notes TEXT, first_seen REAL, last_seen REAL
);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  source TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, ts REAL NOT NULL,
  UNIQUE(device_id, source, key, value)
);
CREATE TABLE IF NOT EXISTS wizard_turns(
  id INTEGER PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  ts REAL NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, images TEXT
);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, started REAL, finished REAL, summary TEXT
);
"""

IDENTITY_FIELDS = ("label", "device_type", "make", "model", "firmware", "notes")


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    # ---- devices -------------------------------------------------------
    def upsert_seen(self, mac: str, ip: str, hostname: str | None, oui_vendor: str | None) -> int:
        now = time.time()
        row = self.db.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if row:
            self.db.execute(
                "UPDATE devices SET ip=?, hostname=COALESCE(?, hostname),"
                " oui_vendor=COALESCE(?, oui_vendor), last_seen=? WHERE id=?",
                (ip, hostname, oui_vendor, now, row["id"]),
            )
            self.db.commit()
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO devices(mac, ip, hostname, oui_vendor, first_seen, last_seen)"
            " VALUES(?,?,?,?,?,?)",
            (mac, ip, hostname, oui_vendor, now, now),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def create_manual(self, label: str) -> int:
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO devices(label, id_source, first_seen, last_seen) VALUES(?, 'user', ?, ?)",
            (label, now, now),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def devices(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM devices ORDER BY confirmed, confidence, id"
        ).fetchall()
        return [dict(r) for r in rows]

    def device(self, device_id: int) -> dict[str, Any] | None:
        r = self.db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return dict(r) if r else None

    def set_identity(
        self,
        device_id: int,
        fields: dict[str, Any],
        source: str,
        confidence: float,
        confirmed: bool = False,
    ) -> bool:
        """Apply an identification. Auto/wizard guesses never override a confirmed device
        or a higher-confidence guess. Returns True if applied."""
        d = self.device(device_id)
        if d is None:
            return False
        if not confirmed:
            if d["confirmed"]:
                return False
            # a fresh auto pass always replaces an older auto pass (it saw all evidence);
            # anything else must beat the current confidence
            refresh = source == "auto" and d["id_source"] in (None, "auto")
            if not refresh and confidence < (d["confidence"] or 0):
                return False
        sets = {k: v for k, v in fields.items() if k in IDENTITY_FIELDS and v not in (None, "")}
        if not confirmed and source == "auto" and d["id_source"] in (None, "auto"):
            # full refresh: fields the new pass could not determine are cleared
            for k in ("device_type", "make", "model"):
                sets.setdefault(k, None)
        sets.update(confidence=confidence, id_source=source, confirmed=int(confirmed))
        cols = ", ".join(f"{k}=?" for k in sets)
        self.db.execute(f"UPDATE devices SET {cols} WHERE id=?", (*sets.values(), device_id))
        self.db.commit()
        return True

    # ---- evidence ------------------------------------------------------
    def add_evidence(self, device_id: int, source: str, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO evidence(device_id, source, key, value, ts) VALUES(?,?,?,?,?)"
            " ON CONFLICT(device_id, source, key, value) DO UPDATE SET ts=excluded.ts",
            (device_id, source, key, value, time.time()),
        )
        self.db.commit()

    def clear_evidence(self, device_id: int, source: str) -> None:
        self.db.execute("DELETE FROM evidence WHERE device_id=? AND source=?", (device_id, source))
        self.db.commit()

    def evidence(self, device_id: int) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT source, key, value, ts FROM evidence WHERE device_id=? ORDER BY source, key",
            (device_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- wizard --------------------------------------------------------
    def add_turn(self, device_id: int, role: str, content: str, images: list[str] | None = None):
        self.db.execute(
            "INSERT INTO wizard_turns(device_id, ts, role, content, images) VALUES(?,?,?,?,?)",
            (device_id, time.time(), role, content, json.dumps(images or [])),
        )
        self.db.commit()

    def turns(self, device_id: int) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM wizard_turns WHERE device_id=? ORDER BY id", (device_id,)
        ).fetchall()
        out = []
        for r in rows:
            t = dict(r)
            t["images"] = json.loads(t["images"] or "[]")
            out.append(t)
        return out

    # ---- scans ---------------------------------------------------------
    def record_scan(self, started: float, summary: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO scans(started, finished, summary) VALUES(?,?,?)",
            (started, time.time(), json.dumps(summary)),
        )
        self.db.commit()

    def last_scan(self) -> dict[str, Any] | None:
        r = self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d["summary"] or "{}")
        return d
