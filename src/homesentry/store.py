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
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  ts REAL NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL,
  title TEXT NOT NULL, detail TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, started REAL, finished REAL, summary TEXT
);
-- v2: what changed between scans (the timeline). Titles never embed device names:
-- the UI renders the label from device_id, so events are safe to hand to the LLM.
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
  device_id INTEGER, title TEXT NOT NULL, detail TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
-- v2: owner said "I know, I accept this" (keyed by stable finding key, not title text)
CREATE TABLE IF NOT EXISTS risk_accepts(
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL, fkey TEXT NOT NULL, note TEXT,
  ts REAL NOT NULL, UNIQUE(device_id, fkey)
);
-- v2: household Q&A history (device references are handles like [D7], never names)
CREATE TABLE IF NOT EXISTS ask_turns(
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL
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
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(devices)")}
        if "network" not in cols:  # v1 migration: which LAN a device lives on
            self.db.execute("ALTER TABLE devices ADD COLUMN network TEXT")
            self.db.commit()
        if "retired" not in cols:  # decommissioned: hidden, never resurrected by gateway
            self.db.execute("ALTER TABLE devices ADD COLUMN retired REAL")
            self.db.commit()
        if "online" not in cols:  # v2: answered in the most recent scan (NULL = never scanned)
            self.db.execute("ALTER TABLE devices ADD COLUMN online INTEGER")
            self.db.commit()

    # ---- devices -------------------------------------------------------
    def upsert_seen(
        self,
        mac: str,
        ip: str,
        hostname: str | None,
        oui_vendor: str | None,
        network: str | None = None,
    ) -> int:
        now = time.time()
        row = self.db.execute("SELECT id, retired FROM devices WHERE mac=?", (mac,)).fetchone()
        if row:
            if row["retired"]:  # a "decommissioned" device is talking on the LAN again
                self.db.execute("UPDATE devices SET retired=NULL WHERE id=?", (row["id"],))
                self.add_evidence(row["id"], "user", "reappeared_after_retire", time.strftime("%F"))
            self.db.execute(
                "UPDATE devices SET ip=?, hostname=COALESCE(?, hostname),"
                " oui_vendor=COALESCE(?, oui_vendor), network=COALESCE(?, network),"
                " last_seen=? WHERE id=?",
                (ip, hostname, oui_vendor, network, now, row["id"]),
            )
            self.db.commit()
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO devices(mac, ip, hostname, oui_vendor, network, first_seen, last_seen)"
            " VALUES(?,?,?,?,?,?,?)",
            (mac, ip, hostname, oui_vendor, network, now, now),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def upsert_known(
        self,
        mac: str,
        ip: str | None,
        hostname: str | None,
        oui_vendor: str | None,
        network: str | None,
    ) -> int:
        """A device another source (e.g. the gateway's DHCP table) remembers but we did not
        see on the wire. Never bumps last_seen; inserts with last_seen NULL (= offline)."""
        row = self.db.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if row:
            return row["id"]
        cur = self.db.execute(
            "INSERT INTO devices(mac, ip, hostname, oui_vendor, network, first_seen)"
            " VALUES(?,?,?,?,?,?)",
            (mac, ip, hostname, oui_vendor, network, time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def retire(self, device_id: int) -> None:
        self.db.execute("UPDATE devices SET retired=? WHERE id=?", (time.time(), device_id))
        self.db.execute("DELETE FROM findings WHERE device_id=?", (device_id,))
        self.db.commit()

    def is_retired(self, mac: str) -> bool:
        r = self.db.execute("SELECT retired FROM devices WHERE mac=?", (mac,)).fetchone()
        return bool(r and r["retired"])

    def create_manual(self, label: str) -> int:
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO devices(label, id_source, first_seen, last_seen) VALUES(?, 'user', ?, ?)",
            (label, now, now),
        )
        self.db.commit()
        return int(cur.lastrowid or 0)

    def devices(self, include_retired: bool = False) -> list[dict[str, Any]]:
        where = "" if include_retired else " WHERE retired IS NULL"
        rows = self.db.execute(
            f"SELECT * FROM devices{where} ORDER BY confirmed, confidence, id"
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

    def delete_evidence(self, device_id: int, source: str, key: str) -> None:
        self.db.execute(
            "DELETE FROM evidence WHERE device_id=? AND source=? AND key=?",
            (device_id, source, key),
        )
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

    # ---- findings ------------------------------------------------------
    def replace_findings(self, device_id: int, findings: list[dict[str, Any]]) -> None:
        now = time.time()
        self.db.execute("DELETE FROM findings WHERE device_id=?", (device_id,))
        self.db.executemany(
            "INSERT INTO findings(device_id, ts, severity, kind, title, detail, data)"
            " VALUES(?,?,?,?,?,?,?)",
            [
                (
                    device_id,
                    now,
                    f["severity"],
                    f["kind"],
                    f["title"],
                    f.get("detail"),
                    json.dumps(f.get("data") or {}),
                )
                for f in findings
            ],
        )
        self.db.commit()

    def findings(self, device_id: int | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM findings" + (" WHERE device_id=?" if device_id else "")
        rows = self.db.execute(q, (device_id,) if device_id else ()).fetchall()
        out = []
        for r in rows:
            f = dict(r)
            f["data"] = json.loads(f["data"] or "{}")
            out.append(f)
        order = ["critical", "high", "medium", "low", "info"]
        return sorted(out, key=lambda f: order.index(f["severity"]))

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

    def scans(self, limit: int = 60) -> list[dict[str, Any]]:
        """Most recent scans, oldest first (for trend lines)."""
        rows = self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in reversed(rows):
            d = dict(r)
            d["summary"] = json.loads(d["summary"] or "{}")
            out.append(d)
        return out

    def last_scan_with(self, key: str) -> dict[str, Any] | None:
        """Most recent scan whose summary has `key` truthy (e.g. 'ports', 'gateway')."""
        for r in self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 500"):
            s = json.loads(r["summary"] or "{}")
            if s.get(key):
                return dict(r, summary=s)
        return None

    def mark_presence(self, started: float) -> None:
        """After a scan: a device is online iff it answered during this scan."""
        self.db.execute(
            "UPDATE devices SET online = CASE WHEN last_seen >= ? THEN 1 ELSE 0 END"
            " WHERE mac IS NOT NULL",
            (started,),
        )
        self.db.commit()

    # ---- events (v2) ---------------------------------------------------
    def add_events(self, events: list[dict[str, Any]], ts: float | None = None) -> None:
        ts = ts or time.time()
        self.db.executemany(
            "INSERT INTO events(ts, kind, severity, device_id, title, detail, data)"
            " VALUES(?,?,?,?,?,?,?)",
            [
                (
                    ts,
                    e["kind"],
                    e["severity"],
                    e.get("device_id"),
                    e["title"],
                    e.get("detail"),
                    json.dumps(e.get("data") or {}),
                )
                for e in events
            ],
        )
        self.db.commit()

    def events(
        self, limit: int = 100, since: float | None = None, device_id: int | None = None
    ) -> list[dict[str, Any]]:
        q, args = "SELECT * FROM events WHERE 1=1", []
        if since is not None:
            q += " AND ts >= ?"
            args.append(since)
        if device_id is not None:
            q += " AND device_id = ?"
            args.append(device_id)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.db.execute(q, args):
            e = dict(r)
            e["data"] = json.loads(e["data"] or "{}")
            out.append(e)
        return out

    # ---- risk acceptance (v2) ------------------------------------------
    def accept_risk(self, device_id: int, fkey: str, note: str = "") -> None:
        self.db.execute(
            "INSERT INTO risk_accepts(device_id, fkey, note, ts) VALUES(?,?,?,?)"
            " ON CONFLICT(device_id, fkey) DO UPDATE SET note=excluded.note, ts=excluded.ts",
            (device_id, fkey, note.strip()[:500], time.time()),
        )
        self.db.commit()

    def unaccept_risk(self, device_id: int, fkey: str) -> None:
        self.db.execute("DELETE FROM risk_accepts WHERE device_id=? AND fkey=?", (device_id, fkey))
        self.db.commit()

    def accepted(self) -> dict[tuple[int, str], dict[str, Any]]:
        return {
            (r["device_id"], r["fkey"]): dict(r)
            for r in self.db.execute("SELECT * FROM risk_accepts")
        }

    # ---- household Q&A (v2) --------------------------------------------
    def add_ask(self, role: str, content: str) -> None:
        self.db.execute(
            "INSERT INTO ask_turns(ts, role, content) VALUES(?,?,?)", (time.time(), role, content)
        )
        self.db.commit()

    def ask_turns(self, limit: int = 40) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM ask_turns ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def clear_ask(self) -> None:
        self.db.execute("DELETE FROM ask_turns")
        self.db.commit()
