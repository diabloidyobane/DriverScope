"""SQLite backend for DriverScope. One database, append-only scan history.

Schema:
  scans          one row per --scan invocation (id, ts, target, host, corpus_size)
  drivers        one row per unique (sha256, path) pair (with primitive classes, signer, arch)
  scan_hits      many-to-many: which drivers were seen in which scan
  vt             latest VT result per sha256
  lol            latest LOLDrivers metadata per sha256
  msbl           latest MS blocklist verdict per sha256
  clusters       optional TLSH cluster membership

Design notes:
  - drivers uniqueness is (sha256, path). Same hash at different paths = separate rows.
  - scan_hits gives history: "how many scans have I seen this hash in".
  - This is INTENTIONALLY not the source of truth for VT/LOL/MSBL — those are caches.
    driverscope.scanner's existing JSON caches remain canonical. This DB is for querying.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL    NOT NULL,
  host          TEXT,
  target_path   TEXT,
  corpus_size   INTEGER,
  hits          INTEGER,
  ms_blocked    INTEGER,
  cli_args      TEXT
);

CREATE TABLE IF NOT EXISTS drivers (
  sha256          TEXT NOT NULL,
  path            TEXT NOT NULL,
  filename        TEXT,
  size_bytes      INTEGER,
  machine         TEXT,
  signed          INTEGER,
  signer          TEXT,
  primitive_json  TEXT,
  matched_imports_json TEXT,
  first_seen_ts   REAL,
  last_seen_ts    REAL,
  PRIMARY KEY (sha256, path)
);

CREATE INDEX IF NOT EXISTS ix_drivers_signer  ON drivers(signer);
CREATE INDEX IF NOT EXISTS ix_drivers_size    ON drivers(size_bytes);
CREATE INDEX IF NOT EXISTS ix_drivers_lastseen ON drivers(last_seen_ts);

CREATE TABLE IF NOT EXISTS scan_hits (
  scan_id   INTEGER NOT NULL REFERENCES scans(id),
  sha256    TEXT    NOT NULL,
  path      TEXT    NOT NULL,
  PRIMARY KEY (scan_id, sha256, path)
);

CREATE INDEX IF NOT EXISTS ix_scan_hits_sha ON scan_hits(sha256);

CREATE TABLE IF NOT EXISTS vt (
  sha256          TEXT PRIMARY KEY,
  fetched_ts      REAL,
  detections      INTEGER,
  total_engines   INTEGER,
  reputation      INTEGER,
  first_seen      TEXT,
  last_seen       TEXT,
  ms_blocklist    INTEGER,
  loldriver       INTEGER,
  detection_names_json TEXT
);

CREATE TABLE IF NOT EXISTS lol (
  sha256      TEXT PRIMARY KEY,
  lol_id      TEXT,
  category    TEXT,
  hvci_bypass INTEGER,
  cves_json   TEXT,
  tags_json   TEXT
);

CREATE TABLE IF NOT EXISTS msbl (
  sha256          TEXT PRIMARY KEY,
  blocked         INTEGER,
  blocked_name    TEXT,
  fetched_ts      REAL
);

CREATE TABLE IF NOT EXISTS clusters (
  cluster_id  INTEGER,
  sha256      TEXT,
  tlsh        TEXT,
  ts          REAL,
  PRIMARY KEY (cluster_id, sha256)
);

CREATE INDEX IF NOT EXISTS ix_clusters_sha ON clusters(sha256);
"""


DEFAULT_DB = Path(__file__).resolve().parent.parent / "driverscope.db"


class DB:
    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else DEFAULT_DB
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextmanager
    def txn(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # -- scan bookkeeping --------------------------------------------------

    def new_scan(self, target_path: str, host: str = "", corpus_size: int = 0,
                 hits: int = 0, ms_blocked: int = 0, cli_args: str = "") -> int:
        with self.txn() as c:
            cur = c.execute(
                "INSERT INTO scans (ts, host, target_path, corpus_size, hits, ms_blocked, cli_args) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), host, target_path, corpus_size, hits, ms_blocked, cli_args),
            )
            return cur.lastrowid

    def finalize_scan(self, scan_id: int, corpus_size: int, hits: int, ms_blocked: int) -> None:
        with self.txn() as c:
            c.execute(
                "UPDATE scans SET corpus_size=?, hits=?, ms_blocked=? WHERE id=?",
                (corpus_size, hits, ms_blocked, scan_id),
            )

    def record_driver(self, scan_id: int, r: Any) -> None:
        """r is a DriverResult (duck-typed: sha256, path, filename, size_bytes, machine,
        signed, signer, primitive_classes, matched_imports)."""
        if not getattr(r, "sha256", ""):
            return
        now = time.time()
        with self.txn() as c:
            # upsert driver
            c.execute(
                "INSERT INTO drivers "
                "  (sha256, path, filename, size_bytes, machine, signed, signer, "
                "   primitive_json, matched_imports_json, first_seen_ts, last_seen_ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(sha256, path) DO UPDATE SET "
                "  filename=excluded.filename, size_bytes=excluded.size_bytes, "
                "  machine=excluded.machine, signed=excluded.signed, signer=excluded.signer, "
                "  primitive_json=excluded.primitive_json, "
                "  matched_imports_json=excluded.matched_imports_json, "
                "  last_seen_ts=excluded.last_seen_ts",
                (
                    r.sha256, r.path, r.filename, r.size_bytes, r.machine,
                    1 if getattr(r, "signed", False) else 0,
                    getattr(r, "signer", "") or "",
                    json.dumps(getattr(r, "primitive_classes", []) or []),
                    json.dumps(getattr(r, "matched_imports", []) or []),
                    now, now,
                ),
            )
            c.execute(
                "INSERT OR IGNORE INTO scan_hits (scan_id, sha256, path) VALUES (?, ?, ?)",
                (scan_id, r.sha256, r.path),
            )
            # optional enrichments
            vt = getattr(r, "vt", None)
            if vt is not None:
                c.execute(
                    "INSERT INTO vt (sha256, fetched_ts, detections, total_engines, "
                    " reputation, first_seen, last_seen, ms_blocklist, loldriver, "
                    " detection_names_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(sha256) DO UPDATE SET "
                    "  fetched_ts=excluded.fetched_ts, detections=excluded.detections, "
                    "  total_engines=excluded.total_engines, reputation=excluded.reputation, "
                    "  first_seen=excluded.first_seen, last_seen=excluded.last_seen, "
                    "  ms_blocklist=excluded.ms_blocklist, loldriver=excluded.loldriver, "
                    "  detection_names_json=excluded.detection_names_json",
                    (
                        r.sha256, now,
                        getattr(vt, "detections", 0),
                        getattr(vt, "total_engines", 0),
                        getattr(vt, "reputation", 0),
                        getattr(vt, "first_seen", "") or "",
                        getattr(vt, "last_seen", "") or "",
                        1 if getattr(vt, "ms_blocklist", False) else 0,
                        1 if getattr(vt, "loldriver", False) else 0,
                        json.dumps(getattr(vt, "detection_names", []) or []),
                    ),
                )
            if getattr(r, "lol_known", False):
                c.execute(
                    "INSERT INTO lol (sha256, lol_id, category, hvci_bypass, cves_json, tags_json) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(sha256) DO UPDATE SET "
                    "  lol_id=excluded.lol_id, category=excluded.category, "
                    "  hvci_bypass=excluded.hvci_bypass, cves_json=excluded.cves_json, "
                    "  tags_json=excluded.tags_json",
                    (
                        r.sha256, getattr(r, "lol_id", ""),
                        getattr(r, "lol_category", ""),
                        1 if getattr(r, "lol_hvci_bypass", False) else 0,
                        json.dumps(getattr(r, "lol_cves", []) or []),
                        json.dumps(getattr(r, "lol_tags", []) or []),
                    ),
                )
            if getattr(r, "ms_blocked", False):
                c.execute(
                    "INSERT INTO msbl (sha256, blocked, blocked_name, fetched_ts) "
                    "VALUES (?, 1, ?, ?) "
                    "ON CONFLICT(sha256) DO UPDATE SET "
                    "  blocked=excluded.blocked, blocked_name=excluded.blocked_name, "
                    "  fetched_ts=excluded.fetched_ts",
                    (r.sha256, getattr(r, "ms_blocked_name", ""), now),
                )

    def record_batch(self, scan_id: int, results: Iterable[Any]) -> None:
        for r in results:
            try:
                self.record_driver(scan_id, r)
            except Exception:
                pass

    def record_cluster(self, cluster_id: int, sha256: str, tlsh: str) -> None:
        with self.txn() as c:
            c.execute(
                "INSERT OR REPLACE INTO clusters (cluster_id, sha256, tlsh, ts) "
                "VALUES (?, ?, ?, ?)",
                (cluster_id, sha256, tlsh, time.time()),
            )

    # -- query surfaces ----------------------------------------------------

    def last_scan_id(self) -> Optional[int]:
        cur = self.conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else None

    def scan_ids(self, limit: int = 10) -> list[dict]:
        cur = self.conn.execute(
            "SELECT id, ts, target_path, corpus_size, hits, ms_blocked "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {"id": r[0], "ts": r[1], "target": r[2],
             "corpus_size": r[3], "hits": r[4], "ms_blocked": r[5]}
            for r in cur.fetchall()
        ]

    def drivers_in_scan(self, scan_id: int) -> set[tuple[str, str]]:
        cur = self.conn.execute(
            "SELECT sha256, path FROM scan_hits WHERE scan_id=?", (scan_id,)
        )
        return {(r[0], r[1]) for r in cur.fetchall()}

    def by_signer(self, signer_substr: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT sha256, path, filename, signer, primitive_json, last_seen_ts "
            "FROM drivers WHERE signer LIKE ? ORDER BY last_seen_ts DESC",
            (f"%{signer_substr}%",),
        )
        out = []
        for r in cur.fetchall():
            out.append({
                "sha256": r[0], "path": r[1], "filename": r[2],
                "signer": r[3], "primitive_classes": json.loads(r[4] or "[]"),
                "last_seen_ts": r[5],
            })
        return out

    def hashes_new_since(self, ts: float) -> list[dict]:
        cur = self.conn.execute(
            "SELECT sha256, path, filename, signer, primitive_json, first_seen_ts "
            "FROM drivers WHERE first_seen_ts > ? ORDER BY first_seen_ts DESC",
            (ts,),
        )
        return [
            {"sha256": r[0], "path": r[1], "filename": r[2], "signer": r[3],
             "primitive_classes": json.loads(r[4] or "[]"), "first_seen_ts": r[5]}
            for r in cur.fetchall()
        ]

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


def open_db(path: Optional[str | Path] = None) -> DB:
    return DB(path)
