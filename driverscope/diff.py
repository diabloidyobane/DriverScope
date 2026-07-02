"""Diff two DriverScope scan snapshots.

Snapshot forms accepted:
  1. JSON file previously written by driverscope scan --json
  2. DriverScope SQLite DB + scan_id
  3. In-memory list of DriverResult objects (duck-typed)

Diff categories:
  new         sha256 present now, absent before
  removed     sha256 absent now, present before
  changed     same path/filename present in both, sha256 differs (driver was replaced)
  moved       same sha256 present in both, but at different path (relocated)
  unchanged   same (sha256, path) in both
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


@dataclass
class DiffEntry:
    kind: str            # "new" | "removed" | "changed" | "moved" | "unchanged"
    sha256: str
    path: str
    prev_sha256: str = ""
    prev_path: str = ""
    filename: str = ""
    signer: str = ""
    primitive_classes: list[str] = field(default_factory=list)


@dataclass
class DiffResult:
    entries: list[DiffEntry] = field(default_factory=list)

    def by_kind(self, kind: str) -> list[DiffEntry]:
        return [e for e in self.entries if e.kind == kind]

    @property
    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.kind] = out.get(e.kind, 0) + 1
        return out


# ── snapshot loaders ─────────────────────────────────────────────────────

@dataclass
class _Record:
    sha256: str
    path: str
    filename: str = ""
    signer: str = ""
    primitive_classes: list[str] = field(default_factory=list)


def _rec_from_dict(d: dict) -> Optional[_Record]:
    sha = (d.get("sha256") or "").lower()
    p = d.get("path") or ""
    if not sha or not p:
        return None
    return _Record(
        sha256=sha, path=p,
        filename=d.get("filename") or Path(p).name,
        signer=d.get("signer") or "",
        primitive_classes=list(d.get("primitive_classes") or []),
    )


def _rec_from_obj(r: Any) -> Optional[_Record]:
    sha = (getattr(r, "sha256", "") or "").lower()
    p = getattr(r, "path", "") or ""
    if not sha or not p:
        return None
    return _Record(
        sha256=sha, path=p,
        filename=getattr(r, "filename", None) or Path(p).name,
        signer=getattr(r, "signer", "") or "",
        primitive_classes=list(getattr(r, "primitive_classes", []) or []),
    )


def load_json(path: str | Path) -> list[_Record]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out: list[_Record] = []
    if isinstance(data, list):
        for d in data:
            if isinstance(d, dict):
                rec = _rec_from_dict(d)
                if rec:
                    out.append(rec)
    return out


def load_iter(results: Iterable[Any]) -> list[_Record]:
    out: list[_Record] = []
    for r in results:
        rec = _rec_from_obj(r)
        if rec:
            out.append(rec)
    return out


def load_sqlite(db_path: str | Path, scan_id: Optional[int] = None) -> list[_Record]:
    """Load the driver snapshot from a DriverScope SQLite DB.

    If scan_id is omitted, uses the latest scan.
    """
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    try:
        if scan_id is None:
            cur = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if not row:
                return []
            scan_id = row[0]
        cur = conn.execute(
            "SELECT h.sha256, h.path, d.filename, d.signer, d.primitive_json "
            "FROM scan_hits h JOIN drivers d "
            "  ON d.sha256=h.sha256 AND d.path=h.path "
            "WHERE h.scan_id=?",
            (scan_id,),
        )
        out: list[_Record] = []
        for r in cur.fetchall():
            out.append(_Record(
                sha256=(r[0] or "").lower(),
                path=r[1] or "",
                filename=r[2] or Path(r[1] or "").name,
                signer=r[3] or "",
                primitive_classes=list(json.loads(r[4] or "[]")),
            ))
        return out
    finally:
        conn.close()


# ── diff core ────────────────────────────────────────────────────────────

def diff(prev: list[_Record], curr: list[_Record]) -> DiffResult:
    prev_by_pp: dict[tuple[str, str], _Record] = {(r.sha256, r.path): r for r in prev}
    curr_by_pp: dict[tuple[str, str], _Record] = {(r.sha256, r.path): r for r in curr}
    prev_by_path: dict[str, _Record] = {r.path: r for r in prev}
    prev_by_sha: dict[str, list[_Record]] = {}
    for r in prev:
        prev_by_sha.setdefault(r.sha256, []).append(r)
    curr_by_sha: set[str] = {r.sha256 for r in curr}

    out = DiffResult()
    seen_curr: set[tuple[str, str]] = set()

    for key, r in curr_by_pp.items():
        if key in prev_by_pp:
            out.entries.append(DiffEntry(
                kind="unchanged", sha256=r.sha256, path=r.path,
                filename=r.filename, signer=r.signer,
                primitive_classes=list(r.primitive_classes),
            ))
        else:
            # same path, different hash → changed
            if r.path in prev_by_path and prev_by_path[r.path].sha256 != r.sha256:
                prev_rec = prev_by_path[r.path]
                out.entries.append(DiffEntry(
                    kind="changed", sha256=r.sha256, path=r.path,
                    prev_sha256=prev_rec.sha256, prev_path=prev_rec.path,
                    filename=r.filename, signer=r.signer,
                    primitive_classes=list(r.primitive_classes),
                ))
            # same hash, new path → moved (or extra copy)
            elif r.sha256 in prev_by_sha:
                prev_rec = prev_by_sha[r.sha256][0]
                out.entries.append(DiffEntry(
                    kind="moved", sha256=r.sha256, path=r.path,
                    prev_sha256=prev_rec.sha256, prev_path=prev_rec.path,
                    filename=r.filename, signer=r.signer,
                    primitive_classes=list(r.primitive_classes),
                ))
            else:
                out.entries.append(DiffEntry(
                    kind="new", sha256=r.sha256, path=r.path,
                    filename=r.filename, signer=r.signer,
                    primitive_classes=list(r.primitive_classes),
                ))
        seen_curr.add(key)

    for key, r in prev_by_pp.items():
        if key not in curr_by_pp and r.sha256 not in curr_by_sha:
            out.entries.append(DiffEntry(
                kind="removed", sha256=r.sha256, path=r.path,
                filename=r.filename, signer=r.signer,
                primitive_classes=list(r.primitive_classes),
            ))
    return out


def render_text(res: DiffResult, show_unchanged: bool = False) -> str:
    lines: list[str] = []
    summary = res.summary
    lines.append("=" * 90)
    lines.append(
        "  DRIVERSCOPE DIFF  "
        + " ".join(f"{k}={v}" for k, v in sorted(summary.items()))
    )
    lines.append("=" * 90)

    order = ["new", "changed", "moved", "removed"]
    if show_unchanged:
        order.append("unchanged")
    for kind in order:
        entries = res.by_kind(kind)
        if not entries:
            continue
        lines.append("")
        lines.append(f"  [{kind.upper()}] {len(entries)}")
        for e in entries[:200]:
            cls = ",".join(e.primitive_classes) if e.primitive_classes else "-"
            if kind in ("changed", "moved"):
                lines.append(
                    f"    {e.sha256[:12]} {e.filename:<32} [{cls}]  was: "
                    f"{e.prev_sha256[:12] if kind=='changed' else e.prev_path}"
                )
            else:
                lines.append(f"    {e.sha256[:12]} {e.path}  [{cls}]")
        if len(entries) > 200:
            lines.append(f"    ... and {len(entries) - 200} more")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse, sys as _sys
    ap = argparse.ArgumentParser(description="Diff two DriverScope snapshots")
    ap.add_argument("prev", help="Prior snapshot: JSON file or sqlite:///PATH[?scan=N]")
    ap.add_argument("curr", help="Current snapshot: JSON file or sqlite:///PATH[?scan=N]")
    ap.add_argument("--show-unchanged", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    def _load(spec: str) -> list[_Record]:
        if spec.startswith("sqlite:///"):
            body = spec[len("sqlite:///"):]
            scan_id: Optional[int] = None
            if "?" in body:
                body, q = body.split("?", 1)
                for chunk in q.split("&"):
                    if "=" in chunk:
                        k, v = chunk.split("=", 1)
                        if k == "scan":
                            scan_id = int(v)
            return load_sqlite(body, scan_id=scan_id)
        return load_json(spec)

    prev = _load(args.prev)
    curr = _load(args.curr)
    res = diff(prev, curr)
    if args.json:
        payload = [e.__dict__ for e in res.entries]
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(res, show_unchanged=args.show_unchanged))
