"""Report the N novel BYOVD candidates from the DriverScope SQLite DB.

Novel := has primitive_classes AND NOT in LOLDrivers AND NOT MS-blocked.
Ranked by primitive-class count, then by presence of a signer (signed > unsigned),
then by size (favour small drivers first).
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Optional


_MS_SIGNER_MARKERS = (
    "microsoft", "redmond", "washington1", "windows (r)",
    "wdkte", "one microsoft", "mopr",
)
_PARSE_ARTIFACT_MARKERS = (
    "(no authenticode)", "(signed, cn parse failed)", "(signed, parse error)",
    "(signed)",
)


def _is_microsoft_signer(sig: str) -> bool:
    s = (sig or "").lower()
    return any(m in s for m in _MS_SIGNER_MARKERS)


def _is_parse_artifact(sig: str) -> bool:
    s = (sig or "").lower().strip()
    return any(m in s for m in _PARSE_ARTIFACT_MARKERS)


def find(db_path: str | Path, limit: int = 250,
         scan_id: Optional[int] = None,
         require_signed: bool = False,
         min_classes: int = 1,
         only_hvci_bypass_potential: bool = False,
         exclude_microsoft: bool = False,
         exclude_parse_artifacts: bool = False,
         path_excludes: Optional[list[str]] = None) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    try:
        if scan_id is None:
            row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            if not row:
                return []
            scan_id = row[0]

        q = """
        SELECT d.sha256, d.path, d.filename, d.size_bytes, d.machine,
               d.signed, d.signer, d.primitive_json, d.matched_imports_json,
               d.first_seen_ts, d.last_seen_ts,
               COALESCE(m.blocked, 0)   AS msbl,
               m.blocked_name,
               COALESCE(l.hvci_bypass, 0) AS lol_hvci,
               l.lol_id, l.category, l.cves_json,
               v.detections, v.total_engines, v.reputation
        FROM drivers d
        JOIN scan_hits h  ON h.sha256=d.sha256 AND h.path=d.path
        LEFT JOIN msbl m  ON m.sha256=d.sha256
        LEFT JOIN lol  l  ON l.sha256=d.sha256
        LEFT JOIN vt   v  ON v.sha256=d.sha256
        WHERE h.scan_id=?
          AND d.primitive_json <> '[]'
          AND (m.blocked IS NULL OR m.blocked=0)
          AND l.sha256 IS NULL
        """
        rows = conn.execute(q, (scan_id,)).fetchall()
    finally:
        conn.close()

    out: list[dict] = []
    seen_sha: set[str] = set()
    path_excludes_lower = [p.lower() for p in (path_excludes or [])]
    for r in rows:
        classes = json.loads(r[7] or "[]")
        if len(classes) < min_classes:
            continue
        if require_signed and not r[5]:
            continue
        signer = r[6] or ""
        if exclude_microsoft and _is_microsoft_signer(signer):
            continue
        if exclude_parse_artifacts and _is_parse_artifact(signer):
            continue
        path_l = (r[1] or "").lower()
        if any(x in path_l for x in path_excludes_lower):
            continue
        # dedup by sha256 (same driver at multiple paths counts once)
        if r[0] in seen_sha:
            continue
        seen_sha.add(r[0])
        out.append({
            "sha256":        r[0],
            "path":          r[1],
            "filename":      r[2],
            "size_bytes":    r[3],
            "machine":       r[4],
            "signed":        bool(r[5]),
            "signer":        r[6] or "",
            "primitive_classes": classes,
            "matched_imports":   json.loads(r[8] or "[]"),
            "first_seen_ts": r[9],
            "vt_detections": r[17] or 0,
            "vt_total":      r[18] or 0,
        })

    def _rank(d: dict) -> tuple:
        return (
            -len(d["primitive_classes"]),
            0 if d["signed"] else 1,
            d["size_bytes"] or 0,
            d["filename"].lower(),
        )

    out.sort(key=_rank)
    return out[:limit]


def render_table(items: list[dict]) -> str:
    lines = []
    lines.append("=" * 130)
    lines.append(f"  NOVEL BYOVD CANDIDATES  ({len(items)} rows, MS-not-blocked, LOL-unknown)")
    lines.append("=" * 130)
    lines.append(f"  {'#':<4} {'sha256':<16} {'signed':<6} {'sz(KB)':>7} {'cls':>3} "
                 f"{'signer':<30} {'primitives':<40}  filename")
    lines.append(f"  {'-'*4} {'-'*16} {'-'*6} {'-'*7} {'-'*3} {'-'*30} {'-'*40}  --------")
    for i, d in enumerate(items, 1):
        classes = ",".join(d["primitive_classes"])
        if len(classes) > 40:
            classes = classes[:37] + "..."
        signer = d["signer"][:30] if d["signer"] else ""
        lines.append(
            f"  {i:<4} {d['sha256'][:16]:<16} "
            f"{'yes' if d['signed'] else 'NO':<6} "
            f"{(d['size_bytes'] or 0) // 1024:>7} "
            f"{len(d['primitive_classes']):>3} "
            f"{signer:<30} {classes:<40}  {d['filename']}"
        )
    return "\n".join(lines)


def render_summary(items: list[dict]) -> str:
    total = len(items)
    signed = sum(1 for d in items if d["signed"])
    class_counts: Counter = Counter()
    signer_counts: Counter = Counter()
    for d in items:
        for c in d["primitive_classes"]:
            class_counts[c] += 1
        s = d["signer"] or "(unsigned)"
        signer_counts[s] += 1
    lines = ["", "SUMMARY", "-" * 60,
             f"  total novel candidates: {total}",
             f"  signed:                 {signed}",
             f"  unsigned:               {total - signed}",
             "", "  top primitive classes:"]
    for c, n in class_counts.most_common(12):
        lines.append(f"    {c:<20} {n:>4}")
    lines.append("")
    lines.append("  top signers:")
    for s, n in signer_counts.most_common(12):
        lines.append(f"    {s[:56]:<56} {n:>4}")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Report N novel BYOVD candidates from a DriverScope DB")
    default_db = str(Path(__file__).resolve().parent.parent / "driverscope.db")
    ap.add_argument("--db", default=default_db)
    ap.add_argument("--limit", type=int, default=250)
    ap.add_argument("--scan-id", type=int, default=None)
    ap.add_argument("--signed-only", action="store_true")
    ap.add_argument("--min-classes", type=int, default=1)
    ap.add_argument("--no-microsoft", action="store_true",
                    help="Drop rows whose signer looks Microsoft-issued")
    ap.add_argument("--no-parse-artifacts", action="store_true",
                    help="Drop rows where the signer field failed to parse")
    ap.add_argument("--exclude-path", action="append", default=[],
                    help="Substring; drop rows whose path contains it. Repeat.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    items = find(args.db, limit=args.limit, scan_id=args.scan_id,
                 require_signed=args.signed_only, min_classes=args.min_classes,
                 exclude_microsoft=args.no_microsoft,
                 exclude_parse_artifacts=args.no_parse_artifacts,
                 path_excludes=args.exclude_path or None)
    if args.json:
        print(json.dumps(items, indent=2, default=str))
    else:
        print(render_table(items))
        print(render_summary(items))
