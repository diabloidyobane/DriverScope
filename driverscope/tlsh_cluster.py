"""TLSH-based clustering for a driver corpus.

Groups .sys files by fuzzy binary similarity. A cluster containing several
known-CVE'd drivers plus one novel driver is a strong lead.

Falls back gracefully:
  1. If python-tlsh is installed → real TLSH digests + real similarity.
  2. Otherwise → a lightweight rolling-imphash surrogate that still surfaces
     obvious clusters (same import graph, similar section layout). Useful for
     initial triage even without the tlsh package.
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

try:
    import tlsh as _tlsh  # type: ignore
    HAVE_TLSH = True
except ImportError:
    _tlsh = None
    HAVE_TLSH = False


# ── digest calculators ──────────────────────────────────────────────────

def _read_bytes(path: str | Path, cap: Optional[int] = None) -> bytes:
    p = Path(path)
    with open(p, "rb") as f:
        return f.read(cap) if cap else f.read()


def tlsh_digest(path: str | Path) -> Optional[str]:
    """Return a TLSH digest (72 hex chars) or None if too small / unavailable."""
    if not HAVE_TLSH:
        return None
    try:
        data = _read_bytes(path)
        if len(data) < 50:
            return None
        h = _tlsh.hash(data)
        if not h or h == "TNULL" or h == "":
            return None
        return h
    except Exception:
        return None


def _imports_from_pe(path: str | Path) -> list[str]:
    """Cheap import-name list without pulling in pefile — best effort."""
    try:
        data = _read_bytes(path)
    except OSError:
        return []
    if len(data) < 0x400 or data[:2] != b"MZ":
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
            return []
    except Exception:
        return []
    # Give up on hand-rolled RVA→file offset math; rely on pefile if present.
    try:
        import pefile  # type: ignore
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(path), fast_load=False)
        out: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        out.append(imp.name.decode("utf-8", errors="replace"))
        pe.close()
        return out
    except Exception:
        return []


def surrogate_digest(path: str | Path) -> str:
    """Fallback digest: SHA1 over sorted-import-list joined with size buckets.

    NOT cryptographically or perceptually meaningful, but tends to cluster
    driver variants of the same tool together in practice.
    """
    imports = sorted(set(_imports_from_pe(path)))
    p = Path(path)
    try:
        size_bucket = str(p.stat().st_size // 4096)
    except OSError:
        size_bucket = "?"
    body = size_bucket + "|" + "|".join(imports)
    return "S1:" + hashlib.sha1(body.encode("utf-8")).hexdigest()


def digest_for(path: str | Path) -> str:
    """Prefer TLSH; fall back to surrogate."""
    if HAVE_TLSH:
        t = tlsh_digest(path)
        if t:
            return "T1:" + t
    return surrogate_digest(path)


# ── similarity ──────────────────────────────────────────────────────────

def distance(a: str, b: str) -> int:
    """Distance between digests. Lower is more similar.

    For real TLSH: uses tlsh.diff (0 = identical, hundreds = unrelated).
    For surrogate: 0 if equal, 1000 otherwise (essentially exact-match only).
    """
    if a.startswith("T1:") and b.startswith("T1:") and HAVE_TLSH:
        return _tlsh.diff(a[3:], b[3:])
    return 0 if a == b else 1000


# ── clustering ──────────────────────────────────────────────────────────

@dataclass
class ClusterMember:
    path: str
    sha256: str = ""
    digest: str = ""
    signer: str = ""
    primitive_classes: list[str] = field(default_factory=list)


@dataclass
class Cluster:
    id: int
    members: list[ClusterMember] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)


def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return ""


def compute_members(paths: Iterable[str | Path]) -> list[ClusterMember]:
    out: list[ClusterMember] = []
    for p in paths:
        p_str = str(p)
        d = digest_for(p_str)
        m = ClusterMember(path=p_str, sha256=_sha256_file(p_str), digest=d)
        out.append(m)
    return out


def enrich_members(members: list[ClusterMember], results: Iterable) -> None:
    """Copy signer / primitive_classes into ClusterMember using a scanner
    DriverResult list keyed by (sha256, path)."""
    by_key = {}
    for r in results:
        try:
            key = ((getattr(r, "sha256", "") or "").lower(), getattr(r, "path", "") or "")
            by_key[key] = r
        except Exception:
            continue
    for m in members:
        r = by_key.get((m.sha256, m.path))
        if r is not None:
            m.signer = getattr(r, "signer", "") or ""
            m.primitive_classes = list(getattr(r, "primitive_classes", []) or [])


def cluster(members: list[ClusterMember], threshold: int = 60) -> list[Cluster]:
    """Greedy single-link clustering. Two members are joined if
    distance(digest_a, digest_b) <= threshold.

    threshold=60 is the widely used TLSH "same family, tuned variant" cutoff.
    """
    clusters: list[Cluster] = []
    next_id = 1
    for m in members:
        placed = False
        for cl in clusters:
            centroid = cl.members[0]
            if distance(m.digest, centroid.digest) <= threshold:
                cl.members.append(m)
                placed = True
                break
        if not placed:
            clusters.append(Cluster(id=next_id, members=[m]))
            next_id += 1
    clusters.sort(key=lambda c: -c.size)
    return clusters


def render_text(clusters: list[Cluster], min_size: int = 2,
                lol_hashes: Optional[set[str]] = None) -> str:
    lines: list[str] = []
    interesting = [c for c in clusters if c.size >= min_size]
    lines.append("=" * 100)
    lines.append(f"  TLSH CLUSTERS  (backend: {'TLSH' if HAVE_TLSH else 'SURROGATE'})  "
                 f"{len(interesting)} clusters >= {min_size} members")
    lines.append("=" * 100)
    for c in interesting:
        known = 0
        novel: list[ClusterMember] = []
        if lol_hashes:
            for m in c.members:
                if m.sha256 in lol_hashes:
                    known += 1
                else:
                    novel.append(m)
        head = f"  cluster #{c.id}  size={c.size}"
        if lol_hashes:
            head += f"  LOLDrivers-known={known}  novel-in-cluster={len(novel)}"
            if known and novel:
                head += "  <-- lead candidate"
        lines.append("")
        lines.append(head)
        for m in c.members[:12]:
            tag = " [LOL]" if lol_hashes and m.sha256 in lol_hashes else ""
            classes = ",".join(m.primitive_classes) if m.primitive_classes else "-"
            signer = m.signer[:32] if m.signer else ""
            lines.append(f"    {m.sha256[:12]} [{classes}] {Path(m.path).name:<32} "
                         f"{signer}{tag}")
        if c.size > 12:
            lines.append(f"    ... and {c.size - 12} more")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="TLSH-cluster a corpus of .sys files")
    ap.add_argument("paths", nargs="+", help=".sys files or directories")
    ap.add_argument("--threshold", type=int, default=60,
                    help="TLSH distance threshold (default 60; smaller=stricter)")
    ap.add_argument("--min-size", type=int, default=2)
    ap.add_argument("--lol-cache", type=str, default=None,
                    help="Path to loldrivers_cache.json for lead highlighting")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    files: list[str] = []
    for a in args.paths:
        p = Path(a)
        if p.is_dir():
            files.extend(str(x) for x in p.rglob("*.sys"))
        elif p.is_file():
            files.append(str(p))
    print(f"[tlsh] hashing {len(files)} files "
          f"(backend: {'TLSH' if HAVE_TLSH else 'SURROGATE'})")

    members = compute_members(files)
    clusters = cluster(members, threshold=args.threshold)

    lol_hashes: Optional[set[str]] = None
    if args.lol_cache and Path(args.lol_cache).exists():
        raw = json.loads(Path(args.lol_cache).read_text(encoding="utf-8"))
        lol_hashes = set()
        for e in raw:
            for s in (e.get("KnownVulnerableSamples") or []):
                sha = (s.get("SHA256") or "").lower()
                if sha:
                    lol_hashes.add(sha)

    if args.json:
        out = [
            {"id": c.id,
             "members": [{"path": m.path, "sha256": m.sha256, "digest": m.digest,
                          "signer": m.signer,
                          "primitive_classes": m.primitive_classes} for m in c.members]}
            for c in clusters if c.size >= args.min_size
        ]
        print(json.dumps(out, indent=2))
    else:
        print(render_text(clusters, min_size=args.min_size, lol_hashes=lol_hashes))
