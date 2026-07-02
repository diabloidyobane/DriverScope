"""archive.org Wayback Machine snapshot enumeration.

Given a vendor's download page URL (or a URL pattern), enumerate historical
snapshots via the Wayback CDX API. Optionally fetch each historical URL and
extract .sys files.

Common invocations:
  wayback.py --url "https://download.msi.com/uti_exe/desktop/*"
  wayback.py --domain aida64.com --path-glob "*download*.zip"

Rate limiting: the CDX API returns as much as we ask for. We paginate and
back off if we hit 429.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional


CDX_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "wayback_harvest"

USER_AGENT = "driverscope-wayback/0.1"


@dataclass
class Snapshot:
    url: str
    ts: str      # 14-char Wayback timestamp
    status: str  # HTTP status at capture
    mime: str
    digest: str
    length: int = 0


def cdx_search(url_pattern: str, from_ts: str = "", to_ts: str = "",
               limit: int = 5000, timeout: int = 60) -> list[Snapshot]:
    """Return matched snapshots. url_pattern accepts CDX-style wildcards (see
    https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server).
    """
    params: dict[str, str] = {
        "url": url_pattern,
        "output": "json",
        "matchType": "prefix" if url_pattern.endswith("*") else "exact",
        "limit": str(limit),
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
    }
    if from_ts:
        params["from"] = from_ts
    if to_ts:
        params["to"] = to_ts

    url = f"{CDX_URL}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            time.sleep(30)
        return []
    except Exception:
        return []
    if not data or len(data) <= 1:
        return []
    header = data[0]
    idx = {name: i for i, name in enumerate(header)}
    snaps: list[Snapshot] = []
    for row in data[1:]:
        try:
            snaps.append(Snapshot(
                ts=row[idx["timestamp"]],
                url=row[idx["original"]],
                status=row[idx["statuscode"]],
                mime=row[idx["mimetype"]],
                digest=row[idx["digest"]],
                length=int(row[idx["length"]]) if row[idx["length"]].isdigit() else 0,
            ))
        except Exception:
            continue
    return snaps


def snapshot_url(s: Snapshot) -> str:
    """Return the raw-file archive URL for this snapshot."""
    return f"https://web.archive.org/web/{s.ts}if_/{s.url}"


def _download(url: str, dest: Path, timeout: int = 90, max_mb: int = 400) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            clen = resp.headers.get("Content-Length")
            if clen and int(clen) > max_mb * 1024 * 1024:
                return False
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        return dest.exists() and dest.stat().st_size > 0
    except Exception:
        return False


def _extract_sys(archive: Path, out_dir: Path) -> list[Path]:
    found: list[Path] = []
    suffix = archive.suffix.lower()

    if suffix == ".zip":
        try:
            import zipfile
            with zipfile.ZipFile(archive) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".sys"):
                        dest = out_dir / Path(name).name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(name) as src, open(dest, "wb") as f:
                            shutil.copyfileobj(src, f)
                        found.append(dest)
        except Exception:
            pass

    if not found and shutil.which("7z"):
        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            p = subprocess.run(["7z", "x", "-y", f"-o{td}", str(archive)],
                               capture_output=True, timeout=180)
            if p.returncode == 0:
                for root, _, files in os.walk(td):
                    for fn in files:
                        if fn.lower().endswith(".sys"):
                            src = Path(root) / fn
                            dst = out_dir / fn
                            try:
                                shutil.copy2(src, dst)
                                found.append(dst)
                            except Exception:
                                pass
    return found


def harvest(url_patterns: Iterable[str],
            out_dir: Path = DEFAULT_OUT,
            fetch: bool = True,
            fetch_max: int = 40,
            dedup_by_digest: bool = True,
            from_ts: str = "",
            to_ts: str = "") -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    staging = out_dir / "_staging"
    staging.mkdir(parents=True, exist_ok=True)
    drivers = out_dir / "drivers"
    drivers.mkdir(parents=True, exist_ok=True)

    manifest: dict = {"queries": [], "snapshots": [], "fetched": [], "sys_found": []}
    all_snaps: list[Snapshot] = []

    for pat in url_patterns:
        snaps = cdx_search(pat, from_ts=from_ts, to_ts=to_ts)
        manifest["queries"].append({"pattern": pat, "hits": len(snaps)})
        all_snaps.extend(snaps)
        time.sleep(1)

    # dedup by digest so we don't re-fetch identical archives
    seen: set[str] = set()
    picks: list[Snapshot] = []
    for s in all_snaps:
        key = s.digest if dedup_by_digest and s.digest else f"{s.url}#{s.ts}"
        if key in seen:
            continue
        seen.add(key)
        picks.append(s)

    manifest["snapshots"] = [asdict(s) for s in picks]

    if fetch:
        fetched = 0
        for s in picks:
            if fetched >= fetch_max:
                break
            if s.status and not s.status.startswith("2"):
                continue
            fname = os.path.basename(urllib.parse.urlparse(s.url).path) or "download.bin"
            fname = re.sub(r'[<>:"|?*]', "_", fname)
            dest = staging / f"{s.ts}__{fname}"
            if not _download(snapshot_url(s), dest):
                continue
            manifest["fetched"].append(str(dest))
            fetched += 1
            for p in _extract_sys(dest, drivers):
                manifest["sys_found"].append(str(p))
            time.sleep(1)

    with open(out_dir / "wayback_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Wayback CDX snapshot enumerator + fetcher")
    ap.add_argument("--url", action="append", default=[],
                    help="URL pattern (may end in * for prefix match). Repeat for multiple.")
    ap.add_argument("--no-fetch", action="store_true")
    ap.add_argument("--fetch-max", type=int, default=40)
    ap.add_argument("--from-ts", type=str, default="")
    ap.add_argument("--to-ts", type=str, default="")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    args = ap.parse_args()

    if not args.url:
        raise SystemExit("Pass at least one --url pattern (may end in *)")

    m = harvest(args.url, out_dir=Path(args.out),
                fetch=not args.no_fetch, fetch_max=args.fetch_max,
                from_ts=args.from_ts, to_ts=args.to_ts)
    print(f"[wayback] snapshots={len(m.get('snapshots', []))} "
          f"fetched={len(m.get('fetched', []))} sys={len(m.get('sys_found', []))}")
