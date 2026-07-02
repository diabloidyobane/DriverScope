"""Walk the Windows Package Manager (winget) catalog for `.sys`-bearing installers.

Approach:
  1. Enumerate packages that match a category filter (hardware, RGB, storage,
     OEM utility, systeminfo, benchmark).
  2. For each, run `winget show <id> --disable-interactivity` to grab the
     installer URL(s).
  3. Download each installer to a staging dir.
  4. Peek inside (7z / unzip / PE resource) for embedded `.sys`.
  5. Extract found .sys into an output dir. driverscope scan takes it from there.

This is a driver, not a general package harvester — pure BYOVD-hunting focus.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_OUT = Path(__file__).resolve().parent.parent / "winget_harvest"
STAGING_SUBDIR = "_staging"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Keyword sets used to shortlist packages that historically bundle a signed .sys.
DEFAULT_QUERIES = [
    "hardware", "monitor", "cpu-z", "hwinfo", "hwmonitor", "aida64", "sensor",
    "smart",   "diskinfo", "diskmark", "ssd manager",
    "rgb", "iCUE", "Armoury", "MSI Center", "MSI Afterburner", "gigabyte",
    "throttle", "overclock", "afterburner", "ryzen master", "extreme tuning",
    "burnintest", "occt", "coretemp", "throttlestop",
    "storage", "wd dashboard", "samsung magician", "crucial storage",
    "kingston ssd", "intel rapid",
    "pcileech", "memprocfs", "rwever", "portable io",
]


def _run(cmd: list[str], timeout: int = 90) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "winget not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def have_winget() -> bool:
    return shutil.which("winget") is not None


def search(query: str, limit: int = 25) -> list[dict]:
    """Best-effort parse of `winget search --query <q>`."""
    rc, out, err = _run(["winget", "search", "--query", query,
                         "--disable-interactivity"])
    if rc != 0:
        return []
    lines = [l for l in out.splitlines() if l.strip()]
    # Try to find header line: "Name    Id    Version    Match    Source"
    header_idx = -1
    for i, l in enumerate(lines):
        if re.match(r"^\s*Name\s+Id\b", l):
            header_idx = i
            break
    if header_idx < 0:
        return []
    body = lines[header_idx + 2:]  # header + dashes
    out_pkgs: list[dict] = []
    for row in body:
        # crude column split; winget pads with 2+ spaces between fields
        parts = re.split(r"\s{2,}", row.strip())
        if len(parts) >= 2:
            name = parts[0]
            pkg_id = parts[1]
            if not pkg_id or " " in pkg_id:
                continue
            out_pkgs.append({"name": name, "id": pkg_id})
        if len(out_pkgs) >= limit:
            break
    return out_pkgs


_INSTALLER_URL_RE = re.compile(r"Installer\s*Url:\s*(\S+)", re.IGNORECASE)
_HASH_RE = re.compile(r"Installer\s*SHA256:\s*([0-9a-fA-F]{64})", re.IGNORECASE)
_TYPE_RE = re.compile(r"Installer\s*Type:\s*(\S+)", re.IGNORECASE)


def show(pkg_id: str) -> dict:
    """Return {installers: [{url, sha256, type}]} for a package id."""
    rc, out, err = _run(["winget", "show", pkg_id, "--disable-interactivity"])
    if rc != 0:
        return {"id": pkg_id, "installers": []}
    urls = _INSTALLER_URL_RE.findall(out)
    hashes = _HASH_RE.findall(out)
    types = _TYPE_RE.findall(out)
    installers = []
    for i, url in enumerate(urls):
        installers.append({
            "url": url.strip(),
            "sha256": (hashes[i] if i < len(hashes) else "").lower(),
            "type": types[i] if i < len(types) else "",
        })
    return {"id": pkg_id, "installers": installers}


def _download(url: str, dest_dir: Path, max_mb: int = 400) -> Optional[Path]:
    parsed = urllib.parse.urlparse(url)
    fname = os.path.basename(parsed.path) or "download.bin"
    fname = re.sub(r'[<>:"|?*]', "_", fname)
    dest = dest_dir / fname
    if dest.exists() and dest.stat().st_size > 100:
        return dest
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            clen = resp.headers.get("Content-Length")
            if clen and int(clen) > max_mb * 1024 * 1024:
                return None
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except Exception:
        return None
    return dest


def _extract_sys(archive: Path, out_dir: Path) -> list[Path]:
    """Best-effort: try native zip first, then 7z if installed, then PE-resource
    extraction (delegated to driverscope.harvester if present)."""
    found: list[Path] = []
    suffix = archive.suffix.lower()

    # ZIP
    if suffix in (".zip",):
        try:
            import zipfile
            with zipfile.ZipFile(archive) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".sys"):
                        target = out_dir / Path(name).name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(name) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        found.append(target)
        except Exception:
            pass

    # 7z / arbitrary installer
    if not found and shutil.which("7z"):
        with tempfile.TemporaryDirectory() as td:
            rc, _, _ = _run(["7z", "x", "-y", f"-o{td}", str(archive)], timeout=180)
            if rc == 0:
                for root, _, files in os.walk(td):
                    for fn in files:
                        if fn.lower().endswith(".sys"):
                            src_p = Path(root) / fn
                            dest = out_dir / fn
                            try:
                                shutil.copy2(src_p, dest)
                                found.append(dest)
                            except Exception:
                                pass

    # PE resource extraction (CPU-Z / HWMonitor pattern)
    if not found:
        try:
            from driverscope.harvester import _extract_pe_resources
            res_found = _extract_pe_resources(archive, out_dir)
            if isinstance(res_found, list):
                found.extend(res_found)
        except Exception:
            pass

    return found


def harvest(queries: Iterable[str] = DEFAULT_QUERIES,
            out_dir: Path = DEFAULT_OUT,
            limit_per_query: int = 20,
            include_ids: Optional[list[str]] = None) -> dict:
    """Search → show → download → extract. Returns a manifest dict."""
    if not have_winget():
        return {"error": "winget not installed", "sys_found": []}

    out_dir.mkdir(parents=True, exist_ok=True)
    staging = out_dir / STAGING_SUBDIR
    staging.mkdir(parents=True, exist_ok=True)
    drivers_out = out_dir / "drivers"
    drivers_out.mkdir(parents=True, exist_ok=True)

    manifest: dict = {"queries": [], "downloads": [], "sys_found": []}

    seen_ids: set[str] = set()
    package_ids: list[dict] = []

    for q in queries:
        pkgs = search(q, limit=limit_per_query)
        manifest["queries"].append({"query": q, "hits": len(pkgs)})
        for pkg in pkgs:
            if pkg["id"] in seen_ids:
                continue
            seen_ids.add(pkg["id"])
            package_ids.append(pkg)

    if include_ids:
        for pid in include_ids:
            if pid not in seen_ids:
                package_ids.append({"id": pid, "name": pid})
                seen_ids.add(pid)

    for pkg in package_ids:
        info = show(pkg["id"])
        for inst in info["installers"]:
            url = inst.get("url", "")
            if not url:
                continue
            archive = _download(url, staging)
            manifest["downloads"].append({
                "id": pkg["id"], "url": url,
                "downloaded": bool(archive), "path": str(archive) if archive else "",
            })
            if not archive:
                continue
            sysfiles = _extract_sys(archive, drivers_out)
            for s in sysfiles:
                manifest["sys_found"].append({
                    "id": pkg["id"], "url": url, "sys": str(s),
                })

    with open(out_dir / "winget_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Winget catalog walk for BYOVD sourcing")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    ap.add_argument("--query", action="append", default=[],
                    help="Extra search query (repeat).")
    ap.add_argument("--id", action="append", default=[],
                    help="Explicit winget package id (repeat).")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    queries = list(DEFAULT_QUERIES) + (args.query or [])
    m = harvest(queries=queries, out_dir=Path(args.out),
                limit_per_query=args.limit, include_ids=args.id or None)
    print(f"[winget] queries={len(m.get('queries', []))} "
          f"downloads={len(m.get('downloads', []))} "
          f".sys extracted={len(m.get('sys_found', []))}")
