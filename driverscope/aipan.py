"""爱盘 (down.52pojie.cn) driver harvester.

52pojie's 爱盘 is a public file mirror of RE/security tools. The
Anti_Rootkit directory ships 24+ tools, nearly all containing signed
kernel drivers. Downloads are direct HTTP with no authentication.

Archive password: www.52pojie.cn
Rate limit: single-thread only (multi-thread gets IP-banned).

Usage:
    python -m driverscope.aipan fetch           # download Anti_Rootkit archives
    python -m driverscope.aipan fetch --all      # download all Tools/* directories
    python -m driverscope.aipan ingest           # extract + dedupe + report
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

BASE_URL = "https://down.52pojie.cn"
DEFAULT_PASSWORD = "www.52pojie.cn"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) driverscope/0.1"

TOOL_DIRS = [
    "Anti_Rootkit",
    "Debuggers",
    "Network_Analyzer",
    "PEtools",
    "Other",
]

ARCHIVE_EXTS = (".7z", ".zip", ".rar", ".tar.gz", ".tgz", ".exe")

DEFAULT_RAW = Path.home() / "Desktop" / "driver_inventory" / "23_aipan" / "raw"
DEFAULT_EXTRACTED = Path.home() / "Desktop" / "driver_inventory" / "23_aipan" / "extracted"
DEFAULT_SCAN_JSON = Path(__file__).resolve().parent.parent / "driver_blocklist_scan.json"

FETCH_DELAY = 3.0


@dataclass
class NovelDriver:
    sha256: str
    path: Path
    size: int
    novel: bool


def load_seen_hashes(scan_json: Path) -> set[str]:
    if not scan_json.exists():
        return set()
    data = json.loads(scan_json.read_text(encoding="utf-8"))
    return {d["sha256"].lower() for d in data.get("drivers", [])}


# ── directory listing parser ─────────────────────────────────────────────

def list_files(directory_url: str) -> list[dict]:
    """Parse the Apache/nginx autoindex or Vue file listing at a directory URL.
    Returns list of {name, size, url}."""
    req = urllib.request.Request(directory_url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    files = []
    for m in re.finditer(r'<a\s+href="([^"]+)"[^>]*>\s*([^<]+)</a>', body):
        href, text = m.group(1), m.group(2).strip()
        if href.startswith("?") or href == "../" or href.endswith("/"):
            continue
        name = html.unescape(text) if text else urllib.parse.unquote(href)
        full = urllib.parse.urljoin(directory_url, href)
        files.append({"name": name, "url": full})
    return files


# ── download ─────────────────────────────────────────────────────────────

def download_file(url: str, out_dir: Path, delay: float = FETCH_DELAY) -> Path | None:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = urllib.parse.unquote(url.rsplit("/", 1)[-1])
    dest = out_dir / name
    if dest.exists():
        print(f"  [skip] {name} (already downloaded)")
        return dest

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        dest.write_bytes(data)
        size_mb = len(data) / (1024 * 1024)
        print(f"  [ok] {name} ({size_mb:.1f} MB)")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"  [!] {name}: {e}")
        return None

    if delay > 0:
        time.sleep(delay)
    return dest


def fetch_directory(tool_dir: str, out_dir: Path, delay: float = FETCH_DELAY) -> list[Path]:
    url = f"{BASE_URL}/Tools/{tool_dir}/"
    print(f"[+] Listing {url}")
    try:
        entries = list_files(url)
    except Exception as e:
        print(f"  [!] Failed to list: {e}")
        return []

    print(f"  {len(entries)} files found")
    downloaded = []
    subdir = out_dir / tool_dir
    for entry in entries:
        path = download_file(entry["url"], subdir, delay)
        if path:
            downloaded.append(path)
    return downloaded


# ── extraction ───────────────────────────────────────────────────────────

def _7z_available() -> str | None:
    for name in ("7z", "7z.exe", "7za", "7za.exe"):
        if shutil.which(name):
            return name
    for fixed in (r"C:\Program Files\7-Zip\7z.exe",
                  r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(fixed).exists():
            return fixed
    return None


def extract(archive: Path, out_dir: Path, password: str = DEFAULT_PASSWORD) -> list[Path]:
    seven = _7z_available()
    if not seven:
        raise RuntimeError("7z not on PATH")
    out_dir.mkdir(parents=True, exist_ok=True)
    subdir = out_dir / archive.stem
    subdir.mkdir(exist_ok=True)

    passwords = [password, "infected", ""]
    for pw in passwords:
        cmd = [seven, "x", "-y", f"-p{pw}", f"-o{subdir}", str(archive)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return list(subdir.rglob("*"))

    print(f"  [!] extraction failed for {archive.name}")
    return []


# ── PE sniff + dedupe ────────────────────────────────────────────────────

def is_pe(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_off = int.from_bytes(f.read(4), "little")
            f.seek(pe_off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_novel_drivers(extracted_root: Path, seen: set[str]) -> list[NovelDriver]:
    out: list[NovelDriver] = []
    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".sys", ".dll", ".exe"):
            if not is_pe(p):
                continue
        if p.suffix.lower() == ".sys" or is_pe(p):
            try:
                h = sha256_file(p)
            except Exception:
                continue
            out.append(NovelDriver(sha256=h, path=p, size=p.stat().st_size,
                                   novel=h not in seen))
    return out


# ── orchestration ────────────────────────────────────────────────────────

def fetch(dirs: list[str], raw_dir: Path, delay: float = FETCH_DELAY) -> None:
    print(f"[+] Fetching {len(dirs)} directories to {raw_dir}")
    for d in dirs:
        fetch_directory(d, raw_dir, delay)


def ingest(raw_dir: Path, extracted_dir: Path, scan_json: Path,
           password: str = DEFAULT_PASSWORD) -> None:
    seen = load_seen_hashes(scan_json)
    print(f"[+] {len(seen)} known hashes from {scan_json.name}")

    archives = [p for p in raw_dir.rglob("*") if p.is_file()
                and any(p.name.lower().endswith(ext)
                        for ext in (".7z", ".zip", ".rar", ".tar.gz", ".tgz"))]
    standalones = [p for p in raw_dir.rglob("*.exe") if p.is_file()]
    print(f"[+] {len(archives)} archives + {len(standalones)} standalone .exe in {raw_dir}")

    for a in archives:
        print(f"[.] Extracting: {a.name}")
        extract(a, extracted_dir, password)

    for exe in standalones:
        dest = extracted_dir / exe.stem
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / exe.name
        if not target.exists():
            shutil.copy2(exe, target)

    novel = collect_novel_drivers(extracted_dir, seen)
    novel_only = [n for n in novel if n.novel]
    sys_only = [n for n in novel_only if n.path.suffix.lower() == ".sys"]

    print(f"\n[=] {len(novel)} total PE found, {len(novel_only)} novel, {len(sys_only)} novel .sys")
    for n in sorted(sys_only, key=lambda x: -x.size):
        try:
            rel = n.path.relative_to(extracted_dir)
        except ValueError:
            rel = n.path
        print(f"    {n.sha256}  {n.size:>10}  {rel}")

    manifest = raw_dir.parent / "aipan_novel.json"
    manifest.write_text(json.dumps({
        "source": "down.52pojie.cn/Tools",
        "total_pe": len(novel),
        "novel": len(novel_only),
        "novel_sys": len(sys_only),
        "drivers": [{"sha256": n.sha256, "size": n.size,
                     "path": str(n.path.name), "novel": n.novel}
                    for n in novel if n.path.suffix.lower() == ".sys"],
    }, indent=2))
    print(f"[+] Wrote {manifest}")


# ── CLI ──────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="爱盘 (52pojie) harvester")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_fetch = sub.add_parser("fetch", help="download tool archives from 爱盘")
    ap_fetch.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap_fetch.add_argument("--all", action="store_true",
                          help="download all TOOL_DIRS, not just Anti_Rootkit")
    ap_fetch.add_argument("--dirs", nargs="+", default=None,
                          help="specific directories to fetch (e.g. Anti_Rootkit Debuggers)")
    ap_fetch.add_argument("--delay", type=float, default=FETCH_DELAY)

    ap_ing = sub.add_parser("ingest", help="extract + dedupe + report")
    ap_ing.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap_ing.add_argument("--extracted", type=Path, default=DEFAULT_EXTRACTED)
    ap_ing.add_argument("--scan-json", type=Path, default=DEFAULT_SCAN_JSON)
    ap_ing.add_argument("--password", default=DEFAULT_PASSWORD)

    args = ap.parse_args()

    if args.cmd == "fetch":
        dirs = args.dirs or (TOOL_DIRS if args.all else ["Anti_Rootkit"])
        fetch(dirs, args.raw, args.delay)
        print("\n[+] Done. Run 'python -m driverscope.aipan ingest' next.")
        return 0

    if args.cmd == "ingest":
        ingest(args.raw, args.extracted, args.scan_json, args.password)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
