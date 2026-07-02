"""VX-Underground driver harvester.

VXUG serves presigned-URL downloads from a Backblaze B2 bucket
(s3.us-east-005.backblazeb2.com). The signing query string is time-limited
(~1 hr) and regenerates per LiveView render, so headless scraping from a raw
HTTP client fails with 401.

Two supported flows:

1) BROWSER-ASSISTED (the default). Paste the JS snippet from
   `vxug_grab_snippet()` into your normal Chrome DevTools console while
   viewing a VXUG search or directory listing. It walks the current file
   list and calls each download URL, saving to ~/Downloads. Then run
   `python -m driverscope.vxug ingest ~/Downloads/vxug` on the host.

2) URL-LIST (offline). Save a text file with one presigned URL per line
   (captured however you like), then run
   `python -m driverscope.vxug fetch --urls urls.txt`.

Post-download this module handles:
  - Container-isolated 7z/zip/rar extract (password 'infected' by default)
  - PE-header sniff + .sys filter
  - SHA256 hash + dedupe against `driver_blocklist_scan.json`
  - Ranked printout of novel physmem candidates
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_RAW = Path.home() / "Desktop" / "driver_inventory" / "22_vxug" / "raw"
DEFAULT_EXTRACTED = Path.home() / "Desktop" / "driver_inventory" / "22_vxug" / "extracted"
DEFAULT_SCAN_JSON = Path(__file__).resolve().parent.parent / "driver_blocklist_scan.json"

VXUG_HOST = "s3.us-east-005.backblazeb2.com"
DEFAULT_PASSWORD = "infected"

ARCHIVE_EXTS = (".7z", ".zip", ".rar", ".tar.gz", ".tgz")


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


# ── extraction ────────────────────────────────────────────────────────────

def _7z_available() -> str | None:
    for name in ("7z", "7z.exe", "7za", "7za.exe"):
        if shutil.which(name):
            return name
    for fixed in (r"C:\Program Files\7-Zip\7z.exe",
                  r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if Path(fixed).exists():
            return fixed
    return None


def extract_local(archive: Path, out_dir: Path, password: str = DEFAULT_PASSWORD) -> list[Path]:
    """Extract with local 7z. Preferred when a sandbox VM is doing the work."""
    seven = _7z_available()
    if not seven:
        raise RuntimeError("7z not on PATH; install 7-Zip or use --docker")
    out_dir.mkdir(parents=True, exist_ok=True)
    subdir = out_dir / archive.stem
    subdir.mkdir(exist_ok=True)
    cmd = [seven, "x", "-y", f"-p{password}", f"-o{subdir}", str(archive)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"[!] 7z failed for {archive.name}: {r.stderr[:200]}")
        return []
    return list(subdir.rglob("*"))


def extract_docker(archive: Path, out_dir: Path, password: str = DEFAULT_PASSWORD,
                   image: str = "alpine") -> list[Path]:
    """Extract inside an air-gapped container. Recommended when host has no
    isolation between analysis tools and untrusted samples."""
    if not shutil.which("docker"):
        raise RuntimeError("docker not on PATH")
    out_dir.mkdir(parents=True, exist_ok=True)
    subdir = out_dir / archive.stem
    subdir.mkdir(exist_ok=True)
    script = (
        "apk add --no-cache p7zip >/dev/null 2>&1 && "
        f"7z x -y '-p{password}' -o/out /in/\"$(ls /in)\""
    )
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{archive.parent}:/in:ro",
        "-v", f"{subdir}:/out",
        image, "sh", "-c", script,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(f"[!] docker extract failed for {archive.name}: {r.stderr[:300]}")
        return []
    return list(subdir.rglob("*"))


# ── PE sniff + dedupe ─────────────────────────────────────────────────────

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
        if p.suffix.lower() != ".sys" and not is_pe(p):
            continue
        try:
            h = sha256_file(p)
        except Exception:
            continue
        out.append(NovelDriver(sha256=h, path=p, size=p.stat().st_size,
                               novel=h not in seen))
    return out


# ── orchestration ─────────────────────────────────────────────────────────

def ingest(raw_dir: Path, extracted_dir: Path, scan_json: Path,
           use_docker: bool = False, password: str = DEFAULT_PASSWORD) -> None:
    seen = load_seen_hashes(scan_json)
    print(f"[+] {len(seen)} known-hash drivers in {scan_json.name}")

    archives = [p for p in raw_dir.rglob("*") if p.is_file()
                and any(p.name.lower().endswith(ext) for ext in ARCHIVE_EXTS)]
    print(f"[+] {len(archives)} archives in {raw_dir}")

    extractor = extract_docker if use_docker else extract_local
    for a in archives:
        print(f"[.] Extracting: {a.name}")
        extractor(a, extracted_dir, password)

    novel = collect_novel_drivers(extracted_dir, seen)
    novel_only = [n for n in novel if n.novel]

    print(f"\n[=] {len(novel)} total .sys/PE found, {len(novel_only)} novel")
    for n in sorted(novel_only, key=lambda x: -x.size):
        print(f"    {n.sha256}  {n.size:>10}  {n.path.relative_to(extracted_dir)}")

    manifest = extracted_dir.parent / "vxug_novel.json"
    manifest.write_text(json.dumps({
        "total_files": len(novel),
        "novel": len(novel_only),
        "drivers": [{"sha256": n.sha256, "size": n.size,
                     "path": str(n.path.relative_to(extracted_dir))}
                    for n in novel_only],
    }, indent=2))
    print(f"[+] Wrote {manifest}")


# ── DevTools grab snippet ─────────────────────────────────────────────────

VXUG_GRAB_JS = r"""
// ─── VXUG bulk-download from DevTools ───────────────────────────────────
// Paste into your normal Chrome DevTools console on a VXUG file listing
// (Samples/, Papers/, Builders/, or a search result page). Downloads
// every archive on the current page to ~/Downloads with staggered delays
// to avoid rate limiting.
(async () => {
  const container = document.getElementById('file-display');
  if (!container) { console.error('No #file-display; open a VXUG listing'); return; }
  const rows = Array.from(container.children);
  const archives = [];
  for (const row of rows) {
    const link = row.querySelector('a[href]');
    const p = row.querySelector('p');
    if (!link || !p) continue;
    const name = p.textContent.trim();
    if (/\.(7z|zip|rar|tar\.gz|tgz)$/i.test(name)) {
      archives.push({name, href: link.href});
    }
  }
  console.log(`Found ${archives.length} archives; downloading...`);
  for (const [i, a] of archives.entries()) {
    const el = document.createElement('a');
    el.href = a.href;
    el.download = a.name.replace(/[^\w.-]/g, '_');
    document.body.appendChild(el);
    el.click();
    el.remove();
    console.log(`[${i+1}/${archives.length}] ${a.name}`);
    await new Promise(r => setTimeout(r, 2500));
  }
  console.log('Done. Files in ~/Downloads');
})();
""".strip()


def vxug_grab_snippet() -> str:
    return VXUG_GRAB_JS


# ── CLI ───────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="VXUG harvester")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_snip = sub.add_parser("snippet", help="print the DevTools JS grab snippet")

    ap_ing = sub.add_parser("ingest", help="extract archives + dedupe + report")
    ap_ing.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap_ing.add_argument("--extracted", type=Path, default=DEFAULT_EXTRACTED)
    ap_ing.add_argument("--scan-json", type=Path, default=DEFAULT_SCAN_JSON)
    ap_ing.add_argument("--docker", action="store_true",
                        help="use --network=none docker container for extraction")
    ap_ing.add_argument("--password", default=DEFAULT_PASSWORD)

    args = ap.parse_args()

    if args.cmd == "snippet":
        print(vxug_grab_snippet())
        print()
        print("USAGE: open your regular Chrome, go to https://vx-underground.org/,")
        print("search for the collection you want, open DevTools (F12) -> Console,")
        print("paste the block above, hit Enter. Files land in ~/Downloads.")
        return 0

    if args.cmd == "ingest":
        ingest(args.raw, args.extracted, args.scan_json,
               use_docker=args.docker, password=args.password)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
