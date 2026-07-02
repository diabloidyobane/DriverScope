"""Download OEM utilities and extract kernel drivers for scanning.

Base SOURCES covers 10 well-known hardware monitoring tools.
Sub-modules add ~55 vendor-specific targets across sysinfo, RGB,
storage, BMC, Chinese forums, VPN, and OEM BIOS/firmware utilities.
"""

import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
import tarfile
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlparse, unquote

from .sysinfo import SOURCES as SYSINFO
from .rgb import SOURCES as RGB
from .storage import SOURCES as STORAGE
from .bmc import SOURCES as BMC
from .cn import SOURCES as CN
from .vpn import SOURCES as VPN
from .oem import SOURCES as OEM

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
GITHUB_API = "https://api.github.com"


SOURCES = [
    {
        "name": "LibreHardwareMonitor",
        "category": "hwmon",
        "type": "github",
        "repo": "LibreHardwareMonitor/LibreHardwareMonitor",
        "asset_pattern": r"LibreHardwareMonitor.*\.zip$",
        "notes": "Bundles WinRing0x64.sys for MSR/physmem",
    },
    {
        "name": "OpenHardwareMonitor",
        "category": "hwmon",
        "type": "direct",
        "urls": ["https://openhardwaremonitor.org/files/openhardwaremonitor-v0.9.6.zip"],
        "notes": "Bundles WinRing0x64.sys",
    },
    {
        "name": "FanControl",
        "category": "fan",
        "type": "github",
        "repo": "Rem0o/FanControl.Releases",
        "asset_pattern": r"FanControl.*\.zip$",
        "notes": "Fan controller, embeds LibreHW driver",
    },
    {
        "name": "OpenRGB",
        "category": "peripheral",
        "type": "github",
        "repo": "CalcProgrammer1/OpenRGB",
        "asset_pattern": r"OpenRGB.*Windows.*64",
        "notes": "RGB controller, bundles SMBus/I2C/inpout driver",
    },
    {
        "name": "NoteBook_FanControl",
        "category": "fan",
        "type": "github",
        "repo": "hirschmann/nbfc",
        "asset_pattern": r"NoteBookFanControl.*\.(zip|exe)$",
        "notes": "Notebook fan control, EC access driver",
    },
    {
        "name": "ThrottleStop",
        "category": "tuning",
        "type": "direct",
        "urls": ["https://www.techpowerup.com/download/techpowerup-throttlestop/"],
        "notes": "CPU undervolt tool, bundles MSR access driver",
    },
    {
        "name": "HWiNFO",
        "category": "hwmon",
        "type": "direct",
        "urls": ["https://www.hwinfo.com/files/hwi_latest.zip"],
        "notes": "Hardware monitor, bundles physmem/MSR driver",
    },
    {
        "name": "CPU-Z",
        "category": "hwmon",
        "type": "direct",
        "urls": ["https://download.cpuid.com/cpu-z/cpu-z_latest-en.zip"],
        "notes": "CPU info, bundles cpuz141_x64.sys",
    },
    {
        "name": "GPU-Z",
        "category": "hwmon",
        "type": "direct",
        "urls": ["https://www.techpowerup.com/download/techpowerup-gpu-z/"],
        "notes": "GPU info, bundles physmem driver",
    },
    {
        "name": "AIDA64",
        "category": "hwmon",
        "type": "direct",
        "urls": [],
        "notes": "System info, bundles aida64.sys (commercial, manual download)",
    },
]

EXTRA_SOURCES = SYSINFO + RGB + STORAGE + BMC + CN + VPN + OEM

ALL_SOURCES = SOURCES + EXTRA_SOURCES

__all__ = [
    "SOURCES", "EXTRA_SOURCES", "ALL_SOURCES",
    "SYSINFO", "RGB", "STORAGE", "BMC", "CN", "VPN", "OEM",
    "harvest",
]


def _github_latest_release(repo: str) -> list[dict]:
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    req = Request(url)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/vnd.github.v3+json")

    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        req.add_header("Authorization", f"token {gh_token}")

    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data.get("assets", [])
    except Exception as e:
        print(f"  [GitHub] {repo}: {e}", file=sys.stderr)
        return []


def _download_file(url: str, dest: Path) -> bool:
    req = Request(url)
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urlopen(req, timeout=120) as resp:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
        return True
    except Exception as e:
        print(f"  [Download] {url}: {e}", file=sys.stderr)
        return False


def _extract_sys_files(archive_path: Path, output_dir: Path) -> list[Path]:
    extracted = []
    output_dir.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        try:
            with zipfile.ZipFile(archive_path) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".sys"):
                        basename = Path(name).name
                        dest = output_dir / basename
                        with zf.open(name) as src, open(dest, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        extracted.append(dest)
        except Exception as e:
            print(f"  [Extract] ZIP error: {e}", file=sys.stderr)

    elif tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path) as tf:
                for member in tf.getmembers():
                    if member.name.lower().endswith(".sys"):
                        member.name = Path(member.name).name
                        tf.extract(member, output_dir)
                        extracted.append(output_dir / member.name)
        except Exception as e:
            print(f"  [Extract] TAR error: {e}", file=sys.stderr)

    return extracted


def _extract_pe_resources(pe_path: Path, output_dir: Path) -> list[Path]:
    try:
        import pefile
    except ImportError:
        return []

    extracted = []
    try:
        pe = pefile.PE(str(pe_path))
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            pe.close()
            return []

        output_dir.mkdir(parents=True, exist_ok=True)
        for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for rsrc_id in getattr(rsrc_type, "directory", {}).entries if hasattr(rsrc_type, "directory") else []:
                for rsrc_lang in getattr(rsrc_id, "directory", {}).entries if hasattr(rsrc_id, "directory") else []:
                    try:
                        data = pe.get_data(rsrc_lang.data.struct.OffsetToData,
                                           rsrc_lang.data.struct.Size)
                        if data[:2] == b"MZ":
                            name = f"resource_{rsrc_id.id or 'unknown'}.sys"
                            dest = output_dir / name
                            dest.write_bytes(data)
                            extracted.append(dest)
                    except Exception:
                        pass
        pe.close()
    except Exception:
        pass

    return extracted


def harvest(output_dir: str, categories: list[str] = None,
            extra: bool = True) -> dict:
    """Download and extract .sys files from vendor tool archives.

    Args:
        output_dir: Where to store downloads and extracted drivers.
        categories: Filter to these categories only (None = all).
        extra: Include EXTRA_SOURCES sub-module targets (default True).
    """
    sources = ALL_SOURCES if extra else SOURCES

    out = Path(output_dir)
    staging = out / "_staging"
    drivers_dir = out / "drivers"
    staging.mkdir(parents=True, exist_ok=True)
    drivers_dir.mkdir(parents=True, exist_ok=True)

    seen_path = out / "seen_hashes.json"
    seen: set[str] = set()
    if seen_path.exists():
        try:
            seen = set(json.loads(seen_path.read_text()))
        except Exception:
            pass

    total_downloaded = 0
    total_extracted = 0
    all_drivers: list[Path] = []

    for source in sources:
        if categories and source["category"] not in categories:
            continue

        name = source["name"]
        print(f"\n  [{name}] {source.get('notes', '')}", file=sys.stderr)

        download_urls = []

        if source["type"] == "github":
            assets = _github_latest_release(source["repo"])
            pattern = re.compile(source.get("asset_pattern", ".*"))
            for asset in assets:
                if pattern.search(asset.get("name", "")):
                    download_urls.append(asset["browser_download_url"])
        elif source["type"] == "direct":
            download_urls = source.get("urls", [])

        for url in download_urls:
            if not url:
                continue
            filename = unquote(urlparse(url).path.split("/")[-1])
            dest = staging / f"{name}_{filename}"

            if dest.exists():
                print(f"    Already downloaded: {dest.name}", file=sys.stderr)
            else:
                print(f"    Downloading: {url[:80]}...", file=sys.stderr)
                if _download_file(url, dest):
                    total_downloaded += 1

            extracted = _extract_sys_files(dest, drivers_dir)
            if not extracted and dest.suffix.lower() in (".exe", ".msi"):
                extracted = _extract_pe_resources(dest, drivers_dir)

            for drv in extracted:
                h = hashlib.sha256(drv.read_bytes()).hexdigest()
                if h not in seen:
                    seen.add(h)
                    all_drivers.append(drv)
                    total_extracted += 1
                    print(f"    Extracted: {drv.name} ({h[:16]}...)",
                          file=sys.stderr)

    try:
        seen_path.write_text(json.dumps(sorted(seen), indent=2))
    except Exception:
        pass

    summary = {
        "downloaded": total_downloaded,
        "extracted": total_extracted,
        "drivers": [str(d) for d in all_drivers],
        "output_dir": str(drivers_dir),
    }

    print(f"\n  Harvest complete: {total_downloaded} downloaded, "
          f"{total_extracted} new drivers extracted to {drivers_dir}",
          file=sys.stderr)

    return summary
