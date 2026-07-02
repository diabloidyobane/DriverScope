"""Local corpus expansion. Collect .sys candidates from every directory that
Windows can load a driver from, plus every common vendor tool install path.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# -- default roots --------------------------------------------------------

def _sysroot() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows"))


def _programfiles() -> list[Path]:
    out: list[Path] = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        v = os.environ.get(env)
        if v:
            p = Path(v)
            if p.exists() and p not in out:
                out.append(p)
    return out


def _programdata() -> Optional[Path]:
    v = os.environ.get("ProgramData")
    return Path(v) if v and Path(v).exists() else None


def _localappdata() -> Optional[Path]:
    v = os.environ.get("LOCALAPPDATA")
    return Path(v) if v and Path(v).exists() else None


# -- roots by category ----------------------------------------------------

SYSTEM_ROOTS = [
    r"System32\drivers",
    r"SysWOW64\drivers",
    r"System32\DriverStore\FileRepository",
    r"WinSxS",
    r"SoftwareDistribution\Download",
    r"servicing\Packages",
    r"INF",
]

# Common vendor-tool install roots. Not exhaustive; the harvester feeds these too.
VENDOR_HINT_DIRS = [
    r"Corsair",
    r"Corsair CUE",
    r"CORSAIR iCUE Software",
    r"NZXT CAM",
    r"Razer",
    r"Logitech",
    r"SteelSeries",
    r"MSI",
    r"MSI Center",
    r"MSI Afterburner",
    r"NVIDIA",
    r"NVIDIA Corporation",
    r"AMD",
    r"ATI Technologies",
    r"Intel",
    r"Intel Corporation",
    r"Realtek",
    r"ASUS",
    r"ASUSTeK",
    r"ASUSTek Computer",
    r"ASRock",
    r"Gigabyte",
    r"CPUID",
    r"HWMonitor",
    r"HWiNFO64",
    r"AIDA64",
    r"OCCT",
    r"CoreTemp",
    r"Speccy",
    r"Piriform",
    r"CrystalDiskInfo",
    r"CrystalDiskMark",
    r"Samsung",
    r"Samsung_Magician",
    r"Western Digital",
    r"WD Dashboard",
    r"Kingston",
    r"Crucial",
    r"Storage Executive",
    r"Seagate",
    r"OpenHardwareMonitor",
    r"LibreHardwareMonitor",
    r"OpenRGB",
    r"Wallpaper Engine",
    r"Steam\steamapps\common\wallpaper_engine",
    r"RivaTuner",
    r"MSI Afterburner",
    r"ThrottleStop",
    r"Passmark",
    r"Passmark Software",
    r"Dell",
    r"Dell OpenManage",
    r"HP",
    r"Hewlett-Packard",
    r"HPE",
    r"Supermicro",
    r"IPMICFG",
    r"SolarWinds",
    r"Broadcom",
    r"Emulex",
    r"Marvell",
    r"WCH",
    r"Silicon Labs",
    r"FTDI",
    r"CH341",
    r"WinRing0",
    r"RWEverything",
    r"RW-Everything",
]


# -- default excludes -----------------------------------------------------

_EXCLUDE_NAME = re.compile(
    r"(?:^symsrv[.]|"                     # symbol server helper drivers
    r"^(?:hidusb|hidclass|hidparse|ndis|"  # very common OS drivers with high FP rate
    r"tcpip|http|afd|null|ksecdd)\.sys$)",
    re.IGNORECASE,
)


@dataclass
class Corpus:
    roots: list[Path] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    excluded_count: int = 0


def _iter_sys(root: Path, follow_symlinks: bool = False) -> Iterable[Path]:
    """os.walk-style .sys iteration; skips reparse points to avoid infinite loops."""
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
            for fn in filenames:
                if fn.lower().endswith(".sys"):
                    yield Path(dirpath) / fn
    except (PermissionError, OSError):
        return


def build(
    include_system: bool = True,
    include_program_files: bool = True,
    include_programdata: bool = False,
    include_localappdata: bool = False,
    include_wu_staged: bool = True,
    extra_roots: Optional[list[str | Path]] = None,
    exclude_default: bool = True,
    dedup_by_name: bool = False,
) -> Corpus:
    """Build a corpus of .sys paths from the requested roots.

    - include_system: %SystemRoot% subtrees (drivers, DriverStore, WinSxS, etc.)
    - include_program_files: Program Files / Program Files (x86) vendor tool dirs
    - include_wu_staged: WU-staged driver payloads (SoftwareDistribution\\Download)
    - include_programdata: %ProgramData% subtree (per-machine vendor caches)
    - include_localappdata: %LOCALAPPDATA% subtree (per-user tool caches)
    - extra_roots: absolute paths to include verbatim
    - exclude_default: drop obviously-OS drivers that trigger too many false positives
    - dedup_by_name: keep only the first path seen per filename (fast scan mode)
    """
    corpus = Corpus()
    roots: list[Path] = []
    sysroot = _sysroot()

    if include_system:
        for rel in SYSTEM_ROOTS:
            p = sysroot / rel
            if p.exists():
                roots.append(p)

    if not include_wu_staged:
        roots = [p for p in roots
                 if p.name.lower() != "download"
                 or "softwaredistribution" not in str(p).lower()]

    if include_program_files:
        for pf in _programfiles():
            roots.append(pf)  # scan all PF for .sys
            for hint in VENDOR_HINT_DIRS:
                cand = pf / hint
                if cand.exists() and cand not in roots:
                    roots.append(cand)

    if include_programdata:
        pd = _programdata()
        if pd:
            roots.append(pd)

    if include_localappdata:
        lad = _localappdata()
        if lad:
            roots.append(lad)

    if extra_roots:
        for r in extra_roots:
            p = Path(r)
            if p.exists():
                roots.append(p)

    # de-duplicate roots by resolved path
    seen_roots: set[Path] = set()
    dedup_roots: list[Path] = []
    for r in roots:
        try:
            rk = r.resolve()
        except OSError:
            rk = r
        if rk in seen_roots:
            continue
        seen_roots.add(rk)
        dedup_roots.append(rk)
    corpus.roots = dedup_roots

    # collect files
    seen_files: set[Path] = set()
    seen_names: set[str] = set()
    for r in dedup_roots:
        for p in _iter_sys(r):
            try:
                p_res = p.resolve()
            except OSError:
                p_res = p
            if p_res in seen_files:
                continue
            if exclude_default and _EXCLUDE_NAME.search(p_res.name):
                corpus.excluded_count += 1
                continue
            if dedup_by_name:
                if p_res.name.lower() in seen_names:
                    continue
                seen_names.add(p_res.name.lower())
            seen_files.add(p_res)
            corpus.files.append(p_res)

    return corpus


def cli_summary(c: Corpus) -> str:
    lines = [
        f"corpus: {len(c.files)} .sys files across {len(c.roots)} roots",
    ]
    for r in c.roots[:12]:
        lines.append(f"  root: {r}")
    if len(c.roots) > 12:
        lines.append(f"  ... and {len(c.roots) - 12} more")
    if c.excluded_count:
        lines.append(f"  excluded {c.excluded_count} well-known OS drivers")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Enumerate the DriverScope local corpus")
    ap.add_argument("--no-system", action="store_true")
    ap.add_argument("--no-program-files", action="store_true")
    ap.add_argument("--no-wu-staged", action="store_true")
    ap.add_argument("--programdata", action="store_true")
    ap.add_argument("--localappdata", action="store_true")
    ap.add_argument("--include-common", action="store_true",
                    help="Do not drop common OS drivers from the corpus")
    ap.add_argument("--dedup-by-name", action="store_true")
    ap.add_argument("--extra", action="append", default=[])
    args = ap.parse_args()

    c = build(
        include_system=not args.no_system,
        include_program_files=not args.no_program_files,
        include_wu_staged=not args.no_wu_staged,
        include_programdata=args.programdata,
        include_localappdata=args.localappdata,
        extra_roots=args.extra,
        exclude_default=not args.include_common,
        dedup_by_name=args.dedup_by_name,
    )
    print(cli_summary(c))
    for p in c.files[:50]:
        print(f"  {p}")
    if len(c.files) > 50:
        print(f"  ... and {len(c.files) - 50} more")
