"""Zero-day hunter — find vulnerable signed drivers BEFORE they appear in public databases.

Scans local system directories and user-specified paths, runs import triage,
filters out everything already documented (LOLDrivers, MS blocklist, KDU),
and ranks remaining NOVEL candidates by exploitability.
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .scanner import (
    scan_driver, DriverResult, PRIMITIVE_CLASSES, _IMPORT_TO_CLASSES,
    build_lol_index, enrich_with_lol, fetch_ms_blocklist, enrich_with_blocklist,
    sha256_file,
)

try:
    from .ioctl import extract_ioctl_surface
    HAS_IOCTL = True
except ImportError:
    HAS_IOCTL = False


# ---------------------------------------------------------------------------
# Known-driver fingerprints (community-known, not necessarily in LOLDrivers)
# ---------------------------------------------------------------------------

KNOWN_KDU_NAMES = {
    "alsysio64.sys", "amdryzenmaster", "aoddriver.sys", "atszio.sys",
    "asio2.sys", "asio3.sys", "asrdrv106.sys", "asrdrv107.sys",
    "axtudrv.sys", "dbutil23.sys", "dbutildrv2.sys", "directio64.sys",
    "echoDrv.sys", "eneio64.sys", "enetchio64.sys", "etdsupport.sys",
    "gdrv.sys", "glckio2.sys", "hw64.sys", "hwrwdrv.x64.sys",
    "inpoutx64.sys", "irec.sys", "kexplore.sys", "kobjexp.sys",
    "kprocesshacker.sys", "kregexp.sys", "lecomax.sys", "lha.sys",
    "lnvmsrio.sys", "mimidrv.sys", "msio64.sys", "naldrv.sys",
    "nvoclock.sys", "physmem.sys", "procexp.sys", "rtcore64.sys",
    "speedfan.sys", "winio64.sys", "winring0x64.sys", "zemana.sys",
}

MS_INBOX_PREFIXES = {
    "acpi", "ahci", "afd", "amdk8", "ataport", "atapi", "battc",
    "beep", "bowser", "cdfs", "cdrom", "cng", "compbatt", "disk",
    "dxgkrnl", "dxgmms", "fdc", "fileinfo", "fltmgr", "fvevol",
    "hid", "http", "i8042prt", "intelppm", "iorate", "ksecdd",
    "ksecpkg", "lxss", "mouhid", "mountmgr", "mrx", "mslldp",
    "mup", "ndis", "netbt", "npfs", "nsi", "ntfs", "null",
    "pacer", "partmgr", "pci", "pcw", "ramdisk", "rdbss",
    "rdp", "refs", "scsi", "sdstor", "smb", "srv", "storport",
    "tcpip", "tdi", "tdx", "tm", "udfs", "usb", "vdrvroot",
    "vhdmp", "vmbus", "volmgr", "volsnap", "vpci", "wdf",
    "wfp", "win32k", "wmi", "wof",
}


def is_ms_inbox(filename: str) -> bool:
    base = filename.lower().replace(".sys", "")
    return any(base.startswith(prefix) for prefix in MS_INBOX_PREFIXES)


def is_known_kdu(filename: str) -> bool:
    normalized = filename.lower().replace(".sys", "").replace("_", "")
    return normalized in {
        n.lower().replace(".sys", "").replace("_", "")
        for n in KNOWN_KDU_NAMES
    }


# ---------------------------------------------------------------------------
# Novelty scoring
# ---------------------------------------------------------------------------

NOVELTY_WEIGHTS = {
    "PhysMem-Map": 30,
    "PhysMem-Section": 25,
    "PhysMem-Copy": 25,
    "CrossProc-VA": 20,
    "CrossProc-Attach": 15,
    "CR-Regs": 20,
    "MSR": 15,
    "KernelExec": 20,
    "I/O-Port": 10,
    "MDL": 10,
    "Callback-Bypass": 15,
    "Process-Lookup": 5,
    "KernelAlloc": 5,
    "Registry": 5,
    "Token-Priv": 5,
}

SIGNED_BONUS = 20
X64_BONUS = 10
IOCTL_BONUS = 15
DEVICE_NAME_BONUS = 10


@dataclass
class NovelCandidate:
    result: DriverResult
    novelty_score: int = 0
    reasons: list[str] = field(default_factory=list)
    ioctl_count: int = 0


def compute_novelty(r: DriverResult) -> NovelCandidate:
    """Score a driver by how interesting it is as a novel 0-day find."""
    candidate = NovelCandidate(result=r)
    score = 0

    for cls in r.primitive_classes:
        w = NOVELTY_WEIGHTS.get(cls, 5)
        score += w
        candidate.reasons.append(f"+{w} {cls}")

    if r.is_signed:
        score += SIGNED_BONUS
        candidate.reasons.append(f"+{SIGNED_BONUS} signed")

    if r.is_64bit:
        score += X64_BONUS
        candidate.reasons.append(f"+{X64_BONUS} x64")

    if r.device_names:
        score += DEVICE_NAME_BONUS
        candidate.reasons.append(f"+{DEVICE_NAME_BONUS} has device name")

    candidate.novelty_score = score
    return candidate


# ---------------------------------------------------------------------------
# Scan paths
# ---------------------------------------------------------------------------

DEFAULT_SCAN_PATHS = [
    r"C:\Windows\System32\drivers",
]

DEEP_SCAN_PATHS = [
    r"C:\Windows\System32\DriverStore\FileRepository",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def collect_sys_files(paths: list[str], recursive: bool = True) -> list[Path]:
    """Collect all .sys files from given paths."""
    files = []
    for p in paths:
        root = Path(p)
        if not root.exists():
            continue
        if root.is_file() and root.suffix.lower() == ".sys":
            files.append(root)
        elif root.is_dir():
            pattern = "**/*.sys" if recursive else "*.sys"
            files.extend(root.glob(pattern))
    return sorted(set(files))


def hunt(scan_paths: list[str] = None, deep: bool = False,
         extra_paths: list[str] = None,
         lol_cache: str = None,
         blocklist_cache: str = None,
         min_score: int = 0) -> list[NovelCandidate]:
    """Run the full zero-day hunting pipeline.

    1. Collect .sys files from scan paths
    2. Scan each for dangerous imports
    3. Filter out MS inbox, known KDU, LOLDrivers, MS blocklist
    4. Score remaining candidates by novelty
    """
    if scan_paths is None:
        scan_paths = list(DEFAULT_SCAN_PATHS)
    if deep:
        scan_paths.extend(DEEP_SCAN_PATHS)
    if extra_paths:
        scan_paths.extend(extra_paths)

    print(f"\n  Scanning {len(scan_paths)} path(s)...", file=sys.stderr)
    sys_files = collect_sys_files(scan_paths)
    print(f"  Found {len(sys_files)} .sys files", file=sys.stderr)

    # Phase 1: scan all files
    results: list[DriverResult] = []
    total = len(sys_files)
    for i, f in enumerate(sys_files, 1):
        print(f"\r  [{i}/{total}] Scanning {f.name:<40}",
              end="", file=sys.stderr, flush=True)
        if is_ms_inbox(f.name):
            continue
        r = scan_driver(str(f))
        if r.flagged_imports:
            results.append(r)
    print(file=sys.stderr)
    print(f"  {len(results)} drivers with red-flag imports", file=sys.stderr)

    # Phase 2: filter known
    lol_index = build_lol_index(cache_path=lol_cache)
    enrich_with_lol(results, lol_index)

    blocklist = fetch_ms_blocklist(cache_path=blocklist_cache)
    enrich_with_blocklist(results, blocklist)

    novel = []
    for r in results:
        if r.lol_known:
            continue
        if r.ms_blocked:
            continue
        if is_known_kdu(r.filename):
            continue
        novel.append(r)

    print(f"  {len(novel)} novel candidates after filtering", file=sys.stderr)

    # Phase 3: score
    candidates = [compute_novelty(r) for r in novel]

    # Phase 4: optional IOCTL extraction
    if HAS_IOCTL:
        for c in candidates:
            try:
                surface = extract_ioctl_surface(c.result.path)
                c.ioctl_count = len(surface.ioctls)
                if surface.ioctls:
                    c.novelty_score += IOCTL_BONUS
                    c.reasons.append(f"+{IOCTL_BONUS} {c.ioctl_count} IOCTLs")
            except Exception:
                pass

    candidates.sort(key=lambda c: -c.novelty_score)

    if min_score > 0:
        candidates = [c for c in candidates if c.novelty_score >= min_score]

    return candidates


def format_results(candidates: list[NovelCandidate], json_output: bool = False) -> str:
    """Format hunt results for display."""
    if json_output:
        out = []
        for c in candidates:
            out.append({
                "filename": c.result.filename,
                "path": c.result.path,
                "sha256": c.result.sha256,
                "score": c.novelty_score,
                "primitive_classes": c.result.primitive_classes,
                "flagged_imports": c.result.flagged_imports,
                "device_names": c.result.device_names,
                "signed": c.result.is_signed,
                "signer": c.result.signer,
                "ioctl_count": c.ioctl_count,
                "reasons": c.reasons,
            })
        return json.dumps(out, indent=2)

    lines = []
    lines.append(f"\n{'='*100}")
    lines.append(f"  NOVEL DRIVER CANDIDATES — {len(candidates)} found")
    lines.append(f"{'='*100}\n")

    if not candidates:
        lines.append("  No novel candidates found.")
        return "\n".join(lines)

    lines.append(f"  {'#':<4} {'Score':>5} {'Driver':<35} {'Classes':>3} "
                 f"{'IOCTLs':>6} {'Signed':<6} Primitive Classes")
    lines.append(f"  {'-'*4} {'-'*5} {'-'*35} {'-'*3} {'-'*6} {'-'*6} {'-'*40}")

    for i, c in enumerate(candidates[:50], 1):
        r = c.result
        name = r.filename[:34] if len(r.filename) <= 34 else r.filename[:31] + "..."
        signed = "YES" if r.is_signed else "no"
        classes = ", ".join(r.primitive_classes)
        lines.append(f"  {i:<4} {c.novelty_score:>5} {name:<35} "
                      f"{len(r.primitive_classes):>3} {c.ioctl_count:>6} "
                      f"{signed:<6} {classes}")

    # Detailed top 20
    lines.append(f"\n{'-'*100}")
    lines.append(f"  TOP CANDIDATES — Detail")
    lines.append(f"{'-'*100}")

    for c in candidates[:20]:
        r = c.result
        lines.append(f"\n  {r.filename} (score={c.novelty_score})")
        lines.append(f"    Path: {r.path}")
        lines.append(f"    SHA256: {r.sha256}")
        lines.append(f"    Size: {r.size:,} bytes | "
                      f"{'x64' if r.is_64bit else 'x86'} | "
                      f"{'Signed' if r.is_signed else 'Unsigned'}")
        if r.signer:
            lines.append(f"    Signer: {r.signer}")
        if r.device_names:
            lines.append(f"    Devices: {', '.join(r.device_names[:5])}")
        if c.ioctl_count:
            lines.append(f"    IOCTLs: {c.ioctl_count}")
        lines.append(f"    Scoring: {' | '.join(c.reasons)}")
        for cls in r.primitive_classes:
            syms = [s for s in r.flagged_imports if s in PRIMITIVE_CLASSES.get(cls, [])]
            if syms:
                lines.append(f"    [{cls}] {', '.join(syms)}")

    return "\n".join(lines)
