"""Microsoft symbol server client + local cache + PE→symbol resolution.

Given a driver path, resolve one or more RVAs (e.g. the IOCTL dispatcher) to
symbol names by:
  1. Reading the CodeView entry from the PE Debug Directory to obtain
     (pdb_filename, guid, age)
  2. Downloading the PDB from https://msdl.microsoft.com/download/symbols/
     using the standard layout: <pdb>/<guid><age>/<pdb>
  3. Parsing the PDB with `pdbparse` if installed; otherwise doing a minimal
     public-symbol scan by hand.
  4. Caching PDBs under DEFAULT_CACHE (defaults to tools/pdb_cache/).

If pdbparse is missing OR the PDB isn't published on the MS symbol server
(true for third-party drivers), we degrade gracefully and return {} rather
than raising.
"""
from __future__ import annotations

import os
import re
import struct
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_CACHE = Path(__file__).resolve().parent.parent / "pdb_cache"
SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

USER_AGENT = "Microsoft-Symbol-Server/10.0"


@dataclass
class DebugInfo:
    pdb_filename: str = ""
    guid: str = ""      # uppercase hex, 32 chars, no dashes
    age: int = 0


# ── PE Debug Directory parse ────────────────────────────────────────────

def _read_debug_dir(pe_path: str | Path) -> Optional[DebugInfo]:
    with open(pe_path, "rb") as f:
        data = f.read()
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        return None

    file_header_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, file_header_off + 2)[0]
    opt_hdr_off = file_header_off + 20
    magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
    if magic == 0x20B:  # PE32+
        data_dir_off = opt_hdr_off + 112
        sect_off = opt_hdr_off + 240
    elif magic == 0x10B:
        data_dir_off = opt_hdr_off + 96
        sect_off = opt_hdr_off + 224
    else:
        return None

    # Debug data directory = index 6
    debug_va = struct.unpack_from("<I", data, data_dir_off + 6 * 8)[0]
    debug_size = struct.unpack_from("<I", data, data_dir_off + 6 * 8 + 4)[0]
    if not debug_va or not debug_size:
        return None

    # section table for RVA → file offset
    sections: list[tuple[int, int, int, int]] = []
    for i in range(num_sections):
        s = sect_off + i * 40
        virt_size = struct.unpack_from("<I", data, s + 8)[0]
        virt_addr = struct.unpack_from("<I", data, s + 12)[0]
        raw_size = struct.unpack_from("<I", data, s + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, s + 20)[0]
        sections.append((virt_addr, virt_size, raw_ptr, raw_size))

    def rva_to_off(rva: int) -> Optional[int]:
        for va, vs, rp, rs in sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    dbg_off = rva_to_off(debug_va)
    if dbg_off is None:
        return None

    # Each IMAGE_DEBUG_DIRECTORY is 28 bytes; type at offset 12; address of raw at 20
    for i in range(debug_size // 28):
        entry = dbg_off + i * 28
        dbg_type = struct.unpack_from("<I", data, entry + 12)[0]
        raw_off = struct.unpack_from("<I", data, entry + 24)[0]
        if dbg_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        # CodeView "RSDS": magic(4) + guid(16) + age(4) + pdb-name (NUL-terminated)
        if data[raw_off: raw_off + 4] != b"RSDS":
            continue
        guid_bytes = data[raw_off + 4: raw_off + 20]
        age = struct.unpack_from("<I", data, raw_off + 20)[0]
        d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
        d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
        d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
        d4 = guid_bytes[8:]
        guid_str = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"

        # pdb name
        end = data.find(b"\x00", raw_off + 24)
        pdb_name_bytes = data[raw_off + 24: end] if end != -1 else b""
        try:
            pdb_name = pdb_name_bytes.decode("utf-8", errors="replace")
        except Exception:
            pdb_name = ""
        pdb_name = os.path.basename(pdb_name)

        return DebugInfo(pdb_filename=pdb_name, guid=guid_str, age=age)
    return None


# ── PDB fetch + cache ───────────────────────────────────────────────────

def _sanitize(name: str) -> str:
    return re.sub(r'[<>:"|?*\\/]', "_", name) or "sym.pdb"


def _cache_path(info: DebugInfo, cache_dir: Path) -> Path:
    return cache_dir / _sanitize(info.pdb_filename) / f"{info.guid}{info.age}" / _sanitize(info.pdb_filename)


def fetch_pdb(info: DebugInfo, cache_dir: Path = DEFAULT_CACHE,
              server: str = SYMBOL_SERVER, timeout: int = 30) -> Optional[Path]:
    """Download the PDB from msdl.microsoft.com and cache it. Returns cache path or None."""
    if not info.pdb_filename or not info.guid:
        return None
    target = _cache_path(info, cache_dir)
    if target.exists() and target.stat().st_size > 0:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    url = f"{server}/{_sanitize(info.pdb_filename)}/{info.guid}{info.age}/{_sanitize(info.pdb_filename)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        # Also try the compressed variant server-side sometimes serves
        if e.code == 404:
            comp_name = info.pdb_filename[:-1] + "_"
            url2 = f"{server}/{_sanitize(info.pdb_filename)}/{info.guid}{info.age}/{comp_name}"
            try:
                req2 = urllib.request.Request(url2, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req2, timeout=timeout) as resp:
                    data = resp.read()
                # write compressed-marked file — pdbparse handles cab-wrapped PDBs
                comp_target = target.with_suffix(".pd_")
                comp_target.write_bytes(data)
                return comp_target
            except Exception:
                return None
        return None
    except Exception:
        return None
    target.write_bytes(data)
    return target


# ── symbol resolution ──────────────────────────────────────────────────

def _resolve_with_pdbparse(pdb_path: Path,
                           rvas: Iterable[int]) -> dict[int, str]:
    try:
        import pdbparse  # type: ignore
    except ImportError:
        return {}
    try:
        pdb = pdbparse.parse(str(pdb_path))
    except Exception:
        return {}
    rvas = list(rvas)
    if not rvas:
        return {}
    result: dict[int, str] = {}
    try:
        omap = pdb.omap_from_src if hasattr(pdb, "omap_from_src") else None
        sects = pdb.STREAM_SECT_HDR_ORIG.sections if hasattr(pdb, "STREAM_SECT_HDR_ORIG") \
            else pdb.STREAM_SECT_HDR.sections
        gsyms = pdb.STREAM_GSYM
        by_offset: dict[tuple[int, int], list[str]] = {}
        for sym in gsyms.globals:
            leaf = getattr(sym, "leaf_type", "")
            if leaf not in ("S_PUB32", "S_GPROC32"):
                continue
            name = getattr(sym, "name", "")
            off = getattr(sym, "offset", 0)
            sect = getattr(sym, "segment", 0)
            by_offset.setdefault((sect, off), []).append(name)

        # Build RVA → symbol
        rva_to_sym: dict[int, str] = {}
        for (sect_i, off), names in by_offset.items():
            if sect_i - 1 < 0 or sect_i - 1 >= len(sects):
                continue
            s = sects[sect_i - 1]
            rva = s.VirtualAddress + off
            if omap:
                rva = omap.remap(rva)
            rva_to_sym[rva] = names[0]

        for rva in rvas:
            if rva in rva_to_sym:
                result[rva] = rva_to_sym[rva]
            else:
                # nearest previous
                nearest = -1
                nearest_name = ""
                for k, name in rva_to_sym.items():
                    if k <= rva > nearest and (rva - k) < 0x1000:
                        nearest = k
                        nearest_name = name
                if nearest_name:
                    result[rva] = f"{nearest_name}+0x{rva - nearest:x}"
    except Exception:
        return result
    return result


def _resolve_by_string_scan(pdb_path: Path,
                            rvas: Iterable[int]) -> dict[int, str]:
    """Heuristic fallback: scan PDB for ASCII/UTF-16 symbol names near their
    32-bit offsets. Coarse but often enough to name obvious dispatchers.
    """
    try:
        raw = pdb_path.read_bytes()
    except OSError:
        return {}
    result: dict[int, str] = {}
    rvas = list(rvas)
    if not rvas:
        return {}
    ascii_re = re.compile(rb"[A-Za-z_@?][A-Za-z0-9_@?$.]{4,}")
    for m in ascii_re.finditer(raw):
        name = m.group(0).decode("ascii", errors="replace")
        # Look for a 4-byte little-endian offset ±0x40 before the name
        pos = m.start()
        window = raw[max(0, pos - 8): pos]
        if len(window) >= 4:
            off = struct.unpack_from("<I", window, len(window) - 4)[0]
            for rva in rvas:
                if off == rva:
                    result.setdefault(rva, name)
    return result


def resolve(pe_path: str | Path, rvas: Iterable[int],
            cache_dir: Path = DEFAULT_CACHE,
            server: str = SYMBOL_SERVER) -> dict[int, str]:
    info = _read_debug_dir(pe_path)
    if not info:
        return {}
    pdb_path = fetch_pdb(info, cache_dir=cache_dir, server=server)
    if not pdb_path:
        return {}
    rvas_list = list(rvas)
    if not rvas_list:
        return {}
    names = _resolve_with_pdbparse(pdb_path, rvas_list)
    if not names:
        names = _resolve_by_string_scan(pdb_path, rvas_list)
    return names


def resolve_dispatcher(pe_path: str | Path, dispatcher_rva: int,
                       cache_dir: Path = DEFAULT_CACHE,
                       server: str = SYMBOL_SERVER) -> Optional[str]:
    m = resolve(pe_path, [dispatcher_rva], cache_dir=cache_dir, server=server)
    return m.get(dispatcher_rva)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Resolve PE RVAs to PDB symbols via MS symbol server")
    ap.add_argument("driver", help="Path to a .sys file")
    ap.add_argument("--rva", action="append", default=[],
                    help="RVA to resolve (hex, e.g. 0x18400). Repeat for multiple.")
    ap.add_argument("--cache", type=str, default=str(DEFAULT_CACHE))
    args = ap.parse_args()

    info = _read_debug_dir(args.driver)
    if not info:
        print("[pdb] no CodeView entry in this PE")
        raise SystemExit(1)
    print(f"[pdb] {info.pdb_filename}  guid={info.guid}  age={info.age}")
    p = fetch_pdb(info, cache_dir=Path(args.cache))
    if not p:
        print("[pdb] fetch failed (not on symbol server?)")
        raise SystemExit(1)
    print(f"[pdb] cached at {p}")

    rvas = [int(x, 16) if x.lower().startswith("0x") else int(x) for x in args.rva]
    if rvas:
        m = resolve(args.driver, rvas, cache_dir=Path(args.cache))
        for rva in rvas:
            print(f"  0x{rva:x}  →  {m.get(rva, '(unresolved)')}")
