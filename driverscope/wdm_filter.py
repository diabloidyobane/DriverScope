"""Filter for plain WDM drivers with physical memory primitives."""

import struct
import sys
from pathlib import Path
from typing import Optional


DANGEROUS_IMPORTS = {
    b"MmMapIoSpace",
    b"MmMapLockedPagesSpecifyCache",
    b"MmMapLockedPages",
    b"ZwMapViewOfSection",
    b"MmGetPhysicalAddress",
    b"MmGetVirtualForPhysical",
    b"MmAllocateContiguousMemory",
    b"MmAllocateContiguousMemorySpecifyCache",
    b"IoAllocateMdl",
    b"MmBuildMdlForNonPagedPool",
}

BONUS_IMPORTS = {
    b"MmCopyVirtualMemory",
    b"ZwAllocateVirtualMemory",
    b"KeStackAttachProcess",
    b"PsLookupProcessByProcessId",
    b"__readmsr",
    b"__writemsr",
    b"__readcr0",
    b"__readcr3",
    b"__readcr4",
}

WDF_MARKERS = [
    b"WdfVersionBind",
    b"Wdf01000",
    b"WdfDriverCreate",
    b"WDFDEVICE",
    b"WdfDeviceCreate",
    b"WdfControlDeviceInitAllocate",
]

WDM_MARKERS = [
    b"IoCreateDevice",
    b"IoCreateDeviceSecure",
    b"IoCreateSymbolicLink",
]

DEVICE_MARKERS = [
    b"\\Device\\",
    b"\\DosDevices\\",
    b"\\\\.\\",
]


def scan_pe_imports(data: bytes) -> set[bytes]:
    imports: set[bytes] = set()
    if data[:2] != b"MZ":
        return imports
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return imports

        magic = struct.unpack_from("<H", data, pe_offset + 0x18)[0]
        if magic == 0x20B:  # PE32+
            import_dir_rva = struct.unpack_from("<I", data, pe_offset + 0x90)[0]
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            section_offset = pe_offset + 0x108
        elif magic == 0x10B:  # PE32
            import_dir_rva = struct.unpack_from("<I", data, pe_offset + 0x80)[0]
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            section_offset = pe_offset + 0xF8
        else:
            return imports

        if import_dir_rva == 0:
            return imports

        sections = []
        for i in range(num_sections):
            s_off = section_offset + i * 40
            s_va = struct.unpack_from("<I", data, s_off + 12)[0]
            s_sz = struct.unpack_from("<I", data, s_off + 8)[0]
            s_raw = struct.unpack_from("<I", data, s_off + 20)[0]
            s_rawsz = struct.unpack_from("<I", data, s_off + 16)[0]
            sections.append((s_va, s_sz, s_raw, s_rawsz))

        def rva_to_offset(rva):
            for s_va, s_sz, s_raw, s_rawsz in sections:
                if s_va <= rva < s_va + max(s_sz, s_rawsz):
                    return rva - s_va + s_raw
            return None

        off = rva_to_offset(import_dir_rva)
        if off is None:
            return imports

        while off + 20 <= len(data):
            ilt_rva = struct.unpack_from("<I", data, off)[0]
            name_rva = struct.unpack_from("<I", data, off + 12)[0]
            if ilt_rva == 0 and name_rva == 0:
                break
            off += 20

            table_rva = ilt_rva if ilt_rva else struct.unpack_from("<I", data, off - 20 + 16)[0]
            if table_rva == 0:
                continue

            t_off = rva_to_offset(table_rva)
            if t_off is None:
                continue

            entry_size = 8 if magic == 0x20B else 4
            while t_off + entry_size <= len(data):
                entry = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, t_off)[0]
                if entry == 0:
                    break
                t_off += entry_size

                if magic == 0x20B and entry & (1 << 63):
                    continue
                if magic == 0x10B and entry & (1 << 31):
                    continue

                hint_off = rva_to_offset(entry & 0x7FFFFFFF)
                if hint_off is None or hint_off + 2 >= len(data):
                    continue

                name_start = hint_off + 2
                name_end = name_start
                while name_end < len(data) and data[name_end] != 0:
                    name_end += 1
                if name_end > name_start:
                    imports.add(data[name_start:name_end])

    except Exception:
        pass
    return imports


def classify_driver(path: Path) -> Optional[dict]:
    try:
        data = path.read_bytes()
    except Exception:
        return None

    if data[:2] != b"MZ":
        return None

    imports = scan_pe_imports(data)

    is_wdf = any(marker in data for marker in WDF_MARKERS)
    is_wdm = any(marker in data for marker in WDM_MARKERS)

    if is_wdf:
        return None  # Skip WDF drivers

    if not is_wdm:
        return None  # Skip non-WDM

    dangerous = [imp.decode() for imp in imports if imp in DANGEROUS_IMPORTS]
    bonus = [imp.decode() for imp in imports if imp in BONUS_IMPORTS]

    if not dangerous:
        return None

    devices = []
    for marker in DEVICE_MARKERS:
        idx = 0
        while True:
            idx = data.find(marker, idx)
            if idx == -1:
                break
            end = idx
            while end < len(data) and end < idx + 200 and data[end] >= 0x20 and data[end] <= 0x7E:
                end += 1
            name = data[idx:end].decode("ascii", errors="replace")
            if len(name) > len(marker) + 2:
                devices.append(name)
            idx = end

    return {
        "filename": path.name,
        "path": str(path),
        "is_wdm": True,
        "dangerous_imports": dangerous,
        "bonus_imports": bonus,
        "device_names": devices,
        "score": len(dangerous) * 10 + len(bonus) * 5,
    }


def scan_for_wdm_physmem(paths: list[str],
                         recursive: bool = True) -> list[dict]:
    results = []
    for p in paths:
        root = Path(p)
        if not root.exists():
            continue
        pattern = "**/*.sys" if recursive else "*.sys"
        files = list(root.glob(pattern))

        for i, f in enumerate(files, 1):
            print(f"\r  [{i}/{len(files)}] {f.name:<40}",
                  end="", file=sys.stderr, flush=True)
            hit = classify_driver(f)
            if hit:
                results.append(hit)

        if files:
            print(file=sys.stderr)

    results.sort(key=lambda r: -r["score"])
    return results
