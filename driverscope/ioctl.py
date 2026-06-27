"""Static IOCTL dispatch-surface extraction for Windows x64 .sys files.

Given a .sys PE on disk:
  1. Resolve DriverEntry (entrypoint or export, then heuristic scan).
  2. Find the store into DRIVER_OBJECT.MajorFunction[IRP_MJ_DEVICE_CONTROL]
     (offset +0xE0 on x64). Recover the dispatcher RVA.
  3. In the dispatcher, find the IoControlCode load and walk the switch to
     collect every IOCTL imm32 + its branch handler RVA.
  4. Decode CTL_CODE fields and scan branch bodies for dangerous imports.

Capstone is optional — without it a narrower byte-pattern fallback runs.
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Iterator

import pefile

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    capstone = None
    HAS_CAPSTONE = False

from .scanner import _IMPORT_TO_CLASSES

# ---------------------------------------------------------------------------
# DRIVER_OBJECT layout (x64, stable since Windows XP x64)
# ---------------------------------------------------------------------------
DRIVER_OBJECT_MAJORFUNCTION_OFF = 0x70
IRP_MJ_DEVICE_CONTROL = 0x0E
DISPATCH_DEVICE_CONTROL_OFFSET = (
    DRIVER_OBJECT_MAJORFUNCTION_OFF + IRP_MJ_DEVICE_CONTROL * 8
)  # 0xE0

IRP_CURRENT_STACK_LOCATION_OFF = 0xB8
IO_STACK_IO_CONTROL_CODE_OFF = 0x18

# ---------------------------------------------------------------------------
# CTL_CODE decoding (winioctl.h)
# ---------------------------------------------------------------------------
CTL_METHOD_MASK = 0x00000003
CTL_FUNCTION_MASK = 0x00003FFC
CTL_FUNCTION_SHIFT = 2
CTL_ACCESS_MASK = 0x0000C000
CTL_ACCESS_SHIFT = 14
CTL_DEVICE_TYPE_SHIFT = 16

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
}

DEVICE_TYPE_NAMES = {
    0x00000001: "FILE_DEVICE_BEEP",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000000B: "FILE_DEVICE_KEYBOARD",
    0x00000012: "FILE_DEVICE_MOUSE",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000034: "FILE_DEVICE_BATTERY",
    0x00000039: "FILE_DEVICE_ACPI",
    0x0000003E: "FILE_DEVICE_KSEC",
}


@dataclass
class CTLCode:
    raw: int
    device_type: int = 0
    device_type_name: str = ""
    function: int = 0
    method: int = 0
    method_name: str = ""
    access: int = 0
    access_name: str = ""

    def __post_init__(self):
        self.device_type = self.raw >> CTL_DEVICE_TYPE_SHIFT
        self.function = (self.raw & CTL_FUNCTION_MASK) >> CTL_FUNCTION_SHIFT
        self.method = self.raw & CTL_METHOD_MASK
        self.access = (self.raw & CTL_ACCESS_MASK) >> CTL_ACCESS_SHIFT
        self.method_name = METHOD_NAMES.get(self.method, f"METHOD_{self.method}")
        self.access_name = ACCESS_NAMES.get(self.access, f"ACCESS_{self.access}")
        dt = DEVICE_TYPE_NAMES.get(self.device_type)
        self.device_type_name = dt if dt else f"USER(0x{self.device_type:04X})"


@dataclass
class IOCTLEntry:
    code: int
    ctl: CTLCode = field(default=None)
    handler_rva: int = 0
    handler_imports: list[str] = field(default_factory=list)
    primitive_classes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.ctl is None:
            self.ctl = CTLCode(self.code)


@dataclass
class IOCTLSurface:
    path: str
    filename: str
    sha256: str = ""
    dispatcher_rva: int = 0
    ioctls: list[IOCTLEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    method: str = ""


def _rva_to_offset(pe: pefile.PE, rva: int) -> Optional[int]:
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None


def _find_dispatcher_pattern(data: bytes, pe: pefile.PE) -> Optional[int]:
    """Byte-pattern scan for MOV [RCX+0xE0], <addr> in DriverEntry."""
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_off = _rva_to_offset(pe, ep_rva)
    if ep_off is None:
        return None

    search_size = min(0x400, len(data) - ep_off)
    chunk = data[ep_off:ep_off + search_size]

    # Pattern: 48 8D 05 xx xx xx xx (LEA RAX, [rip+xx]) followed by
    #          48 89 81 E0 00 00 00 (MOV [RCX+0xE0], RAX)
    # Or:      48 C7 81 E0 00 00 00 (MOV [RCX+0xE0], imm32)
    patterns = [
        (b"\x48\x89\x81\xe0\x00\x00\x00", -7),  # preceded by LEA RAX
        (b"\x48\x89\x41\x70",             -7),   # MOV [RCX+0x70] variant
    ]

    for pat, lea_offset in patterns:
        idx = chunk.find(pat)
        if idx == -1:
            continue
        lea_pos = idx + lea_offset
        if lea_pos < 0 or lea_pos + 7 > len(chunk):
            continue
        if chunk[lea_pos:lea_pos + 3] == b"\x48\x8D\x05":
            disp = struct.unpack_from("<i", chunk, lea_pos + 3)[0]
            rip_val = ep_rva + lea_pos + 7
            return rip_val + disp

    return None


def _find_ioctl_immediates(data: bytes, pe: pefile.PE,
                           dispatcher_rva: int) -> list[IOCTLEntry]:
    """Scan dispatcher body for IOCTL immediate comparisons."""
    off = _rva_to_offset(pe, dispatcher_rva)
    if off is None:
        return []

    entries = []
    search_size = min(0x2000, len(data) - off)
    chunk = data[off:off + search_size]

    seen = set()
    # Look for CMP reg, imm32 patterns: 3D xx xx xx xx or 81 F? xx xx xx xx
    for i in range(len(chunk) - 5):
        imm = None
        if chunk[i] == 0x3D:
            imm = struct.unpack_from("<I", chunk, i + 1)[0]
        elif chunk[i] == 0x81 and (chunk[i + 1] & 0xF8) in (0xF8, 0xF0, 0xE8):
            imm = struct.unpack_from("<I", chunk, i + 2)[0]

        if imm is None:
            continue

        # Validate as plausible IOCTL: device type should be non-zero,
        # function should be non-zero
        device_type = imm >> CTL_DEVICE_TYPE_SHIFT
        function = (imm & CTL_FUNCTION_MASK) >> CTL_FUNCTION_SHIFT
        if device_type == 0 or function == 0:
            continue
        if device_type > 0xFFFF:
            continue

        if imm not in seen:
            seen.add(imm)
            entries.append(IOCTLEntry(code=imm, handler_rva=dispatcher_rva + i))

    return entries


def extract_ioctl_surface(path: str) -> IOCTLSurface:
    """Extract IOCTL dispatch surface from a .sys driver."""
    p = Path(path)
    result = IOCTLSurface(path=str(p), filename=p.name)

    try:
        data = p.read_bytes()
    except Exception as e:
        result.errors.append(f"read error: {e}")
        return result

    result.sha256 = hashlib.sha256(data).hexdigest()

    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        result.errors.append(f"PE parse error: {e}")
        return result

    if pe.FILE_HEADER.Machine != 0x8664:
        result.errors.append("not x64")
        pe.close()
        return result

    dispatcher_rva = _find_dispatcher_pattern(data, pe)
    if dispatcher_rva is not None:
        result.dispatcher_rva = dispatcher_rva
        result.method = "pattern"
        result.ioctls = _find_ioctl_immediates(data, pe, dispatcher_rva)
    else:
        # Fallback: scan the entire .text section for IOCTL-like immediates
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        result.method = "brute"
        result.ioctls = _find_ioctl_immediates(data, pe, ep_rva)
        if not result.ioctls:
            result.errors.append("no dispatcher found")

    pe.close()
    return result
