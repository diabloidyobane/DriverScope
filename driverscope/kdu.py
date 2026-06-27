"""Parse KDU's kdu.db (RMDX format) to extract driver binaries.

KDU (Kernel Driver Utility) bundles 65+ vulnerable drivers in an XOR-encoded
RMDX database. This module parses that database and extracts individual .sys
files using Windows MSDelta decompression.
"""

import ctypes
import ctypes.wintypes
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# KDU resource ID -> driver filename mapping (from consts.h + tanikaze.h)
# ---------------------------------------------------------------------------

RESOURCE_MAP = {
    103: "NalDrv",
    104: "rzpnk",
    105: "RTCore64",
    106: "Gdrv",
    107: "ATSZIO",
    108: "MsIo64",
    109: "GLCKIo2",
    110: "EneIo64",
    111: "WinRing0x64",
    112: "EneTechIo64",
    113: "phymemx64",
    114: "rtkio64",
    115: "EneTechIo64_B",
    116: "lha",
    117: "AsIO2",
    118: "DirectIo64",
    119: "gmerdrv",
    120: "DBUtil23",
    121: "mimidrv",
    122: "KProcessHacker",
    123: "DBUtilDrv2",
    124: "CEDRIVER73",
    125: "AsIO3",
    126: "hw64",
    127: "SysDrv3S",
    128: "ZemanaAntimalware",
    129: "inpoutx64",
    130: "DirectIo64_OSF",
    131: "AsrDrv106",
    132: "ALSysIO64",
    133: "AMDRyzenMasterDriver",
    134: "physmem",
    135: "LenovoDiagnosticsDriver",
    136: "pcdsrvc_x64",
    137: "WinIo",
    138: "EtdSupport",
    139: "KExplore",
    140: "KObjExp",
    141: "KRegExp",
    142: "PhyDMACC",
    143: "EchoDrv",
    144: "nvoclock",
    145: "IREC",
    146: "PdFwKrnl",
    147: "AODDriver",
    148: "wnBios64",
    149: "EleetX1",
    150: "AxtuDrv",
    151: "AppShopDrv103",
    152: "AsrDrv107n",
    153: "AsrDrv107",
    154: "PMxDrv",
    155: "HwRwDrv.x64",
    156: "NeacSafe64",
    157: "ThrottleStop",
    158: "TPwSav",
    159: "LnvMSRIO",
    160: "CORMEM",
    161: "IPCType",
    162: "WinHwDriver",
}


def _xor_decode(data: bytes, key: int) -> bytes:
    """XOR-decode a buffer with a single-byte key."""
    return bytes(b ^ key for b in data)


def _msdelta_decompress(data: bytes) -> bytes:
    """Decompress MSDelta-compressed data using Windows API.

    Requires Windows and msdelta.dll (ships with all Windows versions).
    """
    if sys.platform != "win32":
        raise RuntimeError("MSDelta decompression requires Windows")

    class DELTA_INPUT(ctypes.Structure):
        _fields_ = [
            ("lpStart", ctypes.c_void_p),
            ("uSize", ctypes.c_size_t),
            ("Editable", ctypes.wintypes.BOOL),
        ]

    class DELTA_OUTPUT(ctypes.Structure):
        _fields_ = [
            ("lpStart", ctypes.c_void_p),
            ("uSize", ctypes.c_size_t),
        ]

    try:
        msdelta = ctypes.windll.msdelta
    except OSError:
        raise RuntimeError("msdelta.dll not found")

    buf = ctypes.create_string_buffer(data)
    delta_in = DELTA_INPUT()
    delta_in.lpStart = ctypes.addressof(buf)
    delta_in.uSize = len(data)
    delta_in.Editable = False

    empty_in = DELTA_INPUT()
    empty_in.lpStart = None
    empty_in.uSize = 0
    empty_in.Editable = False

    delta_out = DELTA_OUTPUT()

    DELTA_FLAG_RAW = 0x00000001
    ok = msdelta.ApplyDeltaB(
        DELTA_FLAG_RAW,
        empty_in,
        delta_in,
        ctypes.byref(delta_out),
    )

    if not ok:
        raise RuntimeError("ApplyDeltaB failed")

    result = ctypes.string_at(delta_out.lpStart, delta_out.uSize)
    ctypes.windll.kernel32.LocalFree(delta_out.lpStart)
    return result


def parse_rmdx(db_path: str, output_dir: str = None) -> list[dict]:
    """Parse KDU's RMDX database and optionally extract drivers.

    Returns list of dicts with driver info. If output_dir is set,
    writes extracted .sys files there.
    """
    data = Path(db_path).read_bytes()

    if data[:4] != b"RMDX":
        raise ValueError(f"Not an RMDX file: {db_path}")

    header_size = struct.unpack_from("<I", data, 4)[0]
    entry_count = struct.unpack_from("<I", data, 8)[0]
    xor_key = data[12] if len(data) > 12 else 0

    entries = []
    offset = header_size

    for i in range(entry_count):
        if offset + 8 > len(data):
            break

        resource_id = struct.unpack_from("<I", data, offset)[0]
        entry_size = struct.unpack_from("<I", data, offset + 4)[0]

        if offset + 8 + entry_size > len(data):
            break

        entry_data = data[offset + 8:offset + 8 + entry_size]

        if xor_key:
            entry_data = _xor_decode(entry_data, xor_key)

        name = RESOURCE_MAP.get(resource_id, f"unknown_{resource_id}")

        info = {
            "resource_id": resource_id,
            "name": name,
            "compressed_size": entry_size,
            "decompressed_size": 0,
        }

        if output_dir and sys.platform == "win32":
            try:
                decompressed = _msdelta_decompress(entry_data)
                info["decompressed_size"] = len(decompressed)

                out = Path(output_dir)
                out.mkdir(parents=True, exist_ok=True)
                out_path = out / f"{name}.sys"
                out_path.write_bytes(decompressed)
                info["output_path"] = str(out_path)
            except Exception as e:
                info["error"] = str(e)

        entries.append(info)
        offset += 8 + entry_size

    return entries
