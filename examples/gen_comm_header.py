"""
gen_comm_header.py: turn DriverScope --json output into a C comm header.

Usage:
    driverscope ioctl driver.sys --json > findings.json
    python gen_comm_header.py findings.json > driver_comm.h
"""

import json
import re
import sys
from pathlib import Path


def slug(s: str) -> str:
    """Make a C-safe macro suffix from anything."""
    return re.sub(r"[^A-Z0-9_]+", "_", s.upper()).strip("_") or "UNKNOWN"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    data = json.loads(Path(sys.argv[1]).read_text())

    # Accept either a single surface or a list of surfaces.
    surfaces = data if isinstance(data, list) else [data]

    for s in surfaces:
        fname = s.get("filename", "unknown.sys")
        sym = slug(Path(fname).stem)
        method_via = s.get("method", "?")
        sha = s.get("sha256", "")

        print(f"/* Generated from {fname} ({method_via}, sha256={sha[:16]}...) */")
        print(f"/* Set DEVICE_PATH yourself: DriverScope doesn't always recover it. */")
        print(f"#pragma once")
        print(f"#include <windows.h>")
        print(f"#include <winioctl.h>")
        print()
        print(f'#define {sym}_DEVICE_PATH  "\\\\\\\\.\\\\<SYMLINK>"')
        print()

        for entry in s.get("ioctls", []):
            code = entry.get("code", "0x0")
            dev  = entry.get("device_type", "0x0")
            fn   = entry.get("function", 0)
            meth = entry.get("method", "METHOD_BUFFERED")
            acc  = entry.get("access", "FILE_ANY_ACCESS")
            classes = entry.get("primitive_classes", []) or []

            label = f"{sym}_{code.upper().replace('0X','')}"
            tag = f"  /* {', '.join(classes)} */" if classes else ""
            print(f"#define IOCTL_{label}  CTL_CODE({dev}, {fn}, {meth}, {acc}){tag}")

        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
