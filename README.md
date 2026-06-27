# DriverScope

**Automated BYOVD hunting pipeline** — scan, triage, and discover vulnerable signed Windows kernel drivers before they appear in public databases.

DriverScope automates the manual, tedious process of finding Bring Your Own Vulnerable Driver (BYOVD) candidates. It combines PE import analysis, IOCTL dispatch extraction, and cross-referencing against [LOLDrivers.io](https://www.loldrivers.io/), the [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), and [KDU](https://github.com/hfiref0x/KDU) — surfacing the **novel candidates** that nobody has documented yet.

## Why this exists

The BYOVD landscape is well-cataloged for *known* drivers (LOLDrivers tracks 500+, KDU bundles 65+). But thousands of signed drivers ship with OEM tools, regional vendor utilities, and niche hardware monitors — many with the same dangerous primitives (physmem map, MSR read/write, cross-process VA copy) and zero public documentation.

DriverScope closes that gap by automating the entire pipeline:

```
Harvest → Scan → Classify → Cross-Reference → Filter → Rank → Report
```

## Features

| Stage | Command | What it does |
|-------|---------|-------------|
| **Scan** | `driverscope scan` | Parse PE imports, classify into 18 primitive categories, extract device names |
| **Hunt** | `driverscope hunt` | Full zero-day pipeline — scan system dirs, filter known, rank novel candidates |
| **IOCTL** | `driverscope ioctl` | Static IOCTL dispatch extraction — find handler codes without running the driver |
| **Harvest** | `driverscope harvest` | Download OEM tools (GitHub API + direct URLs), extract bundled .sys drivers |
| **Regional** | `driverscope regional` | Search LOLDrivers by vendor region (CN/KR/JP/TW/RU) |
| **WDM Filter** | `driverscope wdm` | Filter for plain WDM drivers (skip KMDF — they need INF install) |

### Primitive categories

DriverScope classifies dangerous imports into 18 categories:

- **PhysMem-Map** — `MmMapIoSpace`, `MmMapLockedPages`, etc.
- **PhysMem-Section** — `ZwMapViewOfSection`, `ZwOpenSection`
- **CrossProc-VA** — `MmCopyVirtualMemory`, `ZwReadVirtualMemory`
- **CR-Regs** — `__readcr0`, `__readcr3`, `__writecr4`
- **MSR** — `__readmsr`, `__writemsr`
- **KernelExec** — `MmGetSystemRoutineAddress`, `ZwSetSystemInformation`
- **Callback-Bypass** — `ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutine`
- **I/O-Port** — `READ_PORT_UCHAR`, `__inbyte`
- ... and 10 more (see `scanner.py` for the full list)

## Installation

```bash
pip install -e .

# Optional: Capstone for advanced IOCTL extraction
pip install capstone
```

Requires Python 3.10+ and Windows (for system driver scanning and KDU extraction).

## Quick start

```bash
# Scan a single driver
driverscope scan MyDriver.sys

# Scan a directory with LOLDrivers + MS blocklist cross-reference
driverscope scan C:\drivers --lol --blocklist

# Full zero-day hunt on your system
driverscope hunt

# Deep scan (includes DriverStore + Program Files — slower)
driverscope hunt --deep --export findings.json

# Extract IOCTL dispatch surface
driverscope ioctl SomeDriver.sys --json

# Harvest OEM tools and scan the extracted drivers
driverscope harvest --output ./harvested --scan

# Search LOLDrivers by region
driverscope regional --region CN,JP

# Filter for WDM-only physmem drivers
driverscope wdm C:\drivers
```

## VirusTotal integration

```bash
# Set your API key
export VT_API_KEY=your_key_here

# Scan with VT hash lookups (auto-throttles to free tier: 4 req/min)
driverscope scan C:\drivers --vt

# Or pass the key directly
driverscope scan driver.sys --vt --vt-key your_key_here
```

VT results are cached locally (`vt_cache.json`, 30-day TTL) so re-scans are instant.

## Architecture

```
driverscope/
├── cli.py          # Unified CLI entry point
├── scanner.py      # Core PE import scanner + VT/LOLDrivers/MS Blocklist
├── ioctl.py        # Static IOCTL dispatch extraction (Capstone optional)
├── hunter.py       # Zero-day hunting pipeline with novelty scoring
├── harvester.py    # OEM tool downloader + .sys extractor
├── regional.py     # Regional vendor search (CN/KR/JP/TW/RU)
├── wdm_filter.py   # WDM vs KMDF filter
└── kdu.py          # KDU RMDX database parser
```

## How the zero-day pipeline works

1. **Collect** — Gather .sys files from System32\drivers, DriverStore, Program Files, or custom paths
2. **Scan** — Parse PE imports and classify into primitive categories
3. **Filter known** — Remove drivers already in LOLDrivers.io, MS Blocklist, or KDU
4. **Filter inbox** — Remove MS inbox drivers (ntfs.sys, tcpip.sys, etc.)
5. **Score** — Rank remaining candidates by:
   - Primitive class weights (PhysMem-Map=30, CrossProc-VA=20, etc.)
   - Signed bonus (+20)
   - x64 bonus (+10)
   - Device name presence (+10)
   - IOCTL count bonus (+15)
6. **Report** — Top candidates with full detail (SHA256, signer, device names, IOCTLs)

## Responsible disclosure

This tool is for **defensive security research**. If you discover a novel vulnerable driver:

1. **Do not** publish the vulnerability details publicly before disclosure
2. **Report** to the vendor (if contactable) and Microsoft via [MSRC](https://msrc.microsoft.com/)
3. **Request** the driver be added to the [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
4. Consider submitting to [LOLDrivers.io](https://www.loldrivers.io/) after the vendor has had time to respond

## Related work

- [LOLDrivers.io](https://www.loldrivers.io/) — Living Off The Land Drivers catalog
- [KDU](https://github.com/hfiref0x/KDU) — Kernel Driver Utility by hfiref0x
- [BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) — BYOVD research and POCs
- [IOCTLance](https://github.com/ioctlance/ioctlance) — Symbolic execution for WDM driver vuln discovery
- [vulnerable-drivers-ex](https://github.com/lallouslab/vulnerable-drivers-ex) — Import-based driver scanning

## License

MIT
