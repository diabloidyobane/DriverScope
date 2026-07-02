"""System-information tool sources. Nearly all ship a winring0-lineage physmem
driver, and each vendor's signed build has a different Authenticode hash,
which matters for WDAC blocklist coverage.
"""

SOURCES = [
    {
        "name": "HWiNFO64_Portable",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            # HWiNFO stable download URL rotates; give a stable landing and a common tag.
            "https://sourceforge.net/projects/hwinfo/files/Windows_Portable/hwi_834.zip/download",
            "https://www.hwinfo.com/files/hwi_800.zip",
        ],
        # checked: sourceforge mirror, ~18.6MB, current stable
        "notes": "HWiNFO — signed physmem/MSR driver (HWiNFO32.SYS / HWiNFO64.SYS)",
    },
    {
        "name": "OCCT_Personal",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.ocbase.com/download/edition:Personal/os:Windows",
        ],
        # checked: vendor form page yields the .exe; dl.ocbase.com/per/stable/OCCT.exe 301s here; OCCT v17.0.1 released 2026-07-01
        "notes": "OCCT — bundles OCCT-signed driver used for MSR/temp readings",
    },
    {
        "name": "CoreTemp_Portable",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.alcpu.com/CoreTemp/CoreTemp64.zip",
            "https://www.alcpu.com/CoreTemp/php/download.php?p=CoreTemp.zip",
        ],
        # checked: 200 OK, application/zip, ~760KB (verified binary download)
        "notes": "Core Temp — MSR driver (CoreTempReader.sys), often un-blocklisted",
    },
    {
        "name": "Speccy_Portable",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://download.ccleaner.com/spf13484.exe",
        ],
        # checked: Speccy 1.34.84 released 2026-06-22, ccleaner CDN pattern; upstream 200
        "notes": "Speccy — Piriform-signed hardware info tool",
    },
    {
        "name": "Sandra_Lite",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.sisoftware.co.uk/download-lite/",
        ],
        # checked: vendor uses per-mirror redirect form (no direct URL). v31.137 latest; mirror at TechSpot: https://www.techspot.com/downl
        "notes": "SiSoftware Sandra Lite — full HW sensor stack, kernel driver",
    },
    {
        "name": "IntelPowerGadget",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.intel.com/content/dam/develop/external/us/en/documents/intelpowergadget-3.5.exe",
        ],
        # ABANDONED: Intel officially discontinued Power Gadget in Oct 2023; removed from download servers Dec 2023 (INTEL-SA-01037 vulnerability). Intel recommends PCM as replacement.
        "notes": "Intel Power Gadget — MSR reader, Intel-signed",
    },
    {
        "name": "AIDA64_Extreme_Trial",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://download.aida64.com/aida64extreme830.exe",
            "https://download.aida64.com/aida64extreme720.zip",
        ],
        # checked: confirmed direct link on aida64.com; v8.30.8300 stable, ~59MB self-installer EXE
        "notes": "AIDA64 Extreme — full physmem/MSR driver",
    },
    {
        "name": "CrystalDiskInfo_Portable",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://downloads.sourceforge.net/project/crystaldiskinfo/9.9.1/CrystalDiskInfo9_9_1.zip",
        ],
        # checked: sourceforge mirror auto-selected, ~9.9 MB ZIP; version 9.9.1 released 2026-05-23
        "notes": "CrystalDiskInfo — signed SMART/NVMe driver",
    },
    {
        "name": "Argus_Monitor",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.argotronic.com/download/argusmonitor_setup.exe",
        ],
        # checked: vendor now uses www subdomain (SSL fix); official ArgusMonitor_Setup.exe ~14.5MB, v7.4.1.3173 released 2026-05-29
        "notes": "Argus Monitor — MSR/SMART reader, Argotronic-signed",
    },
    {
        "name": "SIV",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "http://rh-software.com/siv.zip",
        ],
        # checked: cert mismatch on rh-software.com HTTPS; HTTP only. SIV v5.87 latest. Contains SIV64X.exe internally.
        "notes": "System Information Viewer — Ray Hinchliffe kernel driver",
    },
]
