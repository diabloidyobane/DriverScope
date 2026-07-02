"""OEM vendor diagnostic / BIOS / firmware update tool sources.

Every major OEM ships signed kernel drivers that need raw physmem access
for BIOS flash, SMBIOS reads, ACPI table manipulation, and hardware
diagnostics. These drivers use MmMapIoSpace, ZwMapViewOfSection on
\\Device\\PhysicalMemory, or direct port I/O (in/out instructions) to
reach hardware registers.

Known-vulnerable OEM drivers that have been used in real attacks:
  - Dell dbutil_2_3.sys (CVE-2021-21551) — physmem R/W via IOCTL
  - Dell dbutildrv2.sys — successor, same primitive
  - HP SSDT manipulation driver (CVE-2021-3437)
  - Gigabyte gdrv.sys (CVE-2018-19320) — physmem R/W, in KDU
  - ASUS ASMMAP64.sys — physmem map to userspace, in LOLDrivers
  - MSI ntiolib_x64.sys / winio64.sys — port I/O + physmem
  - ASRock AsrDrv106.sys — physmem R/W, in KDU
  - Biostar bs_def64.sys — physmem, in KDU
"""

SOURCES = [
    # ── Dell ────────────────────────────────────────────────────────────
    {
        "name": "Dell_SupportAssist",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://downloads.dell.com/FOLDER12669064M/1/SupportAssistInstaller.exe",
        ],
        "notes": "Dell SupportAssist. Ships dbutil/dbutildrv2 kernel driver for BIOS/firmware ops. CVE-2021-21551 was physmem R/W via IOCTL.",
    },
    {
        "name": "Dell_CommandUpdate",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://downloads.dell.com/FOLDER12345678M/1/Dell-Command-Update-Windows-Universal-Application_JXTFT_WIN_5.5.0_A00.EXE",
        ],
        "notes": "Dell Command Update. Uses same dbutil driver family for BIOS update flash operations.",
    },
    {
        "name": "Dell_BIOS_Flash_Utility",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=",
        ],
        "notes": "Dell BIOS update .EXE bundles a physmem driver to flash SPI. Each model has its own download; check by service tag.",
    },

    # ── HP ──────────────────────────────────────────────────────────────
    {
        "name": "HP_PC_Hardware_Diagnostics",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://ftp.ext.hp.com/pub/softpaq/sp152001-152500/sp152013.exe",
        ],
        "notes": "HP PC Hardware Diagnostics Windows. UEFI/physmem driver for hardware testing. SP numbers rotate; check HP support.",
    },
    {
        "name": "HP_Support_Assistant",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://ftp.ext.hp.com/pub/softpaq/sp148001-148500/sp148416.exe",
        ],
        "notes": "HP Support Assistant. Bundles kernel driver for BIOS/firmware update. CVE-2021-3437 in etdsupp.sys (SSDT manipulation).",
    },
    {
        "name": "HP_BIOS_Config_Utility",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://ftp.ext.hp.com/pub/softpaq/sp143501-144000/sp143838.exe",
        ],
        "notes": "HP BIOS Configuration Utility (BCU). Needs physmem for WMI-to-BIOS bridge. Signed by HP Inc.",
    },

    # ── Lenovo ──────────────────────────────────────────────────────────
    {
        "name": "Lenovo_System_Update",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.lenovo.com/pccbbs/thinkvantage_en/systemupdate5.08.04.0025.exe",
        ],
        "notes": "Lenovo System Update. Bundles LenovoDiagnosticsDriver for physmem/SMBIOS access.",
    },
    {
        "name": "Lenovo_Diagnostics",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.lenovo.com/pccbbs/thinkvantage_en/ldiag_4.51.0_setup.exe",
        ],
        "notes": "Lenovo Diagnostics for Windows. Kernel driver reads physmem for memory/CPU/storage tests. Lenovo-signed.",
    },
    {
        "name": "Lenovo_Vantage",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.lenovo.com/us/en/software/vantage/",
        ],
        "notes": "Lenovo Vantage (UWP, MS Store). Backend service uses kernel driver for BIOS settings and firmware update.",
    },

    # ── ASUS ────────────────────────────────────────────────────────────
    {
        "name": "ASUS_AI_Suite_3",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.asus.com/motherboards-components/motherboards/all-series/filter/?SubSeries=702",
        ],
        "notes": "ASUS AI Suite 3. Ships ASMMAP64.sys (physmem map to usermode) + AsIO.sys (port I/O). ASMMAP64 is in LOLDrivers. Download per-board from ASUS support.",
    },
    {
        "name": "ASUS_Armoury_Crate",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://dlcdnets.asus.com/pub/ASUS/mb/14Utilities/ArmouryCrateInstallTool.zip",
        ],
        "notes": "ASUS Armoury Crate installer. Installs AsIO3.sys kernel driver (port I/O, physmem). Lighter than AI Suite.",
    },
    {
        "name": "ASUS_WinFlash",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.asus.com/support/",
        ],
        "notes": "ASUS WinFlash BIOS updater. Must have physmem for SPI flash. Download from individual laptop support pages.",
    },

    # ── MSI ─────────────────────────────────────────────────────────────
    {
        "name": "MSI_Center",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.msi.com/uti_exe/desktop/MSI-Center-Installer.exe",
        ],
        "notes": "MSI Center (replaces Dragon Center). Ships ntiolib_x64.sys (port I/O + physmem) and winio64.sys. Both in LOLDrivers/KDU.",
    },
    {
        "name": "MSI_LiveUpdate",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.msi.com/uti_exe/desktop/LiveUpdate.zip",
        ],
        "notes": "MSI Live Update 6. BIOS/firmware updater. Uses same ntiolib driver family for flash operations.",
    },
    {
        "name": "MSI_Afterburner",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.msi.com/uti_exe/vga/MSIAfterburnerSetup.zip",
        ],
        "notes": "MSI Afterburner. RTCore64.sys kernel driver for GPU register R/W and PCI config access. CVE-2019-16098 = physmem R/W. In LOLDrivers.",
    },

    # ── Gigabyte ────────────────────────────────────────────────────────
    {
        "name": "Gigabyte_APP_Center",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.gigabyte.com/Support/Utility",
        ],
        "notes": "Gigabyte APP Center + @BIOS. Ships gdrv.sys (CVE-2018-19320, physmem R/W via IOCTL). In KDU. Download per-board from Gigabyte support.",
    },
    {
        "name": "Gigabyte_EasyTune",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.gigabyte.com/Support/Utility",
        ],
        "notes": "Gigabyte EasyTune OC utility. Uses gdrv2.sys (updated driver, same physmem primitive). Per-board download.",
    },
    {
        "name": "Gigabyte_SIV",
        "category": "oem",
        "type": "direct",
        "urls": [
            "https://download.gigabyte.com/FileList/Utility/mb_utility_systeminfomationviewer_B23.0606.1.zip",
        ],
        "notes": "Gigabyte System Information Viewer. Kernel driver for temp/voltage/fan, uses physmem for SuperIO access.",
    },

    # ── ASRock ──────────────────────────────────────────────────────────
    {
        "name": "ASRock_Utility",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.asrock.com/support/index.asp",
        ],
        "notes": "ASRock A-Tuning / Instant Flash. Ships AsrDrv106.sys (physmem R/W via IOCTL, in KDU). Per-board download.",
    },

    # ── Biostar ─────────────────────────────────────────────────────────
    {
        "name": "Biostar_Racing_GT",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.biostar.com.tw/app/en/support/download.php",
        ],
        "notes": "Biostar Racing GT / Vivid LED utility. Ships bs_def64.sys / bs_i2c64.sys (physmem, in KDU). Per-board download.",
    },

    # ── AMI (BIOS vendor) ──────────────────────────────────────────────
    {
        "name": "AMI_AFUWIN",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.ami.com/bios-uefi-utilities/",
        ],
        "notes": "AMI Firmware Update (AFUWIN). amifldrv64.sys = physmem + SPI flash R/W. AMI-signed. Requires AMI account for some downloads.",
    },

    # ── Insyde (BIOS vendor) ───────────────────────────────────────────
    {
        "name": "Insyde_H2OFFT",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.insyde.com/products",
        ],
        "notes": "Insyde H2OFFT (firmware flash tool). Kernel driver for SPI physmem access. Ships embedded in OEM BIOS updates (Dell, HP, Lenovo laptops).",
    },

    # ── Phoenix (BIOS vendor) ──────────────────────────────────────────
    {
        "name": "Phoenix_WinPhlash",
        "category": "oem",
        "type": "landing",
        "urls": [
            "https://www.phoenix.com/phoenix-securecore/",
        ],
        "notes": "Phoenix WinPhlash. Kernel driver for BIOS flash via physmem. Less common than AMI/Insyde; found in older Sony/Toshiba laptops.",
    },
]
