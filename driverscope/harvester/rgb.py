"""RGB / AIO / OC control panel sources. Every major peripheral ecosystem
ships one or more signed kernel drivers to read fan speeds, control lighting,
or query I2C EEPROMs on the RAM. They are almost always signed by the vendor
directly (not Microsoft WHQL), so blocklist coverage lags real deployment.
"""

SOURCES = [
    # ── Corsair ─────────────────────────────────────────────────────────
    {
        "name": "Corsair_iCUE",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://www3.corsair.com/software/CUE_V5/public/modules/windows/installer/Install%20iCUE.exe",
        ],
        # checked: 200 OK, ~3.3 MB modular installer (VERIFIED binary download); v5.47.101 released 2026-06-23
        "notes": "Corsair iCUE — bundles CorsairLLAccess/CorsairHWiO signed drivers",
    },
    {
        "name": "Corsair_LinkPortable",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://downloads.corsair.com/Files/Corsair-Link-4/Install-CorsairLink4.exe",
        ],
        # ABANDONED: Corsair Link 4 discontinued 2020, replaced by iCUE; legacy 4.9.9.3 only via 3rd-party mirrors (Softpedia/MajorGeeks). Vendor no longer hosts.
        "notes": "Corsair Link 4 (legacy) — old signed driver still valid",
    },

    # ── Razer ───────────────────────────────────────────────────────────
    {
        "name": "Razer_Synapse",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://rzr.to/synapse-3-pc-download",
        ],
        "notes": "Razer Synapse 3 — bundles rzudd.sys / rzpnk.sys",
    },
    {
        "name": "Razer_Cortex",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://rzr.to/cortex-pc-download",
        ],
        # checked: official rzr.to shortlink pattern; RazerCortexInstaller.exe v11.8.1.3 released 2026-05-26, ~14.23 MB
        "notes": "Razer Cortex — carries rzudd.sys",
    },

    # ── ASUS / ASUSTeK ──────────────────────────────────────────────────
    {
        "name": "ASUS_ArmouryCrate",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://asusarmourycrate.com/ArmouryCrateInstallTool.zip",
        ],
        # checked: official 2.20 MB install-tool ZIP (contains ArmouryCrateInstaller.EXE); dlcdnets.asus.com fallback: https://dlcdnets.asu
        "notes": "ASUS Armoury Crate — asIO3.sys physmem/MSR driver",
    },
    {
        "name": "ASUS_AISuite3",
        "category": "overclock",
        "type": "direct",
        "urls": [
            "https://dlcdnets.asus.com/pub/ASUS/mb/Utilities/AISuite3.zip",
        ],
        # ABANDONED: AI Suite 3 only distributed per-motherboard-model via ASUS Download Center; no single canonical URL. Example model-specific: https://dlcdnets.asus.com/pub/ASUS/misc/utils/ASUS_AISuite3_Win7-81-10_V101
        "notes": "ASUS AI Suite 3 — asIO.sys / atkacpi legacy",
    },
    {
        "name": "ASUS_GPUTweak",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://www.asus.com/supportonly/gpu%20tweak%20iii/helpdesk_download/",
        ],
        # checked: GPU Tweak III v2.69 (2026-05-05); ASUS uses OS-gated download center — direct dlcdnets URLs rotate per release. No stabl
        "notes": "ASUS GPU Tweak III — bundles GpuTweak_ASUSCert driver",
    },

    # ── MSI ─────────────────────────────────────────────────────────────
    {
        "name": "MSI_Afterburner",
        "category": "overclock",
        "type": "direct",
        "urls": [
            "https://www.msi.com/Landing/afterburner/graphics-cards",
        ],
        # checked: MSI Afterburner 4.6.7 latest; download-eu.msi.com host dead. Landing page auto-serves current EXE via JS. Guru3D mirror:
        "notes": "MSI Afterburner — bundles RTCore64 physmem/MSR driver",
    },
    {
        "name": "MSI_DragonCenter",
        "category": "overclock",
        "type": "direct",
        "urls": [
            "https://download.msi.com/uti_exe/desktop/DragonCenter.zip",
        ],
        # ABANDONED: MSI Dragon Center superseded by MSI Center (2021). Legacy download still exists at https://www.msi.com/Landing/dragon-center-download/nb but no canonical direct URL — served via JS dropdown per model.
        "notes": "MSI Dragon Center — legacy bundle including signed HW driver",
    },
    {
        "name": "MSI_Kombustor",
        "category": "hwmon",
        "type": "direct",
        "urls": [
            "https://gpuscore.top/msi/MSI_Kombustor4_Setup_v4.1.36_x64.exe",
        ],
        # checked: v4.1.36 x64 setup ~92 MB; official Geeks3D repo now hosted at gpuscore.top (302 from geeks3d.com/dl/get/837)
        "notes": "MSI Kombustor — GPU stress with helper driver",
    },

    # ── Gigabyte ────────────────────────────────────────────────────────
    {
        "name": "Gigabyte_RGBFusion2",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://download.gigabyte.com/FileList/Utility/GCC_26.01.05.01.zip",
        ],
        # checked: RGB Fusion 2 is now a module inside GIGABYTE Control Center; standalone RGB Fusion 2 discontinued. Note: earlier standal
        "notes": "Gigabyte RGB Fusion 2 — bundles gdrv.sys",
    },
    {
        "name": "Gigabyte_EasyTune",
        "category": "overclock",
        "type": "direct",
        "urls": [
            "https://download.gigabyte.com/FileList/Utility/mb_utility_easytune_B23.1013.1.zip",
        ],
        # ABANDONED: Standalone EasyTune deprecated; folded into GIGABYTE Control Center (GCC). See RGB Fusion entry for GCC URL.
        "notes": "Gigabyte EasyTune — historical CVE-carrying gdrv.sys",
    },

    # ── EVGA ────────────────────────────────────────────────────────────
    {
        "name": "EVGA_PrecisionX1",
        "category": "overclock",
        "type": "direct",
        "urls": [
            "https://www.evga.com/precisionx1/EVGA_Precision_X1_1.3.7.0.zip",
        ],
        # checked: v1.3.7.0 latest (EVGA exited GPU market 2022 but Precision X1 still hosted); vendor download page returns ZIP link
        "notes": "EVGA Precision X1 — ring0 GPU driver",
    },

    # ── SteelSeries / Logitech / NZXT ───────────────────────────────────
    {
        "name": "SteelSeries_GG",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://steelseries.com/gg/download",
        ],
        # checked: v114.0.0 released 2026-07-01 (~660 MB); vendor uses dynamic redirect from /download endpoint. Path was wrong: /downloads
        "notes": "SteelSeries GG — carries SteelSeries-signed helper driver",
    },
    {
        "name": "Logitech_GHUB",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://download01.logi.com/web/ftp/pub/techsupport/gaming/lghub_installer.exe",
        ],
        "notes": "Logitech G HUB — bundles LGHUB kernel helper",
    },
    {
        "name": "NZXT_CAM_Installer",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://nzxt.com/pages/cam",
        ],
        # checked: camwebapp.com is dead; v4.76.3 latest ~97.8 MB. Landing page nzxt.com/pages/cam serves current build via JS.
        "notes": "NZXT CAM installer — bundles CAM signed helper driver",
    },

    # ── Wallpaper Engine (Steam-distributed, but sometimes has resource driver) ──
    {
        "name": "OpenRGB_Nightly",
        "category": "rgb",
        "type": "github",
        "repo": "CalcProgrammer1/OpenRGB",
        "asset_pattern": r"OpenRGB.*Windows.*(?:64|x64).*\.zip$",
        # checked: OpenRGB moved from GitLab to Codeberg; v1.0rc3 released 2026-06-28
        "notes": "OpenRGB nightly — bundles inpout / SMBus helper",
    },
    {
        "name": "SignalRGB",
        "category": "rgb",
        "type": "direct",
        "urls": [
            "https://signalrgb.io/download.html",
        ],
        # checked: cdn.signalrgb.com dead; signalrgb.io serves Install_SignalRgb.exe ~282MB, v2.5.72.0 released 2026-06-26
        "notes": "SignalRGB — signed WhirlwindFX driver",
    },
    {
        "name": "GLightbox_JackNet_RGB_Sync",
        "category": "rgb",
        "type": "github",
        "repo": "JackNet3/RGB-Sync-Studio",
        "asset_pattern": r"\.zip$",
        "notes": "JackNet RGB Sync — carries multiple vendor drivers via plugins",
    },
]
