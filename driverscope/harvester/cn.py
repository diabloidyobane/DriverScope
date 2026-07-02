"""Chinese OEM mirrors and Chinese-market utility tools. Many of these carry
signed drivers that never appear on English vendor pages. They also often ship
older signed builds still valid under the current WHCP root.

NOTE on URLs: Chinese CDN endpoints move often. The harvester treats a 404 as
non-fatal and moves on. Adjust when new links appear.
"""

SOURCES = [
    # ── Lenovo China ──────────────────────────────────────────────────
    {
        "name": "Lenovo_QuickFix_CN",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://download.lenovo.com/lenovo/content/qf/LenovoQuickFix.zip",
        ],
        # ABANDONED: Lenovo QuickFix (CN) product decommissioned; no successor product on Lenovo global download portal. Standalone CN QuickFix suite retired ~2022.
        "notes": "Lenovo QuickFix — carries Lenovo helper drivers",
    },
    {
        "name": "Lenovo_SystemUpdate_CN",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://download.lenovo.com/pccbbs/thinkvantage_en/systemupdate.exe",
        ],
        # checked: Lenovo System Update filename dropped version suffix; canonical is systemupdate.exe (or systemupdate_5.08.exe). Update: 
        "notes": "Lenovo System Update — bundles ThinkPad management drivers",
    },
    {
        "name": "Lenovo_VantageService",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://download.lenovo.com/vantage/vantageservice/lenovovantageservice.msi",
        ],
        # ABANDONED: lenovovantageservice.msi no longer distributed standalone; Lenovo Vantage now distributed exclusively via Microsoft Store (apps.microsoft.com/detail/9wzdncrfj4mv). Non-Store MSI requires Lenovo Commer
        "notes": "Lenovo Vantage Service — carries LenovoDiag driver",
    },

    # ── Huawei / MateBook ──────────────────────────────────────────────
    {
        "name": "Huawei_PCManager",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://consumer.huawei.com/content/dam/huawei-cbg-site/cn/mkt/pcmanager/PCManager_Setup.zip",
        ],
        # ABANDONED: Huawei PC Manager only installs on Huawei-branded hardware (BIOS-check gated); download requires Huawei ID login. Not un-authenticated.
        "notes": "Huawei PC Manager — MateBook signed helper driver",
    },
    {
        "name": "Honor_Suite",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://res5.hihonorcdn.com/pub_hosting/honor_suite/HonorSuiteInstaller.zip",
        ],
        # ABANDONED: res5.hihonorcdn.com DNS dead. HonorSuite v11.0.0.726 for Windows/macOS but download only linked from honor.com/global with region-gated access; no un-authenticated direct URL.
        "notes": "Honor Suite — Honor MagicBook helpers",
    },

    # ── Xiaomi laptops ─────────────────────────────────────────────────
    {
        "name": "Xiaomi_MiSmart",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://cnbj1.fds.api.mi-img.com/mi-smart/misn.zip",
        ],
        # ABANDONED: cnbj1.fds.api.mi-img.com DNS dead. Xiaomi Mi Smart Share PC client for Windows discontinued; Xiaomi migrated all sharing to Android-only ShareMe app.
        "notes": "Xiaomi Mi Smart — laptop management helpers",
    },

    # ── LuDaShi / 鲁大师 (very common Chinese hardware ID tool) ─────────
    {
        "name": "LuDaShi",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://cdn-file-ssl-pc.ludashi.com/inst_pkgs/ludashi/6.1026.4680.626/ludashi_minisetup.exe",
            "https://d.ludashi.com/download/LuDaShiSetup.exe",
        ],
        # checked: v6.1026.4680.626 released 2026-06-29, ~221 MB. CDN is Chinese-only but reachable un-authenticated.
        "notes": "LuDaShi (Master Lu) — Chinese hardware detector, physmem driver",
    },

    # ── 360 Total Security Kernel Helper (drops kernel helpers) ─────────
    {
        "name": "360TotalSecurity",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://free.360totalsecurity.com/totalsecurity/360TS_Setup_11.0.0.1314.exe",
        ],
        # checked: v11.0.0.1314 released 2026-03-30, ~109 MB. Path was wrong (needed version suffix): 360TS_Setup_Mini.exe still 200 but is
        "notes": "360 Total Security — Qihoo 360 signed kernel helpers",
    },

    # ── QQ PC Manager / Tencent PC Manager ──────────────────────────────
    {
        "name": "Tencent_PCManager",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://guanjia.qq.com/pcmgr/setup.exe",
        ],
        # ABANDONED: guanjia.qq.com/pcmgr/setup.exe dead. Tencent PC Manager EN international build v12.3.26601 last hosted on 3rd-party mirrors (clubic/lo4d); no canonical Tencent CDN URL for international build. CN buil
        "notes": "Tencent PC Manager — Tencent-signed kernel driver",
    },

    # ── Baidu Anti-Malware ──────────────────────────────────────────────
    {
        "name": "Baidu_AntivirusInternational",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://av.baidu.com/download/BAV_Setup_International.exe",
        ],
        # ABANDONED: Baidu Antivirus discontinued Dec 2018 / removed from download servers 2019. av.baidu.com dead. Product officially retired.
        "notes": "Baidu Antivirus Intl — Baidu-signed kernel components",
    },

    # ── IObit ─ (Chinese/HK origin, ubiquitous "PC utility" installer) ──
    {
        "name": "IObit_DriverBooster_Portable",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://cdn.iobit.com/dl/driver_booster_setup.exe",
        ],
        # checked: URL confirmed valid; v13.5.0.359 released 2026-06-06. Original URL was correct — likely transient DNS/net glitch during 
        "notes": "IObit Driver Booster — bundles IObit signed drivers",
    },
    {
        "name": "IObit_AdvancedSystemCare",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://cdn.iobit.com/dl/advanced-systemcare-setup.exe",
        ],
        # checked: 200 OK, application/octet-stream, ~40MB+ (verified binary download); v19.4.0.210 released 2026-05-27. Path was wrong (as
        "notes": "IObit ASC — kernel monitoring driver",
    },

    # ── SkyView / MICSYS / other niche Chinese HW vendors ───────────────
    {
        "name": "MICSYS_Driver_ZIP",
        "category": "cn_oem",
        "type": "direct",
        "urls": [
            "https://www.micsystech.com/tools/MICSYS_Utilities.zip",
        ],
        # ABANDONED: micsystech.com DNS dead. MICSYS Technology Co Ltd is only a driver-signing shell (MsIo64.sys ships inside Gigabyte GCC + MSI Afterburner); no independent utility distribution. Get msio64.sys via those
        "notes": "MICSYS niche driver bundle",
    },
]
