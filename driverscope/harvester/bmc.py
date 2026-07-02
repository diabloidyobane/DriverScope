"""BMC / server management tool sources. Enterprise WHQL-signed and rarely on
any consumer blocklist, so they clear WDAC in the wild much longer than
gaming-vendor drivers.
"""

SOURCES = [
    {
        "name": "Dell_OpenManage_ServerAdmin",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://www.dell.com/support/kbdoc/en-us/000132087/support-for-dell-emc-openmanage-server-administrator-omsa",
        ],
        # checked: OMSA v11.1.0.0 latest; FOLDER10855872M dead. Dell rotates FOLDER IDs per release. Landing KB doc links to current build.
        "notes": "Dell OMSA — hapi driver + PowerEdge BMC helpers",
    },
    {
        "name": "Dell_CommandUpdate",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://dl.dell.com/FOLDER14424243M/1/Dell-Command-Update-Application_RXT5N_WIN64_5.7.0_A00.EXE",
        ],
        # checked: v5.7.0 latest; new FOLDER ID14424243M (old FOLDER10858920M dead)
        "notes": "Dell Command Update — carries Dell-signed helpers",
    },
    {
        "name": "HP_iLO_Utility",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://support.hpe.com/connect/s/softwaredetails?language=en_US&collectionId=MTX-UNITY_C9113",
        ],
        # checked: HPE Lights-Out Online Configuration Utility for Windows x64; vendor collection page (individual .exe URLs require sessio
        "notes": "HPE iLO Amplifier utility — HPE-signed physmem driver",
        # Sometimes redirects; harvester falls back per URL.
    },
    {
        "name": "HP_SmartArray_Utility",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://downloads.linux.hpe.com/repo/mcp/tools/HP-SmartArray-Utility.zip",
        ],
        # ABANDONED: downloads.linux.hpe.com/repo/mcp path is Linux-only Management Component Pack. HP SmartArray Windows utilities distributed via HPE Support Center per-server model (kmpmoid gated), no canonical direct 
        "notes": "HP SmartArray CLI — HPE-signed RAID passthrough driver",
    },
    {
        "name": "Supermicro_IPMICFG",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://www.supermicro.com/wdl/utility/IPMICFG/IPMICFG_1.35.1_build.230912.zip",
        ],
        # checked: v1.35.1 build 230912; hostname was wrong (wftp -> wdl)
        "notes": "Supermicro IPMICFG — ipmidrv helper",
    },
    {
        "name": "Supermicro_SUM",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://www.supermicro.com/Bios/sw_download/1026/sum_2.15.0_Linux_x86_64_20251104.tar.gz",
            "https://www.supermicro.com/wftp/utility/SUM/sum_2.9.0_Win_x86_64_20220211.zip",
        ],
        # checked: SUM v2.15.0 (2025-11-04) latest; wftp path is dead, sw_download path works. Windows variant per-page-request only.
        "notes": "Supermicro SUM — BMC firmware helper",
    },
    {
        "name": "Lenovo_XClarity_Essentials",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://datacentersupport.lenovo.com/us/en/solutions/HT116433",
        ],
        # checked: XClarity Essentials suite; direct binaries gated by product-selection form. Landing page serves per-tool downloader.
        "notes": "Lenovo XClarity Essentials — server management driver",
    },
    {
        "name": "IntelServer_SetSelectionUtility",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://www.intel.com/content/www/us/en/download/19765/intel-server-configuration-utility.html",
        ],
        # checked: Intel Server Configuration Utility (SysCfgUtility renamed); downloadmirror.intel.com/29740 dead. Landing page serves cur
        "notes": "Intel Server Set Selection Utility — SMI helper driver",
    },
    {
        "name": "Broadcom_MegaRAID_Storage",
        "category": "bmc",
        "type": "direct",
        "urls": [
            "https://docs.broadcom.com/docs/17.05.06.00_MSM_Windows.zip",
        ],
        # checked: MegaRAID Storage Manager v17.05.06.00 Windows ZIP; canonical docs.broadcom.com direct URL
        "notes": "Broadcom MegaRAID Storage Manager — LSI-signed passthrough",
    },
]
