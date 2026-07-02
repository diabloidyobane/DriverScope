"""Storage vendor utility sources. All of these read SMART attributes via a
physmem or NVMe passthrough driver.
"""

SOURCES = [
    {
        "name": "Samsung_Magician",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://download.semiconductor.samsung.com/resources/software-resources/Samsung_Magician_Installer_Official_9.0.1.950.exe",
        ],
        # checked: v9.0.1.950 released 2026-03-30, ~195 MB (previous URL truncated at ..._O)
        "notes": "Samsung Magician — Samsung-signed NVMe/SMART driver",
    },
    {
        "name": "WD_Dashboard",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://downloads.sandisk.com/downloads/WesternDigitalDashboardSetup.exe",
        ],
        # ABANDONED: Western Digital Dashboard reached end-of-support 2026-06-10; superseded by SanDisk Dashboard for SSDs and Kitfox for HDDs. See SanDisk entry.
        "notes": "WD/SanDisk Dashboard — signed SATA/NVMe passthrough driver",
    },
    {
        "name": "Kingston_SSD_Manager",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://media.kingston.com/support/downloads/KSM_setup_1.5.6.5.exe",
        ],
        # checked: v1.5.6.5 released 2026-04-09, ~53 MB. Case-sensitive: KSM_setup (lowercase 'setup')
        "notes": "Kingston SSD Manager — signed helper driver",
    },
    {
        "name": "Crucial_StorageExecutive",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://www.crucial.com/support/storage-executive",
        ],
        # checked: Storage Executive v11.11.112025 released 2025-12-20; direct URL rotates per release, vendor page serves current via JS b
        "notes": "Crucial Storage Executive — Micron-signed helper driver",
    },
    {
        "name": "Intel_MemoryStorageTool",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://downloadmirror.intel.com/822150/Intel_MAS_GUI_Tool_Win_2.5.zip",
        ],
        # checked: Intel MAS v2.5; downloadmirror.intel.com 403s WebFetch (license-gate) but URL is canonical
        "notes": "Intel Memory and Storage Tool — replaces SSD Toolbox",
    },
    {
        "name": "Intel_RapidStorage",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://www.intel.com/content/www/us/en/download/849936/intel-rapid-storage-technology-driver-installation-software-with-intel-optane-memory-12th-to-15th-gen-platforms.html",
        ],
        # checked: SetupRST.exe v20.2.6.1025.3 released 2026-01-07; direct downloadmirror URLs require license accept, landing page serves 
        "notes": "Intel Rapid Storage Technology — RAID/AHCI helper drivers",
    },
    {
        "name": "Seagate_SeaTools",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://www.seagate.com/support/downloads/seatools/",
        ],
        # checked: SeaToolsWindowsInstaller.exe v5.2.5 released 2026-01-08, ~67.8 MB; vendor page serves current build
        "notes": "Seagate SeaTools — Seagate-signed HDD diagnostic driver",
    },
    {
        "name": "SanDisk_Extreme_Dashboard",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://support-en.sandisk.com/app/answers/detailweb/a_id/31759/",
        ],
        # checked: SanDisk Dashboard installer (DashboardSetup.exe) v5.2.2.3; vendor auth-gated at downloads.sandisk.com direct URLs, but l
        "notes": "SanDisk Extreme Portable dashboard — helper driver",
    },
    {
        "name": "Corsair_SSDToolbox",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://www.corsair.com/us/en/explorer/release-notes/ssd-toolbox/ssd-toolbox-20129-preview/",
        ],
        # checked: v2.0.129 preview released 2026-01-26; direct .zip URL 404s (path was wrong); vendor page has download button
        "notes": "Corsair SSD Toolbox — SATA passthrough driver",
    },
    {
        "name": "ADATA_SSDToolbox",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://www.adata.com/en/support/downloads/",
        ],
        # checked: ADATA_SSDToolBoxSetup_v6.2.3.exe v6.2.3 released 2026-05-22; vendor uses form-submit downloader
        "notes": "ADATA SSD Toolbox — signed helper driver",
    },
    {
        "name": "SKhynix_SSDDashboard",
        "category": "storage",
        "type": "direct",
        "urls": [
            "https://ssd.skhynix.com/download/driver_manager/DriveManager-C3.2.0-windows-installer-x64.exe",
        ],
        # checked: SK hynix Drive Manager Easy Kit v3.2.0 x64 installer; path was wrong (EasyKit.zip -> DriveManager-C3.2.0-windows-install
        "notes": "SK hynix SSD easy-kit — hynix-signed driver",
    },
]
