"""Enterprise VPN / endpoint security client sources.

Every vendor here ships a Windows client installer containing WHCP-signed
kernel drivers: TUN/TAP adapters, NDIS miniport/filter drivers, kernel
firewalls, and endpoint compliance agents. Enterprise signers rarely land
on the MS consumer blocklist or LOLDrivers.

These drivers typically have:
  - NDIS miniport/filter (raw packet I/O from usermode)
  - Virtual network adapter (TUN/TAP)
  - Kernel-mode firewall hooks
  - IOCTL handlers for config that may accept arbitrary pointers

Several have had public CVEs in their kernel components (Fortinet,
Ivanti/Pulse, Palo Alto, Cisco).
"""

SOURCES = [
    # ── Fortinet ─────────────────────────────────────────────────────────
    {
        "name": "FortiClient_VPN",
        "category": "vpn",
        "type": "direct",
        "urls": [
            "https://links.fortinet.com/forticlient/win/vpnagent",
        ],
        "notes": "FortiClient VPN-only (free). Ships ppp*.sys, fortishield.sys, NDIS miniport. CVE-2022-26113 in kernel driver.",
    },

    # ── Ivanti / Pulse Secure ────────────────────────────────────────────
    {
        "name": "Ivanti_Secure_Access",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://forums.ivanti.com/s/product-downloads",
        ],
        "notes": "Ivanti Secure Access Client (ex-Pulse Secure). dsNcAdpt.sys TUN adapter + endpoint compliance driver. Auth required for direct download.",
    },

    # ── SonicWall ────────────────────────────────────────────────────────
    {
        "name": "SonicWall_NetExtender",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://mysonicwall.com/muir/freedownloads",
        ],
        "notes": "SonicWall NetExtender. Virtual NIC kernel driver. Requires MySonicWall account login despite 'freedownloads' path. Client also served from appliance user portal.",
    },

    # ── Palo Alto ────────────────────────────────────────────────────────
    {
        "name": "PaloAlto_GlobalProtect",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.paloaltonetworks.com/vpn-client",
        ],
        "notes": "GlobalProtect agent. pangp*.sys virtual adapter + host firewall. Auth gated via support.paloaltonetworks.com for direct MSI.",
    },

    # ── Cisco ────────────────────────────────────────────────────────────
    {
        "name": "Cisco_SecureClient",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.cisco.com/c/en/us/support/security/anyconnect-secure-mobility-client/series.html",
        ],
        "notes": "Cisco Secure Client (ex-AnyConnect). acsock.sys, acumbrellanetwork.sys, NDIS 6 filter. Requires Cisco login for downloads.",
    },

    # ── Citrix ───────────────────────────────────────────────────────────
    {
        "name": "Citrix_Gateway_Plugin",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.citrix.com/downloads/citrix-gateway/",
        ],
        "notes": "Citrix Gateway Plug-in + EPA. ctxusbm.sys, deterministic network enhancer, EPA scan driver. Auth required.",
    },

    # ── Sophos ───────────────────────────────────────────────────────────
    {
        "name": "Sophos_Connect",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.sophos.com/en-us/support/downloads",
        ],
        "notes": "Sophos Connect VPN client. sntp*.sys kernel driver. CDN URL version rotates and 404s quickly; download from Sophos portal or UTM downloads page.",
    },

    # ── WatchGuard ───────────────────────────────────────────────────────
    {
        "name": "WatchGuard_MobileVPN_SSL",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.watchguard.com/wgrd-resource-center/security-software-downloads",
        ],
        "notes": "WatchGuard Mobile VPN with SSL. NDIS TUN/TAP adapter driver. Client usually downloaded from the firewall admin portal, not vendor CDN.",
    },

    # ── Aruba / HPE ──────────────────────────────────────────────────────
    {
        "name": "Aruba_VIA",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://networkingsupport.hpe.com/downloads;products=Aruba%20VIA",
        ],
        "notes": "Aruba VIA VPN client (HPE). Virtual adapter driver. Auth required for download.",
    },

    # ── Zyxel ────────────────────────────────────────────────────────────
    {
        "name": "Zyxel_SecuExtender",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://www.zyxel.com/global/en/support/download",
        ],
        "notes": "Zyxel SecuExtender IPSec/SSL VPN. TUN/TAP driver. Download library requires model-number search; links are dynamically rendered.",
    },

    # ── DrayTek ──────────────────────────────────────────────────────────
    {
        "name": "DrayTek_SmartVPN",
        "category": "vpn",
        "type": "direct",
        "urls": [
            "https://www.draytek.co.uk/support/downloads/software?task=download.send&id=4323:smartvpnclient-572&catid=336",
        ],
        "notes": "DrayTek Smart VPN Client 5.7.2. Virtual NIC kernel driver. ~10 MB. MD5: 7c80908bf9edae56a676b85d55b06a70. No auth required.",
    },

    # ── Juniper (legacy, now Ivanti) ─────────────────────────────────────
    {
        "name": "Juniper_PulseSecure_Legacy",
        "category": "vpn",
        "type": "landing",
        "urls": [
            "https://forums.ivanti.com/s/product-downloads",
        ],
        "notes": "Junos Pulse (EOL). Acquired by Pulse Secure (2014), then Ivanti (2020). Now Ivanti Secure Access Client. Same dsNcAdpt.sys lineage. Juniper download page returns errors.",
    },

    # ── Bonus: OpenVPN / TAP-Windows ─────────────────────────────────────
    {
        "name": "OpenVPN_TAPWindows",
        "category": "vpn",
        "type": "direct",
        "urls": [
            "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.12-I001-amd64.msi",
        ],
        "notes": "OpenVPN ships TAP-Windows6 / Wintun kernel drivers. OpenVPN Inc WHCP-signed. Huge install base.",
    },

    # ── Bonus: WireGuard / Wintun ────────────────────────────────────────
    {
        "name": "WireGuard_Wintun",
        "category": "vpn",
        "type": "direct",
        "urls": [
            "https://download.wireguard.com/windows-client/wireguard-installer.exe",
        ],
        "notes": "WireGuard ships Wintun kernel TUN driver (WireGuard LLC signed). Minimal attack surface but interesting for physmem chain.",
    },
]
