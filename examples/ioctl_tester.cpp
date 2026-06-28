/*
 * ioctl_tester.cpp — minimal validator for a DriverScope-found surface.
 *
 * Build (MSVC):
 *     cl /EHsc ioctl_tester.cpp
 * Build (MinGW):
 *     g++ ioctl_tester.cpp -o ioctl_tester.exe -lstdc++ -static
 *
 * Usage:
 *     ioctl_tester.exe              # run the structured validation sweep
 *     ioctl_tester.exe sweep 0x100  # fuzz-sweep raw IOCTLs (count to try)
 *     ioctl_tester.exe 0x80002048   # single raw IOCTL with zeroed buffers
 *
 * SAFETY: every call goes to ring 0. A bad call against a physmem or MSR
 * driver will BSOD instantly. Use a VM with a snapshot.
 */

#include "comm_template.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void print_result(const char* label, bool ok, DWORD err = 0) {
    if (!err && !ok) err = GetLastError();
    const char* hint =
        err == ERROR_SUCCESS          ? "OK" :
        err == ERROR_INVALID_FUNCTION  ? "handler rejected (wrong code?)" :
        err == ERROR_ACCESS_DENIED     ? "access denied (need elevation?)" :
        err == ERROR_INVALID_PARAMETER ? "struct layout wrong" :
        err == ERROR_BUFFER_OVERFLOW   ? "out buffer too small" :
                                         "see GetLastError";
    printf("  %-30s ok=%d err=%lu (%s)\n", label, ok ? 1 : 0, err, hint);
}

static int structured_sweep(ExampleDriver& drv) {
    printf("[*] Structured validation sweep\n");

    /* 1. Probe — does the handler respond at all? */
    uint32_t status = 0;
    bool ok = drv.Probe(0xDEADBEEF, &status);
    printf("  probe status=0x%08X\n", status);
    print_result("Probe()", ok);

    /* 2. PhysMem-Map primitive — read 16 bytes from the BIOS shadow area.
          On a real BIOS-shadowing system this is reliably readable. */
    uint8_t bios[16] = {0};
    ok = drv.ReadPhysical(0x000F0000, bios, sizeof(bios));
    printf("  bios[0..7] = %02X %02X %02X %02X %02X %02X %02X %02X\n",
           bios[0], bios[1], bios[2], bios[3], bios[4], bios[5], bios[6], bios[7]);
    print_result("ReadPhysical(0xF0000)", ok);

    /* 3. MSR primitive — read EFER. NXE bit (bit 11) should be set on
          any post-XP-SP2 system. */
    uint64_t efer = 0;
    ok = drv.ReadMsr(0xC0000080, &efer);
    printf("  EFER = 0x%016llX  (NXE=%d, LMA=%d)\n",
           (unsigned long long)efer,
           (int)((efer >> 11) & 1),
           (int)((efer >> 10) & 1));
    print_result("ReadMsr(EFER)", ok);

    return 0;
}

static int raw_sweep(ExampleDriver& drv, DWORD count) {
    printf("[*] Raw IOCTL sweep (count=%lu, base=0x80002000)\n", count);
    uint8_t in_buf[256] = {0};
    uint8_t out_buf[256] = {0};
    int hits = 0;
    for (DWORD i = 0; i < count; ++i) {
        DWORD code = 0x80002000 + (i * 4);
        DWORD returned = 0;
        bool ok = drv.Invoke(code, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf), &returned);
        if (ok || GetLastError() != ERROR_INVALID_FUNCTION) {
            printf("  0x%08lX -> ok=%d returned=%lu err=%lu\n",
                   code, ok ? 1 : 0, returned, GetLastError());
            ++hits;
        }
    }
    printf("[*] %d non-rejected codes\n", hits);
    return 0;
}

static int single_call(ExampleDriver& drv, DWORD code) {
    printf("[*] Single IOCTL 0x%08lX (zeroed buffers)\n", code);
    uint8_t in_buf[256] = {0};
    uint8_t out_buf[256] = {0};
    DWORD returned = 0;
    bool ok = drv.Invoke(code, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf), &returned);
    printf("  ok=%d returned=%lu err=%lu\n", ok ? 1 : 0, returned, GetLastError());
    return 0;
}

int main(int argc, char** argv) {
    ExampleDriver drv;
    if (!drv.Open()) {
        printf("Could not open %s: %lu\n", EXAMPLE_DEVICE_PATH, GetLastError());
        printf("  - Is the driver loaded? Check `sc query <name>`.\n");
        printf("  - Is the symlink right? Try WinObj.\n");
        printf("  - Are you elevated?\n");
        return 1;
    }
    printf("[+] Opened %s\n", EXAMPLE_DEVICE_PATH);

    if (argc == 1) {
        return structured_sweep(drv);
    }
    if (argc == 3 && strcmp(argv[1], "sweep") == 0) {
        return raw_sweep(drv, (DWORD)strtoul(argv[2], nullptr, 0));
    }
    if (argc == 2) {
        return single_call(drv, (DWORD)strtoul(argv[1], nullptr, 0));
    }

    printf("Usage:\n");
    printf("  %s                 # structured validation sweep\n", argv[0]);
    printf("  %s sweep 0x100     # raw sweep N codes from 0x80002000\n", argv[0]);
    printf("  %s 0x80002048      # single raw IOCTL\n", argv[0]);
    return 1;
}
