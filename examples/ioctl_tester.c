/*
 * ioctl_tester.c — minimal user-mode IOCTL fuzzer / sanity checker.
 *
 * Build (MSVC):
 *   cl ioctl_tester.c
 * Build (MinGW):
 *   gcc ioctl_tester.c -o ioctl_tester.exe
 *
 * Usage:
 *   ioctl_tester.exe              # opens device, calls every defined IOCTL with zeroed input
 *   ioctl_tester.exe 0x80102040   # call a single raw IOCTL code
 *
 * Replace `comm_template.h` with your per-driver header.
 *
 * SAFETY: each IOCTL call goes to ring-0. A bad call can BSOD the box.
 * Test in a VM with a snapshot you can roll back.
 */

#include "comm_template.h"
#include <stdio.h>
#include <stdlib.h>

static int call_ioctl(HANDLE h, DWORD code, void *in_buf, DWORD in_sz,
                      void *out_buf, DWORD out_sz)
{
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, code, in_buf, in_sz, out_buf, out_sz,
                              &returned, NULL);
    DWORD err = GetLastError();
    printf("  IOCTL 0x%08lX  ok=%d  returned=%lu  err=%lu (%s)\n",
           code, ok, returned, err,
           err == ERROR_SUCCESS         ? "OK" :
           err == ERROR_INVALID_FUNCTION ? "invalid function (handler rejected)" :
           err == ERROR_ACCESS_DENIED    ? "access denied (privileged caller required)" :
           err == ERROR_INVALID_PARAMETER ? "invalid parameter (struct layout wrong?)" :
                                            "see GetLastError");
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    HANDLE h = CreateFileA(DRIVER_DEVICE_PATH,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        printf("CreateFile(%s) failed: %lu\n", DRIVER_DEVICE_PATH, GetLastError());
        printf("  Driver not loaded? Symlink different? Run as Administrator?\n");
        return 1;
    }
    printf("Opened %s\n", DRIVER_DEVICE_PATH);

    BYTE in_buf[256]  = {0};
    BYTE out_buf[256] = {0};

    if (argc == 2) {
        /* single-IOCTL mode: ioctl_tester.exe 0x80102040 */
        DWORD code = (DWORD)strtoul(argv[1], NULL, 0);
        call_ioctl(h, code, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf));
    } else {
        /* sweep mode: call every IOCTL declared in the header */
        printf("Sweeping declared IOCTLs (zeroed input):\n");
        call_ioctl(h, IOCTL_EXAMPLE_READ,  in_buf, sizeof(in_buf), out_buf, sizeof(out_buf));
        call_ioctl(h, IOCTL_EXAMPLE_WRITE, in_buf, sizeof(in_buf), out_buf, sizeof(out_buf));
        /* add more IOCTL_* macros here as you find them */
    }

    CloseHandle(h);
    return 0;
}
