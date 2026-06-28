/*
 * comm_template.h — IOCTL communication header for a vulnerable driver under test
 *
 * Workflow:
 *   1. Run `driverscope ioctl driver.sys --json > findings.json`
 *   2. Copy this template, rename per-driver (e.g. ene_comm.h)
 *   3. Set DEVICE_PATH from DriverScope's reported device name
 *      (or via `objdir` / WinObj if the driver doesn't expose one symbolically)
 *   4. Fill in IOCTL_* macros with the codes DriverScope found
 *   5. Compile ioctl_tester.c against this header to call them
 *
 * Only use against drivers you own or have explicit written authorization to test.
 */

#pragma once
#include <windows.h>
#include <winioctl.h>

/* ---- device path ----
 * From DriverScope's `device_names` field. Usually \\.\<symlink>.
 * Examples:
 *   \\.\PhyMem        (ene.sys)
 *   \\.\AsIO          (AsIO3.sys)
 *   \\.\inpoutx64     (inpoutx64.sys)
 */
#define DRIVER_DEVICE_PATH  "\\\\.\\<SYMLINK_NAME>"

/* ---- IOCTL codes ----
 *
 * Two equivalent ways to declare each IOCTL:
 *
 *   (A) Raw code from DriverScope output:
 *       #define IOCTL_FOO  0x80102040
 *
 *   (B) Reconstructed via CTL_CODE macro (preferred — self-documenting):
 *       #define IOCTL_FOO  CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
 *
 * DriverScope's --json output gives you device_type, function, method, and access
 * for every IOCTL — plug those directly into form (B).
 */

#define IOCTL_EXAMPLE_READ   CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EXAMPLE_WRITE  CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- input/output structs (reverse-engineered from the handler) ----
 *
 * DriverScope tells you what the handler imports (e.g. MmMapIoSpace);
 * the input layout is on you — usually a {phys_addr, size, virt_out} triple
 * for physmem mappers, or {port, value} for I/O port drivers.
 */

#pragma pack(push, 1)
typedef struct _EXAMPLE_PHYSMEM_REQ {
    UINT64  physical_address;
    UINT32  size;
    UINT64  mapped_virtual;   /* OUT */
} EXAMPLE_PHYSMEM_REQ, *PEXAMPLE_PHYSMEM_REQ;
#pragma pack(pop)
