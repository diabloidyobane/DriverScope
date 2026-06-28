/*
 * comm_template.h: researcher-grade C++ wrapper for validating IOCTL findings.
 *
 * This is the shape you build around a vulnerable driver once DriverScope
 * gives you a list of IOCTL codes. The class-per-driver + struct-per-IOCTL
 * pattern keeps reverse-engineered handler layouts close to the call sites,
 * so when you find out the struct is actually {phys, size, virt} instead of
 * {addr, len, _} you change it in exactly one place.
 *
 * Workflow:
 *   1. driverscope ioctl driver.sys --json > findings.json
 *   2. python examples/gen_comm_header.py findings.json   # generates CTL_CODE lines
 *   3. Copy + rename this file (e.g. ene_comm.h)
 *   4. Paste in the generated CTL_CODE macros
 *   5. Fill in the per-IOCTL request structs by reading the handler in IDA/Ghidra
 *   6. Compile ioctl_tester.cpp against it
 *
 * Only use against drivers you own or have explicit written authorization to test.
 * Test in a VM with a snapshot.
 */

#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>

/* ===== device path =====
 *
 * From DriverScope's `device_names` (or recovered manually via WinObj /
 * objdir / reverse-engineering IoCreateSymbolicLink in the .sys).
 * Examples (illustrative: fill in for your target):
 *     "\\\\.\\ExampleDrv"
 *     "\\\\.\\PhyMem"
 *     "\\\\Global??\\\\MyDriver"
 */
#define EXAMPLE_DEVICE_PATH    "\\\\.\\ExampleDrv"

/* ===== IOCTL codes =====
 *
 * Use CTL_CODE() rather than raw hex: it's self-documenting and lets you
 * see at a glance what method + access the handler expects.
 *
 * (These are placeholders. Replace with codes from your --json findings.)
 */
#define IOCTL_EXAMPLE_PROBE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EXAMPLE_READ_PHYS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EXAMPLE_READ_MSR     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ===== per-IOCTL request structs =====
 *
 * Reverse-engineered from the handler. The handler's first move on entry
 * is usually `mov rcx, [Irp+0xB8] ; mov rdx, [IrpSp+0x10]`: that's your
 * input pointer + length. Walk forward to see what offsets it reads.
 */
#pragma pack(push, 1)

struct ProbeRequest {
    uint32_t cookie;       /* IN : magic the handler validates */
    uint32_t status;       /* OUT */
};

struct PhysReadRequest {
    uint64_t physical_addr;   /* IN : physical address to map */
    uint32_t size;            /* IN : bytes to copy */
    uint32_t _pad;
    uint8_t  out_buffer[256]; /* OUT: copied bytes (cap whatever the handler does) */
};

struct MsrReadRequest {
    uint32_t msr_index;       /* IN : e.g. 0xC0000080 for EFER */
    uint32_t _pad;
    uint64_t value;           /* OUT */
};

#pragma pack(pop)

/* ===== driver wrapper class =====
 *
 * RAII handle, one method per IOCTL, templated helpers for the common
 * primitive shapes. Add methods as you discover more IOCTLs.
 */
class ExampleDriver {
public:
    ExampleDriver() : handle_(INVALID_HANDLE_VALUE) {}

    ~ExampleDriver() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    /* Open the device. Returns false on failure (driver not loaded,
       symlink wrong, not running elevated). */
    bool Open() {
        handle_ = CreateFileA(
            EXAMPLE_DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        return handle_ != INVALID_HANDLE_VALUE;
    }

    bool IsOpen() const { return handle_ != INVALID_HANDLE_VALUE; }

    /* Generic IOCTL invoker: useful for sweeping unknown codes. */
    bool Invoke(DWORD code, void* in_buf, DWORD in_sz,
                              void* out_buf, DWORD out_sz, DWORD* returned = nullptr) {
        DWORD bytes = 0;
        BOOL ok = DeviceIoControl(
            handle_, code,
            in_buf, in_sz,
            out_buf, out_sz,
            &bytes, nullptr);
        if (returned) *returned = bytes;
        return ok != FALSE;
    }

    /* Per-IOCTL typed wrappers: confirms the handler accepts your struct. */

    bool Probe(uint32_t cookie, uint32_t* status_out = nullptr) {
        ProbeRequest req{ cookie, 0 };
        DWORD ret = 0;
        bool ok = Invoke(IOCTL_EXAMPLE_PROBE, &req, sizeof(req), &req, sizeof(req), &ret);
        if (status_out) *status_out = req.status;
        return ok;
    }

    /* Validates PhysMem-Map primitive: ask the handler to copy out bytes
       from a known-readable physical address (e.g. low BIOS area) and check
       that what came back matches what you'd expect via another channel. */
    bool ReadPhysical(uint64_t phys_addr, void* dst, uint32_t size) {
        if (size > sizeof(PhysReadRequest::out_buffer)) return false;
        PhysReadRequest req{};
        req.physical_addr = phys_addr;
        req.size = size;
        bool ok = Invoke(IOCTL_EXAMPLE_READ_PHYS, &req, sizeof(req), &req, sizeof(req));
        if (ok) memcpy(dst, req.out_buffer, size);
        return ok;
    }

    /* Validates MSR primitive: read EFER (0xC0000080) and check bit 11
       is set on any post-NX-era CPU. Sanity check that doesn't require
       any state and confirms the handler reached the wrmsr/rdmsr path. */
    bool ReadMsr(uint32_t msr_index, uint64_t* value_out) {
        MsrReadRequest req{ msr_index, 0, 0 };
        bool ok = Invoke(IOCTL_EXAMPLE_READ_MSR, &req, sizeof(req), &req, sizeof(req));
        if (ok && value_out) *value_out = req.value;
        return ok;
    }

private:
    HANDLE handle_;
};
