"""Speakeasy driver emulation: trace DriverEntry, extract API calls,
device names, PDB paths, debug strings, and primitive classifications."""

import json
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pefile
except ImportError:
    pefile = None

try:
    import speakeasy
    HAS_SPEAKEASY = True
except ImportError:
    HAS_SPEAKEASY = False

try:
    import capstone
    from capstone import x86 as cs_x86
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

DANGEROUS_APIS = {
    "KeStackAttachProcess", "KeDetachProcess", "KeUnstackDetachProcess",
    "MmCopyVirtualMemory", "MmMapIoSpace", "MmMapIoSpaceEx",
    "MmCopyMemory", "MmGetVirtualForPhysical", "MmIsAddressValid",
    "ZwAllocateVirtualMemory", "ZwFreeVirtualMemory",
    "PsLookupProcessByProcessId", "__readmsr", "__writemsr",
    "__readcr0", "__readcr3", "__readcr4",
    "ZwMapViewOfSection", "ZwOpenSection", "ZwOpenPhysicalMemory",
    "MmMapLockedPagesSpecifyCache", "MmAllocatePagesForMdl",
    "ObOpenObjectByName", "ZwOpenProcess",
}

SKIP_STRINGS = {
    ".text", ".rdata", ".data", ".pdata", "INIT", ".bss", ".xdata",
    ".text$mn", ".text$mn$21", ".text$s",
    ".idata$2", ".idata$3", ".idata$4", ".idata$5", ".idata$6",
    ".rdata$zzzdbg", "Rich",
    "!This program cannot be run in DOS mode.",
    "ntoskrnl.exe", "HAL.dll", "WDFLDR.SYS", "FLTMGR.SYS",
}

PRIMITIVE_KEYWORDS = [
    "physic", "cr3", "cr0", "msr", "pml4", "pdpt", "pte", "pde",
    "readmem", "writemem", "readphys", "writephys",
    "mapiosp", "allocate.*vad", "insert.*vad",
    "dirtbl", "directorytable", "kernel.*base", "ntos",
    "ioctl", "irp_mj_device_control",
]


# Uncomment to inject extra kernel modules into the Speakeasy module list.
# Useful for unsigned/manual-mapped drivers that hook dxgkrnl exports
# instead of using standard IOCTL dispatch.  Not needed for signed BYOVD
# drivers which all use IoCreateDevice + IRP_MJ_DEVICE_CONTROL.
# EXTRA_SYSTEM_MODULES = [
#     {
#         "name": "dxgkrnl",
#         "base_addr": "0xD8000000",
#         "path": "C:\\Windows\\system32\\drivers\\dxgkrnl.sys",
#     },
# ]
EXTRA_SYSTEM_MODULES = []

_fake_export_pages = {}


def _rtlfindexportedroutinebyname_hook(emu, api_name, orig, argv):
    """Stub for RtlFindExportedRoutineByName.

    Speakeasy's decoy modules have empty export tables, so the real PE
    walk returns NULL.  This hook allocates a persistent page per
    (module_base, routine_name) pair and returns a stable address the
    driver can store and call later.
    """
    module_base, name_ptr = argv
    if not name_ptr:
        return 0
    try:
        raw = bytes(emu.mem_read(name_ptr, 256))
        name = raw.split(b'\x00', 1)[0].decode('ascii', errors='replace')
    except Exception:
        return 0
    if not name:
        return 0

    key = (module_base, name)
    if key not in _fake_export_pages:
        page = emu.mem_map(0x1000, tag=f'emu.fake_export.{name}')
        # write a RET so if the driver calls through it, emulation doesn't crash
        emu.mem_write(page, b'\xC3')
        _fake_export_pages[key] = page
    return _fake_export_pages[key]


def _iocreatedriver_hook(emu, api_name, orig, argv):
    """Generic stub for ntoskrnl.IoCreateDriver.

    Drivers that call IoCreateDriver create a hidden driver object and pass
    a DRIVER_INITIALIZE callback that populates MajorFunction.  Speakeasy
    has no built-in stub for this API, so emulation stops at DriverEntry.

    This hook uses Capstone to disassemble the callback at argv[1], finds
    LEA rax,[rip+X] / MOV [drv_reg+off],rax pairs that set MajorFunction
    entries, writes those addresses into the existing DriverObject's memory,
    creates a dummy DeviceObject for IRP dispatch, and returns STATUS_SUCCESS.
    """
    _driver_name_ptr, init_func_addr = argv
    drv = emu.drivers[-1]

    if HAS_CAPSTONE and init_func_addr:
        code = bytes(emu.mem_read(init_func_addr, 2048))
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        reg_vals = {}
        last_imul_val = None

        for insn in md.disasm(code, init_func_addr):
            ops = insn.operands

            if insn.mnemonic == 'lea' and len(ops) == 2:
                dst, src = ops
                if (dst.type == capstone.CS_OP_REG
                        and src.type == capstone.CS_OP_MEM
                        and src.mem.base == cs_x86.X86_REG_RIP):
                    reg_vals[dst.reg] = (
                        insn.address + insn.size + src.mem.disp)

            if insn.mnemonic == 'imul' and len(ops) == 3:
                if ops[2].type == capstone.CS_OP_IMM:
                    last_imul_val = ops[2].imm

            if insn.mnemonic == 'mov' and len(ops) == 2:
                dst, src = ops
                if (dst.type == capstone.CS_OP_MEM
                        and src.type == capstone.CS_OP_REG
                        and src.reg in reg_vals):
                    disp = dst.mem.disp
                    index = dst.mem.index
                    scale = dst.mem.scale
                    if index == 0:
                        offset = disp
                    elif disp == 0x70 and scale == 1 and (
                            last_imul_val is not None):
                        offset = 0x70 + 8 * last_imul_val
                    else:
                        continue
                    if 0x68 <= offset <= 0x140:
                        emu.mem_write(drv.address + offset,
                                      struct.pack('<Q', reg_vals[src.reg]))

            if insn.mnemonic == 'ret':
                break

    dev = emu.create_device_object(
        name='\\Device\\IoCreateDriver_stub', drv=drv)
    drv.devices.append(dev)
    return 0


@dataclass
class EntryPointTrace:
    ep_type: str = ""
    address: str = ""
    api_calls: list[dict] = field(default_factory=list)
    ret_val: str = ""
    error_type: str = ""
    error_detail: str = ""
    crashed: bool = False


@dataclass
class EmulationResult:
    filename: str
    path: str
    sha256: str = ""
    arch: str = ""
    is_driver: bool = False
    image_base: str = ""
    entry_point: str = ""
    image_size: str = ""
    device_names: list[str] = field(default_factory=list)
    symlinks: list[str] = field(default_factory=list)
    pdb_path: str = ""
    api_calls: list[dict] = field(default_factory=list)
    dangerous_apis_called: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    all_strings: list[str] = field(default_factory=list)
    primitives: list[str] = field(default_factory=list)
    entry_points: list[EntryPointTrace] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    crash_count: int = 0
    crash_sites: list[str] = field(default_factory=list)
    emulation_time: float = 0.0
    error: str = ""


def _classify_primitives(imports: list[str], strings: list[str]) -> list[str]:
    primitives = set()
    combined = " ".join(imports + strings).lower()

    checks = [
        ("PhysMem-Map", ["mmmapiospace", "mmmapiospaceex", "mapiosp"]),
        ("CrossProc-VA", ["mmcopyvirtualmemory", "kestackattachprocess"]),
        ("MSR-RW", ["readmsr", "__readmsr", "writemsr", "__writemsr",
                     "msr_read", "msr_write"]),
        ("CR-Regs", ["readcr", "__readcr3", "cr3", "cr0"]),
        ("PageTable-Walk", ["pml4", "pdpt", "pte", "pde", "pagetable",
                            "page table"]),
        ("VAD-Inject", ["allocatevad", "insertvad", "miallocatevad"]),
        ("KernelMem-Copy", ["mmcopymemory"]),
        ("PhysMem-Section", ["zwmapviewofsection", "openphysicalmemory",
                             "\\device\\physicalmemory"]),
        ("MDL-Map", ["mmallocatepagesformdl", "mmmaplockedpages"]),
        ("PhysMem-Direct", ["physical_read", "physical_write",
                            "readphysical", "writephysical"]),
        ("VirtMem-RW", ["virtual_read", "virtual_write"]),
        ("PCI-Config", ["pci_config_read", "pci_config_write"]),
        ("IO-Port", ["io_read", "io_write", "read_io_port",
                      "write_io_port"]),
    ]

    for name, keywords in checks:
        if any(kw in combined for kw in keywords):
            primitives.add(name)

    return sorted(primitives)


def _is_interesting_string(val: str) -> bool:
    if not val or len(val) < 6 or val in SKIP_STRINGS:
        return False

    val_lower = val.lower()

    if any(kw in val_lower for kw in PRIMITIVE_KEYWORDS):
        return True
    if val.startswith("[") and "]" in val:
        return True
    if "\\Device\\" in val or "\\DosDevices\\" in val or "\\Registry\\" in val:
        return True
    if "\\Driver\\" in val:
        return True
    if any(x in val for x in ["IOCTL", "ioctl", "Driver"]):
        return True
    if any(x in val for x in ["Failed", "Error", "Success"]):
        if len(val) > 12:
            return True
    if any(x in val_lower for x in ["alloc", "physical", "virtual",
                                     "process", "memory"]):
        if len(val) > 15:
            return True

    return False


def emulate_driver(driver_path: str) -> EmulationResult:
    """Run Speakeasy emulation on a single driver and return structured results."""
    name = os.path.basename(driver_path)
    result = EmulationResult(filename=name, path=driver_path)

    if not HAS_SPEAKEASY:
        result.error = "speakeasy-emulator not installed"
        return result

    # SHA256
    import hashlib
    with open(driver_path, "rb") as f:
        result.sha256 = hashlib.sha256(f.read()).hexdigest()

    # PE imports
    if pefile:
        try:
            pe = pefile.PE(driver_path)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        iname = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
                        result.imports.append(f"{entry.dll.decode()}!{iname}")
            pe.close()
        except Exception:
            pass

    # Speakeasy emulation
    import time
    t0 = time.perf_counter()

    try:
        config_path = os.path.join(os.path.dirname(speakeasy.__file__),
                                   'configs', 'default.json')
        with open(config_path, 'r') as f:
            config = json.load(f)
        sys_mods = config.get('modules', {}).get('system_modules', [])
        existing = {m.get('name', '').lower() for m in sys_mods}
        for extra in EXTRA_SYSTEM_MODULES:
            if extra['name'].lower() not in existing:
                sys_mods.append(extra)
        config['modules']['system_modules'] = sys_mods

        se = speakeasy.Speakeasy(config=config)
        module = se.load_module(driver_path)

        result.image_base = hex(module.get_base())
        result.entry_point = hex(module.ep)
        result.is_driver = module.is_driver()
        result.image_size = hex(module.get_image_size())
        result.arch = "x64" if module.ptr_size == 8 else "x86"

        # Collect exported function names
        try:
            for exp in module.get_exports():
                ename = exp.get("name", "") if isinstance(exp, dict) else ""
                if ename:
                    result.exports.append(ename)
        except Exception:
            pass

        se.add_api_hook(_iocreatedriver_hook,
                        module='ntoskrnl',
                        api_name='IoCreateDriver', argc=2)
        se.add_api_hook(_rtlfindexportedroutinebyname_hook,
                        module='ntoskrnl',
                        api_name='RtlFindExportedRoutineByName', argc=2)
        se.run_module(module, all_entrypoints=True)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"

    result.emulation_time = round(time.perf_counter() - t0, 3)

    try:
        report = se.get_report()
    except Exception:
        report = {}

    # Extract all entry points with full lifecycle + crash detection
    for ep in report.get("entry_points", []):
        ep_type = ep.get("ep_type", "unknown")
        ep_addr = ep.get("start_addr", "0")
        ep_ret = str(ep.get("ret_val", ""))
        ep_err = ep.get("error", {})

        trace = EntryPointTrace(
            ep_type=ep_type, address=ep_addr, ret_val=ep_ret,
        )

        if ep_err:
            err_type = ep_err.get("type", "")
            trace.error_type = err_type
            if err_type in ("invalid_read", "invalid_write"):
                trace.crashed = True
                addr = ep_err.get("address", "?")
                pc = ep_err.get("pc", "?")
                instr = ep_err.get("instr", "?")
                trace.error_detail = (
                    f"{err_type} at {addr} (pc={pc}, {instr})")
                result.crash_count += 1
                result.crash_sites.append(
                    f"{ep_type}@{ep_addr}: {err_type} {addr} [{instr}]")
            elif err_type == "unsupported_api":
                api_name = ep_err.get("api_name", "?")
                trace.error_detail = f"unsupported API: {api_name}"
            else:
                trace.error_detail = str(ep_err.get("type", ep_err))

        for api in ep.get("apis", []):
            api_name = api.get("api_name", "?")
            short = api_name.split(".")[-1] if "." in api_name else api_name
            args = api.get("args", [])
            pc = api.get("pc", "0")
            call = {"pc": pc, "name": short, "args": args}
            trace.api_calls.append(call)
            result.api_calls.append(call)

            if short in DANGEROUS_APIS and short not in result.dangerous_apis_called:
                result.dangerous_apis_called.append(short)

            if "CreateDevice" in short or "InitUnicodeString" in short:
                for a in args:
                    if isinstance(a, str):
                        if "\\Device\\" in a and a not in result.device_names:
                            result.device_names.append(a)
                        if "\\DosDevices\\" in a and a not in result.symlinks:
                            result.symlinks.append(a)

            if "CreateSymbolicLink" in short:
                for a in args:
                    if isinstance(a, str) and "\\DosDevices\\" in a:
                        if a not in result.symlinks:
                            result.symlinks.append(a)

        result.entry_points.append(trace)

    # Extract strings
    strings_data = report.get("strings", {})
    for section in [strings_data.get("static", {}), strings_data.get("in_memory", {})]:
        for s in section.get("ansi", []) + section.get("unicode", []):
            val = s if isinstance(s, str) else (
                s.get("string", "") if isinstance(s, dict) else str(s))
            if not val or len(val) < 4:
                continue

            result.all_strings.append(val)

            if ".pdb" in val.lower() and not result.pdb_path:
                result.pdb_path = val
                continue

            if _is_interesting_string(val):
                result.interesting_strings.append(val)

    # Classify primitives from both imports and strings
    import_names = [i.split("!")[-1] for i in result.imports]
    result.primitives = _classify_primitives(
        import_names, result.interesting_strings + result.all_strings
    )

    return result


def emulate_batch(
    paths: list[str],
    recursive: bool = True,
) -> list[EmulationResult]:
    """Emulate multiple drivers. Accepts files or directories."""
    targets = []
    for p in paths:
        pp = Path(p)
        if pp.is_file() and pp.suffix.lower() == ".sys":
            targets.append(str(pp))
        elif pp.is_dir():
            pattern = "**/*.sys" if recursive else "*.sys"
            targets.extend(str(f) for f in sorted(pp.glob(pattern)))

    results = []
    for i, t in enumerate(targets, 1):
        print(f"\r  [{i}/{len(targets)}] {os.path.basename(t):<40}",
              end="", flush=True)
        try:
            results.append(emulate_driver(t))
        except Exception as e:
            r = EmulationResult(
                filename=os.path.basename(t), path=t,
                error=f"Fatal: {type(e).__name__}: {e}",
            )
            results.append(r)
    print()

    return results


def format_table(results: list[EmulationResult]) -> str:
    """Format results as a human-readable summary table."""
    lines = []
    lines.append(f"\n{'='*100}")
    lines.append(f"  EMULATION RESULTS: {len(results)} drivers")
    lines.append(f"{'='*100}\n")

    lines.append(
        f"  {'#':<4} {'Driver':<32} {'Device':<22} {'EPs':>3} "
        f"{'Crash':>5} {'PDB':<20} Primitives"
    )
    lines.append(
        f"  {'-'*4} {'-'*32} {'-'*22} {'-'*3} "
        f"{'-'*5} {'-'*20} {'-'*40}"
    )

    for i, r in enumerate(results, 1):
        name = r.filename[:31] if len(r.filename) <= 31 else r.filename[:28] + "..."
        dev = (r.device_names[0].replace("\\Device\\", "") if r.device_names
               else "")[:21]
        pdb = ""
        if r.pdb_path:
            pdb = os.path.basename(r.pdb_path).replace(".pdb", "")[:19]
        prims = ", ".join(r.primitives) or ("ERROR" if r.error else "none")
        ep_count = len(r.entry_points)
        crash = f"{r.crash_count}" if r.crash_count else ""
        lines.append(
            f"  {i:<4} {name:<32} {dev:<22} {ep_count:>3} "
            f"{crash:>5} {pdb:<20} {prims}"
        )

    # Detail blocks
    lines.append(f"\n{'-'*100}")
    for r in results:
        lines.append(f"\n  {r.filename}")
        lines.append(f"    SHA256: {r.sha256}")
        lines.append(f"    Arch: {r.arch}  Base: {r.image_base}  "
                      f"EP: {r.entry_point}  Size: {r.image_size}")
        lines.append(f"    Emulation: {r.emulation_time}s")

        if r.error:
            lines.append(f"    Error: {r.error}")
        if r.device_names:
            lines.append(f"    Devices: {', '.join(r.device_names)}")
        if r.symlinks:
            lines.append(f"    Symlinks: {', '.join(r.symlinks)}")
        if r.pdb_path:
            lines.append(f"    PDB: {r.pdb_path}")
        if r.primitives:
            lines.append(f"    Primitives: {', '.join(r.primitives)}")

        if r.entry_points:
            lines.append(f"    Lifecycle ({len(r.entry_points)} entry points):")
            for ep in r.entry_points:
                status = ""
                if ep.crashed:
                    status = f"  CRASH: {ep.error_detail}"
                elif ep.error_type == "unsupported_api":
                    status = f"  STUB: {ep.error_detail}"
                api_count = len(ep.api_calls)
                lines.append(
                    f"      {ep.ep_type:<30} addr={ep.address:<14} "
                    f"apis={api_count:<4} ret={ep.ret_val}{status}")
                for api in ep.api_calls[:4]:
                    marker = " <<<" if api["name"] in DANGEROUS_APIS else ""
                    arg_str = ", ".join(str(a) for a in api["args"][:3])
                    lines.append(f"        {api['name']}({arg_str}){marker}")
                if len(ep.api_calls) > 4:
                    lines.append(f"        ... +{len(ep.api_calls)-4} more")

        if r.crash_count:
            lines.append(f"    BSOD RISK: {r.crash_count} crash sites:")
            for site in r.crash_sites:
                lines.append(f"      {site}")

        if r.exports:
            lines.append(f"    Exports ({len(r.exports)}):")
            for exp in r.exports[:10]:
                lines.append(f"      {exp}")
            if len(r.exports) > 10:
                lines.append(f"      ... +{len(r.exports)-10} more")

        if r.interesting_strings:
            lines.append(f"    Interesting strings ({len(r.interesting_strings)}):")
            for s in r.interesting_strings[:20]:
                lines.append(f"      {s}")
            if len(r.interesting_strings) > 20:
                lines.append(f"      ... +{len(r.interesting_strings) - 20} more")

    return "\n".join(lines)
