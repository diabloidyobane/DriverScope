"""Static IOCTL dispatch-surface extraction for Windows x64 .sys files."""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pefile

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    capstone = None
    HAS_CAPSTONE = False

from .scanner import _IMPORT_TO_CLASSES

DRIVER_OBJECT_MAJORFUNCTION_OFF = 0x70
IRP_MJ_DEVICE_CONTROL = 0x0E
DISPATCH_DEVICE_CONTROL_OFFSET = (
    DRIVER_OBJECT_MAJORFUNCTION_OFF + IRP_MJ_DEVICE_CONTROL * 8
)  # 0xE0

IRP_CURRENT_STACK_LOCATION_OFF = 0xB8
IO_STACK_IO_CONTROL_CODE_OFF = 0x18

DRIVER_ENTRY_SCAN_BYTES = 0x600
DRIVER_ENTRY_SCAN_INSNS = 256
DISPATCHER_SCAN_BYTES = 0x2000
DISPATCHER_SCAN_INSNS = 1024
PER_BRANCH_SCAN_BYTES = 0x200
PER_BRANCH_SCAN_INSNS = 256

CTL_METHOD_MASK = 0x00000003
CTL_FUNCTION_MASK = 0x00003FFC
CTL_FUNCTION_SHIFT = 2
CTL_ACCESS_MASK = 0x0000C000
CTL_ACCESS_SHIFT = 14
CTL_DEVICE_TYPE_SHIFT = 16

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
}

DEVICE_TYPE_NAMES = {
    0x00000001: "FILE_DEVICE_BEEP",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000000B: "FILE_DEVICE_KEYBOARD",
    0x00000012: "FILE_DEVICE_MOUSE",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000034: "FILE_DEVICE_BATTERY",
    0x00000039: "FILE_DEVICE_ACPI",
    0x0000003E: "FILE_DEVICE_KSEC",
}


@dataclass
class CTLCode:
    raw: int
    device_type: int = 0
    device_type_name: str = ""
    function: int = 0
    method: int = 0
    method_name: str = ""
    access: int = 0
    access_name: str = ""

    def __post_init__(self):
        self.device_type = self.raw >> CTL_DEVICE_TYPE_SHIFT
        self.function = (self.raw & CTL_FUNCTION_MASK) >> CTL_FUNCTION_SHIFT
        self.method = self.raw & CTL_METHOD_MASK
        self.access = (self.raw & CTL_ACCESS_MASK) >> CTL_ACCESS_SHIFT
        self.method_name = METHOD_NAMES.get(self.method, f"METHOD_{self.method}")
        self.access_name = ACCESS_NAMES.get(self.access, f"ACCESS_{self.access}")
        dt = DEVICE_TYPE_NAMES.get(self.device_type)
        self.device_type_name = dt if dt else f"USER(0x{self.device_type:04X})"


@dataclass
class IOCTLEntry:
    code: int
    ctl: CTLCode = field(default=None)
    handler_rva: int = 0
    handler_imports: list[str] = field(default_factory=list)
    primitive_classes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.ctl is None:
            self.ctl = CTLCode(self.code)


@dataclass
class IOCTLSurface:
    path: str
    filename: str
    sha256: str = ""
    dispatcher_rva: int = 0
    ioctls: list[IOCTLEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    method: str = ""


def _rva_to_offset(pe: pefile.PE, rva: int) -> Optional[int]:
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None


def _read_section_bytes(pe: pefile.PE, rva: int, length: int) -> bytes:
    try:
        data = pe.get_data(rva, length)
        return data if data else b""
    except Exception:
        for shrink in (length // 2, length // 4, 0x80, 0x40):
            try:
                data = pe.get_data(rva, shrink)
                if data:
                    return data
            except Exception:
                continue
        return b""


def _iter_text_sections(pe: pefile.PE):
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_CNT_CODE = 0x00000020
    for sec in pe.sections:
        chars = sec.Characteristics
        if (chars & IMAGE_SCN_MEM_EXECUTE) or (chars & IMAGE_SCN_CNT_CODE):
            size = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            yield (sec.VirtualAddress, size, sec.PointerToRawData)


def _build_iat_map(pe: pefile.PE) -> dict[int, str]:
    out = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name is None:
                continue
            name = imp.name.decode("ascii", errors="replace")
            if imp.address:
                out[imp.address - image_base] = name
    return out


def _build_thunk_map(pe: pefile.PE, iat_map: dict[int, str]) -> dict[int, str]:
    """Scan .text for JMP [rip+disp] thunks that resolve to IAT slots."""
    out = {}
    if not iat_map:
        return out
    for (sec_rva, sec_size, _) in _iter_text_sections(pe):
        body = _read_section_bytes(pe, sec_rva, min(sec_size, 0x800000))
        if not body:
            continue
        n = len(body)
        i = 0
        while i + 6 <= n:
            if body[i] == 0xFF and body[i + 1] == 0x25:
                disp = struct.unpack("<i", body[i + 2:i + 6])[0]
                thunk_rva = sec_rva + i
                target_rva = thunk_rva + 6 + disp
                if target_rva in iat_map:
                    out[thunk_rva] = iat_map[target_rva]
                i += 6
                continue
            if i + 7 <= n and body[i] == 0x48 and body[i + 1] == 0xFF and body[i + 2] == 0x25:
                disp = struct.unpack("<i", body[i + 3:i + 7])[0]
                thunk_rva = sec_rva + i
                target_rva = thunk_rva + 7 + disp
                if target_rva in iat_map:
                    out[thunk_rva] = iat_map[target_rva]
                i += 7
                continue
            i += 1
    return out


def _follow_entrypoint_thunk(pe: pefile.PE, rva: int) -> int:
    """Follow GS cookie init trampolines that tail-JMP to the real DriverEntry."""
    body = _read_section_bytes(pe, rva, 0x80)
    if not body:
        return rva

    if HAS_CAPSTONE:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        last_jmp = None
        seen_rip_load = False
        for ins in md.disasm(body, rva):
            if ins.mnemonic in ("mov", "lea") and "rip" in ins.op_str:
                seen_rip_load = True
            if ins.mnemonic == "jmp":
                if ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
                    last_jmp = ins.operands[0].imm
                break
            if ins.mnemonic == "ret":
                break
        if last_jmp is not None and (seen_rip_load or last_jmp != rva):
            for (sec_rva, sec_size, _) in _iter_text_sections(pe):
                if sec_rva <= last_jmp < sec_rva + sec_size:
                    return last_jmp
        return rva

    # Bytescan: look for near JMP rel32 (E9) in first 0x40 bytes
    for off in range(min(len(body), 0x40)):
        if body[off] == 0xE9 and off + 5 <= len(body):
            disp = struct.unpack("<i", body[off + 1:off + 5])[0]
            target = rva + off + 5 + disp
            for (sec_rva, sec_size, _) in _iter_text_sections(pe):
                if sec_rva <= target < sec_rva + sec_size:
                    return target
            return rva
        if body[off] == 0xC3:
            break
    return rva


def _resolve_driver_entry(pe: pefile.PE, errors: list[str]) -> int:
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep:
        return _follow_entrypoint_thunk(pe, ep)

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = (sym.name or b"").decode("ascii", errors="replace")
            if name == "DriverEntry":
                return sym.address

    errors.append("DriverEntry not resolvable")
    return 0


# -- Capstone dispatcher finder: tracks register aliases of RCX --

def _find_dispatcher_capstone(pe: pefile.PE, entry_rva: int,
                              errors: list[str]) -> int:
    if not HAS_CAPSTONE:
        return 0

    body = _read_section_bytes(pe, entry_rva, DRIVER_ENTRY_SCAN_BYTES)
    if not body:
        errors.append("DriverEntry body unreadable")
        return 0

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    x86 = capstone.x86
    OP_REG, OP_MEM, OP_IMM = x86.X86_OP_REG, x86.X86_OP_MEM, x86.X86_OP_IMM

    alias = {x86.X86_REG_RCX: True}
    lea_target = {}
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for insn in md.disasm(body, entry_rva, count=DRIVER_ENTRY_SCAN_INSNS):
        ops = insn.operands

        # Register aliasing: mov dst, src
        if (insn.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == OP_REG and ops[1].type == OP_REG):
            src, dst = ops[1].reg, ops[0].reg
            if alias.get(src):
                alias[dst] = True
            else:
                alias.pop(dst, None)
            lea_target.pop(dst, None)
            continue

        # LEA reg, [rip+disp]: candidate handler address
        if (insn.mnemonic == "lea" and len(ops) == 2
                and ops[0].type == OP_REG and ops[1].type == OP_MEM):
            mem = ops[1].mem
            if mem.base == x86.X86_REG_RIP:
                lea_target[ops[0].reg] = insn.address + insn.size + mem.disp
                alias.pop(ops[0].reg, None)
            continue

        # mov [alias_of_rcx + 0xE0], reg: the dispatch store
        if (insn.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == OP_MEM and ops[1].type == OP_REG):
            mem = ops[0].mem
            if (mem.index == 0
                    and mem.disp == DISPATCH_DEVICE_CONTROL_OFFSET
                    and alias.get(mem.base)):
                src_reg = ops[1].reg
                if src_reg in lea_target:
                    return lea_target[src_reg]
                errors.append("dispatch store found but handler source unresolved")
                return 0

        # Loop store: mov [alias+rax*8+0x70], reg (all MJ slots at once)
        if (insn.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == OP_MEM and ops[1].type == OP_REG):
            mem = ops[0].mem
            if (alias.get(mem.base) and mem.scale == 8
                    and mem.disp == DRIVER_OBJECT_MAJORFUNCTION_OFF):
                src_reg = ops[1].reg
                if src_reg in lea_target:
                    return lea_target[src_reg]

        # Immediate store: mov [alias+0xE0], imm32
        if (insn.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == OP_MEM and ops[1].type == OP_IMM):
            mem = ops[0].mem
            if mem.disp == DISPATCH_DEVICE_CONTROL_OFFSET and alias.get(mem.base):
                imm = ops[1].imm
                return (imm - image_base) if imm > image_base else imm

    errors.append("no MajorFunction[IRP_MJ_DEVICE_CONTROL] store found in DriverEntry")
    return 0


# -- Bytescan dispatcher finder (fallback) --

def _find_dispatcher_bytescan(data: bytes, pe: pefile.PE) -> Optional[int]:
    """Byte-pattern scan for MOV [RCX+0xE0], <addr> in DriverEntry."""
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_off = _rva_to_offset(pe, ep_rva)
    if ep_off is None:
        return None

    search_size = min(DRIVER_ENTRY_SCAN_BYTES, len(data) - ep_off)
    chunk = data[ep_off:ep_off + search_size]

    patterns = [
        (b"\x48\x89\x81\xe0\x00\x00\x00", -7),
        (b"\x48\x89\x41\x70",             -7),
    ]

    for pat, lea_offset in patterns:
        idx = chunk.find(pat)
        if idx == -1:
            continue
        lea_pos = idx + lea_offset
        if lea_pos < 0 or lea_pos + 7 > len(chunk):
            continue
        if chunk[lea_pos:lea_pos + 3] == b"\x48\x8D\x05":
            disp = struct.unpack_from("<i", chunk, lea_pos + 3)[0]
            rip_val = ep_rva + lea_pos + 7
            return rip_val + disp

    return None


# -- Capstone IOCTL enumerator with shape classification --

def _classify_dispatcher_shape(insns: list, ioctl_reg: int) -> str:
    x86 = capstone.x86
    OP_REG, OP_IMM, OP_MEM = x86.X86_OP_REG, x86.X86_OP_IMM, x86.X86_OP_MEM

    cmp_count = jcc_count = 0
    has_sub = has_ja = has_indirect_jmp = has_jg_jl = False

    for ins in insns[:64]:
        ops = ins.operands
        if ins.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == OP_REG and ops[0].reg == ioctl_reg:
            cmp_count += 1
        elif ins.mnemonic == "sub" and len(ops) == 2 and ops[0].type == OP_REG and ops[0].reg == ioctl_reg and ops[1].type == OP_IMM:
            has_sub = True
        elif ins.mnemonic in ("je", "jne", "jz", "jnz"):
            jcc_count += 1
        elif ins.mnemonic in ("ja", "jae", "jb", "jbe"):
            has_ja = True
        elif ins.mnemonic in ("jg", "jge", "jl", "jle"):
            has_jg_jl = True
        elif ins.mnemonic == "jmp" and ops and ops[0].type == OP_MEM:
            mem = ops[0].mem
            if mem.scale == 8 or mem.index != 0:
                has_indirect_jmp = True

    if has_sub and has_ja and has_indirect_jmp:
        return "sub_cmp_range"
    if has_indirect_jmp and cmp_count >= 1:
        return "switch_jump_table"
    if has_jg_jl and cmp_count >= 3:
        return "binsearch_tree"
    if cmp_count >= 1 and jcc_count >= 1:
        return "cmp_je_chain"
    return "unknown"


def _next_jcc_target(insns: list, k: int) -> Optional[int]:
    x86 = capstone.x86
    for j in range(k + 1, min(k + 5, len(insns))):
        ins = insns[j]
        if ins.mnemonic in ("je", "jne", "jz", "jnz"):
            if ins.operands and ins.operands[0].type == x86.X86_OP_IMM:
                return ins.operands[0].imm
            return None
        if ins.mnemonic in ("cmp", "test", "ret", "jmp"):
            return None
    return None


def _parse_subcmp_range(work: list, ioctl_reg: int):
    x86 = capstone.x86
    OP_REG, OP_IMM, OP_MEM = x86.X86_OP_REG, x86.X86_OP_IMM, x86.X86_OP_MEM
    base = count = jt_rva = None

    for ins in work[:32]:
        ops = ins.operands
        if ins.mnemonic == "sub" and len(ops) == 2 and ops[0].type == OP_REG and ops[0].reg == ioctl_reg and ops[1].type == OP_IMM:
            base = ops[1].imm & 0xFFFFFFFF
        elif ins.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == OP_REG and ops[0].reg == ioctl_reg and ops[1].type == OP_IMM:
            count = ops[1].imm & 0xFFFFFFFF
        elif ins.mnemonic == "jmp" and ops and ops[0].type == OP_MEM:
            mem = ops[0].mem
            if mem.base == x86.X86_REG_RIP:
                jt_rva = ins.address + ins.size + mem.disp
            elif mem.disp:
                jt_rva = mem.disp
            break

    if base is None or count is None or jt_rva is None:
        return (None, None, None)
    return (base, count, jt_rva)


def _read_jump_table(pe: pefile.PE, jt_rva: int, n_entries: int) -> list[int]:
    if n_entries <= 0 or n_entries > 1024:
        return []
    try:
        data = pe.get_data(jt_rva, n_entries * 4)
    except Exception:
        return []
    if not data or len(data) < n_entries * 4:
        return []

    out = []
    for i in range(n_entries):
        rva = struct.unpack("<I", data[i * 4:(i + 1) * 4])[0]
        in_code = any(sec_rva <= rva < sec_rva + sec_size
                      for sec_rva, sec_size, _ in _iter_text_sections(pe))
        out.append(rva if in_code else 0)

    # If none valid as direct RVAs, try as signed offsets from table base
    if not any(out):
        out = []
        for i in range(n_entries):
            disp = struct.unpack("<i", data[i * 4:(i + 1) * 4])[0]
            rva = jt_rva + disp
            in_code = any(sec_rva <= rva < sec_rva + sec_size
                          for sec_rva, sec_size, _ in _iter_text_sections(pe))
            out.append(rva if in_code else 0)
    return out


def _enumerate_ioctls_capstone(pe: pefile.PE, dispatcher_rva: int,
                               errors: list[str]) -> list[tuple[int, int]]:
    body = _read_section_bytes(pe, dispatcher_rva, DISPATCHER_SCAN_BYTES)
    if not body:
        errors.append("dispatcher body unreadable")
        return []

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    x86 = capstone.x86
    OP_REG, OP_MEM, OP_IMM = x86.X86_OP_REG, x86.X86_OP_MEM, x86.X86_OP_IMM

    insns = list(md.disasm(body, dispatcher_rva, count=DISPATCHER_SCAN_INSNS))
    if not insns:
        errors.append("dispatcher: no instructions decoded")
        return []

    # Stage A: locate the IOCTL register via IRP+0xB8 -> IrpSp+0x18 chain
    irpsp_reg = None
    ioctl_reg = None
    ioctl_idx = None

    for idx, ins in enumerate(insns):
        ops = ins.operands
        if (ins.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == OP_REG and ops[1].type == OP_MEM):
            mem = ops[1].mem
            if (mem.base == x86.X86_REG_RDX and mem.index == 0
                    and mem.disp == IRP_CURRENT_STACK_LOCATION_OFF):
                irpsp_reg = ops[0].reg
                continue
            if (irpsp_reg is not None and mem.base == irpsp_reg
                    and mem.index == 0 and mem.disp == IO_STACK_IO_CONTROL_CODE_OFF
                    and ops[0].size == 4):
                ioctl_reg = ops[0].reg
                ioctl_idx = idx
                break

    if ioctl_reg is None:
        errors.append("IOCTL register not found (no IRP+0xB8 / IrpSp+0x18 load)")
        return []

    # Stage B: classify shape and collect IOCTLs
    work = insns[ioctl_idx + 1:]
    shape = _classify_dispatcher_shape(work, ioctl_reg)
    ioctls = []

    if shape in ("cmp_je_chain", "binsearch_tree"):
        seen = set()
        for k, ins in enumerate(work):
            if (ins.mnemonic == "cmp" and len(ins.operands) == 2
                    and ins.operands[0].type == OP_REG
                    and ins.operands[0].reg == ioctl_reg
                    and ins.operands[1].type == OP_IMM):
                imm = ins.operands[1].imm & 0xFFFFFFFF
                if imm not in seen:
                    tgt = _next_jcc_target(work, k)
                    if tgt is not None:
                        ioctls.append((imm, tgt))
                        seen.add(imm)

    elif shape == "sub_cmp_range":
        base, count, jt_rva = _parse_subcmp_range(work, ioctl_reg)
        if base is not None:
            table = _read_jump_table(pe, jt_rva, count + 1)
            for offset, branch_rva in enumerate(table):
                if branch_rva:
                    ioctls.append((base + offset, branch_rva))
        else:
            errors.append("sub/cmp range dispatcher: jump-table not parseable")

    elif shape == "switch_jump_table":
        base, count, jt_rva = _parse_subcmp_range(work, ioctl_reg)
        if base is not None and count is not None and count <= 256:
            table = _read_jump_table(pe, jt_rva, count + 1)
            for offset, branch_rva in enumerate(table):
                if branch_rva:
                    ioctls.append((base + offset, branch_rva))
        else:
            errors.append("switch jump-table dispatcher: not parseable")

    else:
        errors.append(f"dispatcher shape unrecognised: {shape}")

    return ioctls


# -- Bytescan IOCTL enumerator (fallback) --

def _enumerate_ioctls_bytescan(data: bytes, pe: pefile.PE,
                               dispatcher_rva: int) -> list[IOCTLEntry]:
    off = _rva_to_offset(pe, dispatcher_rva)
    if off is None:
        return []

    search_size = min(DISPATCHER_SCAN_BYTES, len(data) - off)
    chunk = data[off:off + search_size]
    entries = []
    seen = set()

    for i in range(len(chunk) - 5):
        imm = None
        if chunk[i] == 0x3D:
            imm = struct.unpack_from("<I", chunk, i + 1)[0]
        elif chunk[i] == 0x81 and (chunk[i + 1] & 0xF8) in (0xF8, 0xF0, 0xE8):
            imm = struct.unpack_from("<I", chunk, i + 2)[0]

        if imm is None:
            continue

        device_type = imm >> CTL_DEVICE_TYPE_SHIFT
        function = (imm & CTL_FUNCTION_MASK) >> CTL_FUNCTION_SHIFT
        if device_type == 0 or function == 0 or device_type > 0xFFFF:
            continue

        if imm not in seen:
            seen.add(imm)
            entries.append(IOCTLEntry(code=imm, handler_rva=dispatcher_rva + i))

    return entries


# -- Per-branch import scanning --

def _scan_branch_imports(pe: pefile.PE, branch_rva: int,
                         iat_map: dict[int, str],
                         thunk_map: dict[int, str]) -> list[str]:
    body = _read_section_bytes(pe, branch_rva, PER_BRANCH_SCAN_BYTES)
    if not body:
        return []

    names = set()

    if HAS_CAPSTONE:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        x86 = capstone.x86
        OP_IMM, OP_MEM = x86.X86_OP_IMM, x86.X86_OP_MEM

        for ins in md.disasm(body, branch_rva, count=PER_BRANCH_SCAN_INSNS):
            ops = ins.operands
            if ins.mnemonic == "call" and ops:
                if ops[0].type == OP_IMM and ops[0].imm in thunk_map:
                    names.add(thunk_map[ops[0].imm])
                elif ops[0].type == OP_MEM and ops[0].mem.base == x86.X86_REG_RIP:
                    tgt_rva = ins.address + ins.size + ops[0].mem.disp
                    if tgt_rva in iat_map:
                        names.add(iat_map[tgt_rva])
            elif ins.mnemonic == "ret":
                break
            elif ins.mnemonic == "jmp" and ops:
                if ops[0].type == OP_IMM:
                    if ops[0].imm in thunk_map:
                        names.add(thunk_map[ops[0].imm])
                    if not (branch_rva <= ops[0].imm < branch_rva + PER_BRANCH_SCAN_BYTES):
                        break
                elif ops[0].type == OP_MEM:
                    if ops[0].mem.base == x86.X86_REG_RIP:
                        tgt_rva = ins.address + ins.size + ops[0].mem.disp
                        if tgt_rva in iat_map:
                            names.add(iat_map[tgt_rva])
                    break
    else:
        n = len(body)
        i = 0
        while i + 5 <= n:
            b = body[i]
            if b == 0xE8:
                disp = struct.unpack("<i", body[i + 1:i + 5])[0]
                tgt = branch_rva + i + 5 + disp
                if tgt in thunk_map:
                    names.add(thunk_map[tgt])
                i += 5
                continue
            if b == 0xFF and i + 6 <= n and body[i + 1] == 0x15:
                disp = struct.unpack("<i", body[i + 2:i + 6])[0]
                tgt_rva = branch_rva + i + 6 + disp
                if tgt_rva in iat_map:
                    names.add(iat_map[tgt_rva])
                i += 6
                continue
            if b == 0xC3:
                break
            i += 1

    return sorted(names)


def _classify_imports(import_names: list[str]) -> list[str]:
    classes = set()
    for name in import_names:
        if name in _IMPORT_TO_CLASSES:
            classes.update(_IMPORT_TO_CLASSES[name])
    return sorted(classes)


# -- Main entry point --

def extract_ioctl_surface(path: str) -> IOCTLSurface:
    p = Path(path)
    result = IOCTLSurface(path=str(p), filename=p.name)

    try:
        data = p.read_bytes()
    except Exception as e:
        result.errors.append(f"read error: {e}")
        return result

    result.sha256 = hashlib.sha256(data).hexdigest()

    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        result.errors.append(f"PE parse error: {e}")
        return result

    if pe.FILE_HEADER.Machine != 0x8664:
        result.errors.append("not x64")
        pe.close()
        return result

    iat_map = _build_iat_map(pe)
    thunk_map = _build_thunk_map(pe, iat_map)

    if HAS_CAPSTONE:
        entry_rva = _resolve_driver_entry(pe, result.errors)
        if entry_rva == 0:
            pe.close()
            return result

        dispatcher_rva = _find_dispatcher_capstone(pe, entry_rva, result.errors)
        if dispatcher_rva:
            result.dispatcher_rva = dispatcher_rva
            result.method = "capstone"
            raw_ioctls = _enumerate_ioctls_capstone(pe, dispatcher_rva, result.errors)

            seen = set()
            for code_int, handler_rva in raw_ioctls:
                if code_int in seen:
                    continue
                seen.add(code_int)
                entry = IOCTLEntry(code=code_int, handler_rva=handler_rva)
                if handler_rva:
                    entry.handler_imports = _scan_branch_imports(
                        pe, handler_rva, iat_map, thunk_map)
                    entry.primitive_classes = _classify_imports(entry.handler_imports)
                result.ioctls.append(entry)
        else:
            # Capstone dispatcher finding failed, fall through to bytescan
            dispatcher_rva = _find_dispatcher_bytescan(data, pe)
            if dispatcher_rva is not None:
                result.dispatcher_rva = dispatcher_rva
                result.method = "bytescan"
                result.ioctls = _enumerate_ioctls_bytescan(data, pe, dispatcher_rva)
            else:
                ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                result.method = "brute"
                result.ioctls = _enumerate_ioctls_bytescan(data, pe, ep_rva)
                if not result.ioctls:
                    result.errors.append("no dispatcher found")
    else:
        dispatcher_rva = _find_dispatcher_bytescan(data, pe)
        if dispatcher_rva is not None:
            result.dispatcher_rva = dispatcher_rva
            result.method = "bytescan"
            result.ioctls = _enumerate_ioctls_bytescan(data, pe, dispatcher_rva)
        else:
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            result.method = "brute"
            result.ioctls = _enumerate_ioctls_bytescan(data, pe, ep_rva)
            if not result.ioctls:
                result.errors.append("no dispatcher found")

    pe.close()
    return result
