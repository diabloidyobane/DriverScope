"""PE import scanner — classify kernel drivers by dangerous import primitives."""

import base64
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed.  pip install pefile", file=sys.stderr)
    sys.exit(1)

PRIMITIVE_CLASSES: dict[str, list[str]] = {
    "PhysMem-Map": [
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "MmMapLockedPages",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesWithReservedMapping",
    ],
    "PhysMem-Unmap": [
        "MmUnmapIoSpace",
        "MmUnmapLockedPages",
    ],
    "PhysMem-Section": [
        "ZwMapViewOfSection",
        "ZwOpenSection",
        "ZwCreateSection",
        "NtMapViewOfSection",
        "NtOpenSection",
        "NtCreateSection",
    ],
    "PhysMem-Copy": [
        "MmCopyMemory",
        "MiCopySinglePage",
    ],
    "CrossProc-VA": [
        "MmCopyVirtualMemory",
        "ZwReadVirtualMemory",
        "ZwWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
    ],
    "CrossProc-Attach": [
        "KeStackAttachProcess",
        "KeAttachProcess",
        "KeUnstackDetachProcess",
        "KeDetachProcess",
    ],
    "Process-Lookup": [
        "PsLookupProcessByProcessId",
        "PsLookupThreadByThreadId",
        "ZwOpenProcess",
        "NtOpenProcess",
    ],
    "CR-Regs": [
        "__readcr0",
        "__readcr2",
        "__readcr3",
        "__readcr4",
        "__readcr8",
        "__writecr0",
        "__writecr3",
        "__writecr4",
        "__writecr8",
    ],
    "MSR": [
        "__readmsr",
        "__writemsr",
        "HalGetBusData",
        "HalSetBusData",
        "HalGetBusDataByOffset",
        "HalSetBusDataByOffset",
    ],
    "Debug-Regs": [
        "__readdr",
        "__writedr",
    ],
    "KernelAlloc": [
        "ExAllocatePool",
        "ExAllocatePoolWithTag",
        "ExAllocatePool2",
        "ExAllocatePool3",
        "ExAllocatePoolZero",
        "MmAllocateContiguousMemory",
        "MmAllocateContiguousMemorySpecifyCache",
        "MmAllocateNonCachedMemory",
    ],
    "KernelExec": [
        "MmGetSystemRoutineAddress",
        "ZwSetSystemInformation",
        "NtSetSystemInformation",
        "ExRegisterCallback",
        "PsCreateSystemThread",
        "IoCreateDriver",
    ],
    "I/O-Port": [
        "READ_PORT_UCHAR",
        "READ_PORT_USHORT",
        "READ_PORT_ULONG",
        "WRITE_PORT_UCHAR",
        "WRITE_PORT_USHORT",
        "WRITE_PORT_ULONG",
        "__inbyte",
        "__inword",
        "__indword",
        "__outbyte",
        "__outword",
        "__outdword",
    ],
    "PCI-Config": [
        "HalGetBusDataByOffset",
        "HalSetBusDataByOffset",
        "HalGetBusData",
        "HalSetBusData",
    ],
    "Interrupt": [
        "__halt",
        "KeBugCheck",
        "KeBugCheckEx",
        "__int2c",
    ],
    "Registry": [
        "ZwSetValueKey",
        "ZwDeleteKey",
        "ZwDeleteValueKey",
    ],
    "Token-Priv": [
        "SePrivilegeCheck",
        "SeSinglePrivilegeCheck",
        "ZwAdjustPrivilegesToken",
        "NtAdjustPrivilegesToken",
    ],
    "Callback-Bypass": [
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutineEx2",
        "PsSetCreateThreadNotifyRoutine",
        "PsSetLoadImageNotifyRoutine",
        "PsSetLoadImageNotifyRoutineEx",
        "CmRegisterCallback",
        "CmRegisterCallbackEx",
        "CmUnRegisterCallback",
        "ObRegisterCallbacks",
        "ObUnRegisterCallbacks",
    ],
    "MDL": [
        "IoAllocateMdl",
        "MmBuildMdlForNonPagedPool",
        "MmProbeAndLockPages",
        "MmUnlockPages",
        "IoFreeMdl",
    ],
}

_IMPORT_TO_CLASSES: dict[str, set[str]] = {}
for _cls_name, _symbols in PRIMITIVE_CLASSES.items():
    for _sym in _symbols:
        _IMPORT_TO_CLASSES.setdefault(_sym, set()).add(_cls_name)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 16):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class DriverResult:
    path: str
    filename: str
    sha256: str = ""
    size: int = 0
    is_64bit: bool = False
    is_signed: bool = False
    signer: str = ""
    imports: list[str] = field(default_factory=list)
    flagged_imports: list[str] = field(default_factory=list)
    primitive_classes: list[str] = field(default_factory=list)
    score: int = 0
    device_names: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # LOLDrivers enrichment
    lol_known: bool = False
    lol_id: str = ""
    lol_hvci_bypass: bool = False
    lol_cves: list[str] = field(default_factory=list)
    lol_category: str = ""
    lol_tags: list[str] = field(default_factory=list)
    # MS Blocklist enrichment
    ms_blocked: bool = False
    # VT enrichment
    vt_detections: int = 0
    vt_total: int = 0
    vt_signer: str = ""


def scan_driver(path: str) -> DriverResult:
    p = Path(path)
    result = DriverResult(path=str(p), filename=p.name)

    try:
        data = p.read_bytes()
    except Exception as e:
        result.errors.append(f"read error: {e}")
        return result

    result.size = len(data)
    result.sha256 = sha256_bytes(data)

    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        result.errors.append(f"PE parse error: {e}")
        return result

    result.is_64bit = pe.FILE_HEADER.Machine == 0x8664

    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        result.is_signed = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
    except (IndexError, AttributeError):
        pass

    try:
        for entry in getattr(pe, "FileInfo", []):
            for st in getattr(entry, "StringTable", []):
                for item in st.entries.items():
                    key = item[0].decode("utf-8", errors="replace")
                    val = item[1].decode("utf-8", errors="replace")
                    if key.lower() in ("companyname", "legalcopyright"):
                        if val and not result.signer:
                            result.signer = val[:80]
    except Exception:
        pass

    all_imports: list[str] = []
    flagged: list[str] = []
    hit_classes: set[str] = set()

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", errors="replace")
                    all_imports.append(name)
                    if name in _IMPORT_TO_CLASSES:
                        flagged.append(name)
                        hit_classes.update(_IMPORT_TO_CLASSES[name])

    result.imports = all_imports
    result.flagged_imports = sorted(set(flagged))
    result.primitive_classes = sorted(hit_classes)
    result.score = len(hit_classes)

    # Interesting strings (device names, etc.)
    _extract_strings(data, result)

    pe.close()
    return result


def _extract_strings(data: bytes, result: DriverResult) -> None:
    device_markers = [b"\\Device\\", b"\\DosDevices\\", b"\\\\.\\"]
    for marker in device_markers:
        idx = 0
        while True:
            idx = data.find(marker, idx)
            if idx == -1:
                break
            end = idx + len(marker)
            while end < len(data) and end < idx + 200:
                b = data[end]
                if b == 0 or b < 0x20 or b > 0x7E:
                    break
                end += 1
            name = data[idx:end].decode("ascii", errors="replace")
            if len(name) > len(marker.decode()) + 2:
                result.device_names.append(name)
            idx = end

    # Also check for wide-char device strings
    for marker_bytes in device_markers:
        marker_wide = marker_bytes.decode().encode("utf-16-le")
        idx = 0
        while True:
            idx = data.find(marker_wide, idx)
            if idx == -1:
                break
            end = idx
            chars = []
            while end + 1 < len(data) and end < idx + 400:
                lo, hi = data[end], data[end + 1]
                if hi != 0 or lo == 0 or lo < 0x20 or lo > 0x7E:
                    break
                chars.append(chr(lo))
                end += 2
            name = "".join(chars)
            if len(name) > len(marker_bytes.decode()) + 2:
                result.device_names.append(name)
            idx = end if end > idx else idx + 2


def scan_directory(path: str, recursive: bool = True) -> list[DriverResult]:
    root = Path(path)
    pattern = "**/*.sys" if recursive else "*.sys"
    results = []
    files = sorted(root.glob(pattern))
    total = len(files)

    for i, f in enumerate(files, 1):
        print(f"\r  [{i}/{total}] {f.name:<40}", end="", file=sys.stderr, flush=True)
        result = scan_driver(str(f))
        results.append(result)

    if total:
        print(file=sys.stderr)

    results.sort(key=lambda r: (-r.score, r.filename.lower()))
    return results


VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT = 4
_vt_timestamps: list[float] = []
_vt_cache: dict[str, dict] = {}
_vt_cache_dirty: bool = False
_vt_cache_path: Optional[str] = None
_vt_cache_disabled: bool = False
_vt_ttl_seconds: int = 30 * 86400


class VTTransient(Exception):
    pass


class VTQuotaExhausted(Exception):
    pass


def _vt_throttle():
    now = time.time()
    _vt_timestamps[:] = [t for t in _vt_timestamps if now - t < 60]
    if len(_vt_timestamps) >= VT_RATE_LIMIT:
        wait = 60 - (now - _vt_timestamps[0]) + 0.5
        if wait > 0:
            print(f"\r  [VT] rate limit -- waiting {wait:.0f}s...",
                  end="", file=sys.stderr, flush=True)
            time.sleep(wait)
    _vt_timestamps.append(time.time())


def _vt_request(endpoint: str, api_key: str, method: str = "GET",
                params: dict = None, max_attempts: int = 3) -> Optional[dict]:
    url = f"{VT_API_BASE}/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    for attempt in range(1, max_attempts + 1):
        _vt_throttle()
        req = urllib.request.Request(url, method=method)
        req.add_header("x-apikey", api_key)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                if attempt == max_attempts:
                    raise VTQuotaExhausted(f"VT 429 after {attempt} attempts")
                time.sleep(30 * attempt)
                continue
            if attempt == max_attempts:
                raise VTTransient(f"HTTP {e.code}")
        except Exception as e:
            if attempt == max_attempts:
                raise VTTransient(str(e))
            time.sleep(5 * attempt)
    return None


@dataclass
class VTInfo:
    detected: bool = False
    detections: int = 0
    total_engines: int = 0
    detection_names: list[str] = field(default_factory=list)
    known_names: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    reputation: int = 0
    tags: list[str] = field(default_factory=list)
    signature_info: str = ""
    ms_blocklist: bool = False
    loldriver: bool = False
    error: str = ""


def vt_cache_init(path: str, ttl_seconds: int = 30 * 86400,
                  disabled: bool = False) -> None:
    global _vt_cache, _vt_cache_path, _vt_ttl_seconds, _vt_cache_disabled
    _vt_cache_path = path
    _vt_ttl_seconds = ttl_seconds
    _vt_cache_disabled = disabled
    if disabled or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            _vt_cache = json.load(f)
        now = time.time()
        for sha, entry in list(_vt_cache.items()):
            age = now - entry.get("fetched_at", 0)
            if entry.get("error_kind") != "not_found" and age > ttl_seconds:
                del _vt_cache[sha]
        print(f"  [VT] cache: {len(_vt_cache)} entries from {path}",
              file=sys.stderr)
    except Exception as e:
        print(f"  [VT] cache load failed: {e}", file=sys.stderr)
        _vt_cache = {}


def vt_cache_save() -> None:
    global _vt_cache_dirty
    if not _vt_cache_dirty or _vt_cache_disabled or not _vt_cache_path:
        return
    try:
        tmp = _vt_cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_vt_cache, f, indent=2)
        os.replace(tmp, _vt_cache_path)
        _vt_cache_dirty = False
    except Exception as e:
        print(f"  [VT] cache save failed: {e}", file=sys.stderr)


def vt_lookup_hash(sha256: str, api_key: str) -> VTInfo:
    global _vt_cache_dirty
    sha = sha256.lower()

    if not _vt_cache_disabled and sha in _vt_cache:
        d = _vt_cache[sha]
        return VTInfo(
            detected=d.get("detected", False),
            detections=d.get("detections", 0),
            total_engines=d.get("total_engines", 0),
            detection_names=d.get("detection_names", []),
            known_names=d.get("known_names", []),
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            reputation=d.get("reputation", 0),
            tags=d.get("tags", []),
            signature_info=d.get("signature_info", ""),
            error=d.get("error", ""),
        )

    info = VTInfo()
    try:
        data = _vt_request(f"files/{sha}", api_key)
    except VTQuotaExhausted:
        info.error = "VT quota exhausted"
        raise
    except VTTransient as e:
        info.error = f"transient: {e}"
        return info

    if data is None:
        info.error = "not found on VT"
        if not _vt_cache_disabled:
            _vt_cache[sha] = {"sha256": sha, "error": info.error,
                              "error_kind": "not_found",
                              "fetched_at": time.time()}
            _vt_cache_dirty = True
        return info

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    info.detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
    info.total_engines = sum(stats.values())
    info.detected = info.detections > 0

    results = attrs.get("last_analysis_results", {})
    for engine, result in results.items():
        if result.get("category") in ("malicious", "suspicious") and result.get("result"):
            info.detection_names.append(f"{engine}:{result['result']}")

    info.known_names = attrs.get("names", [])[:10]

    fs = attrs.get("first_submission_date")
    if fs:
        info.first_seen = time.strftime("%Y-%m-%d", time.gmtime(fs))
    ls = attrs.get("last_submission_date")
    if ls:
        info.last_seen = time.strftime("%Y-%m-%d", time.gmtime(ls))

    info.reputation = attrs.get("reputation", 0)
    info.tags = attrs.get("tags", [])

    sig = attrs.get("signature_info", {})
    if isinstance(sig, dict):
        signer = sig.get("subject", sig.get("signers", ""))
        if signer:
            info.signature_info = str(signer)[:80]

    popular = attrs.get("popular_threat_classification", {})
    if popular:
        label = popular.get("suggested_threat_label", "")
        if label:
            info.detection_names.insert(0, f"[VT:{label}]")

    if not _vt_cache_disabled:
        _vt_cache[sha] = {**asdict(info), "sha256": sha,
                          "fetched_at": time.time(), "error_kind": ""}
        _vt_cache_dirty = True
        vt_cache_save()

    return info


LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"


@dataclass
class LOLDriver:
    lol_id: str
    filename: str
    sha256: str
    md5: str
    category: str
    publisher: str
    description: str
    product: str
    cves: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    matched_imports: list[str] = field(default_factory=list)
    primitive_classes: list[str] = field(default_factory=list)
    machine_type: str = ""
    loads_despite_hvci: bool = False
    tags: list[str] = field(default_factory=list)


def build_lol_index(cache_path: str = None,
                    max_age_hours: int = 168) -> dict[str, dict]:
    if cache_path is None:
        cache_path = os.path.join(os.getcwd(), "loldrivers_cache.json")

    raw_catalog = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                raw_catalog = json.load(f)
            print(f"  [LOLDrivers] Loaded cache ({len(raw_catalog)} entries)",
                  file=sys.stderr)
        except Exception:
            raw_catalog = None

    if raw_catalog is None:
        print(f"  [LOLDrivers] Fetching from {LOLDRIVERS_URL}...",
              file=sys.stderr, flush=True)
        req = urllib.request.Request(LOLDRIVERS_URL)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw_catalog = json.loads(resp.read())
            with open(cache_path, "w") as f:
                json.dump(raw_catalog, f)
            print(f"  [LOLDrivers] Cached {len(raw_catalog)} entries",
                  file=sys.stderr)
        except Exception as e:
            print(f"  [LOLDrivers] fetch failed: {e}", file=sys.stderr)
            return {}

    index: dict[str, dict] = {}
    for entry in raw_catalog:
        lol_id = entry.get("Id", "")
        category = entry.get("Category", "")
        cves = entry.get("CVE", []) or []
        if isinstance(cves, str):
            cves = [cves]
        tags = entry.get("Tags", []) or []
        if isinstance(tags, str):
            tags = [tags]
        for sample in entry.get("KnownVulnerableSamples", []):
            sha = (sample.get("SHA256") or "").lower()
            if len(sha) != 64:
                continue
            index[sha] = {
                "lol_id": lol_id,
                "category": category,
                "cves": cves,
                "tags": tags,
                "loads_despite_hvci": bool(sample.get("LoadsDespiteHVCI", False)),
                "filename": (sample.get("Filename")
                             or sample.get("OriginalFilename") or ""),
            }

    print(f"  [LOLDrivers] Indexed {len(index)} unique SHA256 hashes",
          file=sys.stderr)
    return index


def enrich_with_lol(results: list[DriverResult],
                    lol_index: dict[str, dict]) -> None:
    for r in results:
        if not r.sha256:
            continue
        rec = lol_index.get(r.sha256.lower())
        if rec:
            r.lol_known = True
            r.lol_id = rec["lol_id"]
            r.lol_hvci_bypass = rec["loads_despite_hvci"]
            r.lol_cves = rec["cves"]
            r.lol_category = rec["category"]
            r.lol_tags = rec["tags"]


MS_BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"
_blocklist_cache: dict[str, str] = {}


def _parse_blocklist_xml(xml_data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return result

    for deny in root.iter():
        if "Deny" in deny.tag or "deny" in deny.tag:
            h = deny.get("Hash", "")
            fn = deny.get("FriendlyName", "")
            if h and len(h) == 64:
                result[h.lower()] = fn
            elif h:
                try:
                    decoded = base64.b64decode(h)
                    if len(decoded) == 32:
                        result[decoded.hex()] = fn
                except Exception:
                    pass
    return result


def fetch_ms_blocklist(cache_path: str = None) -> dict[str, str]:
    global _blocklist_cache
    if _blocklist_cache:
        return _blocklist_cache

    if cache_path is None:
        cache_path = os.path.join(os.getcwd(), "ms_blocklist_sha256.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                data = json.load(f)
            hashes = set(data.get("hashes", []))
            names = data.get("driver_names", {})
            _blocklist_cache = {h: names.get(h, "") for h in hashes}
            print(f"  [Blocklist] Loaded {len(_blocklist_cache)} hashes from cache",
                  file=sys.stderr)
            return _blocklist_cache
        except Exception:
            pass

    print("  [Blocklist] Downloading from Microsoft...",
          file=sys.stderr, flush=True)
    req = urllib.request.Request(MS_BLOCKLIST_URL)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except Exception as e:
        print(f"  [Blocklist] Download failed: {e}", file=sys.stderr)
        return {}

    if raw[:2] != b"PK":
        print("  [Blocklist] Unexpected format (not ZIP)", file=sys.stderr)
        return {}

    xml_data = None
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            if name.endswith(".xml") and "Legacy" not in name:
                xml_data = zf.read(name)
                break
        if xml_data is None:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    xml_data = zf.read(name)
                    break

    if xml_data is None:
        print("  [Blocklist] No XML found in ZIP", file=sys.stderr)
        return {}

    _blocklist_cache = _parse_blocklist_xml(xml_data)

    try:
        names_map = {h: n for h, n in _blocklist_cache.items() if n}
        with open(cache_path, "w") as f:
            json.dump({
                "source": "Microsoft Vulnerable Driver Blocklist",
                "count": len(_blocklist_cache),
                "hashes": list(_blocklist_cache.keys()),
                "driver_names": names_map,
            }, f, indent=2)
    except Exception:
        pass

    print(f"  [Blocklist] Parsed {len(_blocklist_cache)} hashes",
          file=sys.stderr)
    return _blocklist_cache


def enrich_with_blocklist(results: list[DriverResult],
                          blocklist: dict[str, str]) -> None:
    for r in results:
        if r.sha256 and r.sha256.lower() in blocklist:
            r.ms_blocked = True
