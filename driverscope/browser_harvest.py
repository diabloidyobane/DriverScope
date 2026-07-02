"""Browser-based driver harvester using patchright (anti-detection chromium).

Downloads hardware utility installers from vendor sites, extracts .sys files.
"""
import asyncio
import hashlib
import shutil
import subprocess
import struct
import tempfile
from pathlib import Path

SEVEN_ZIP = r"C:\Program Files\7-Zip\7z.exe"
OUT_DIR = Path(r"C:\Users\Jon\Desktop\driver_inventory\20_browser_harvest")
DRIVERS_DIR = OUT_DIR / "drivers"
STAGING_DIR = OUT_DIR / "staging"

TARGETS = [
    {"name": "cpuz_latest", "url": "https://download.cpuid.com/cpu-z/cpu-z_2.12-en.zip"},
    {"name": "hwinfo64_portable", "url": "https://www.hwinfo.com/files/hwi_848.zip"},
    {"name": "aida64_extreme", "url": "https://download.aida64.com/aida64extreme740.zip"},
    {"name": "speedfan", "url": "https://www.almico.com/speedfan453.exe"},
    {"name": "coretemp", "url": "https://www.alcpu.com/CoreTemp/php/download.php?id=1"},
    {"name": "winio", "url": "https://www.internals.com/utilities/WinIO_3_0.zip"},
    {"name": "smu_debug", "url": "https://github.com/irusanov/SMUDebugTool/releases/download/v1.40/SMUDebugTool_v1.40.zip"},
    {"name": "ohm", "url": "https://openhardwaremonitor.org/files/openhardwaremonitor-v0.9.6.zip"},
    {"name": "lhm", "url": "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases/download/v0.10.0/LibreHardwareMonitor-net10-0.10.0.zip"},
    {"name": "fancontrol", "url": "https://github.com/Rem0o/FanControl.Releases/releases/download/V270/FanControl_270_net_10_0.zip"},
    {"name": "zentimings", "url": "https://github.com/irusanov/ZenTimings/releases/download/v1.39/ZenTimings_v1.39.zip"},
    {"name": "rweverything", "url": "http://rweverything.com/downloads/RwPortableX64V1.7.zip"},
    {"name": "winobjex", "url": "https://github.com/hfiref0x/WinObjEx64/releases/download/v2.1.0/WinObjEx64_2.1.0.zip"},
    {"name": "processhacker", "url": "https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe"},
    {"name": "nbfc", "url": "https://github.com/hirschmann/nbfc/releases/download/1.6.3/NoteBookFanControl.1.6.3.setup.exe"},
    {"name": "samsung_magician", "url": "https://download.semiconductor.samsung.com/resources/software-resources/Samsung_Magician_Installer_Official_9.0.1.950.exe"},
    {"name": "crystaldiskinfo", "url": "https://crystalmark.info/download/zz/CrystalDiskInfo9_9_1.exe"},
    {"name": "afterburner", "url": "https://download.msi.com/uti_exe/vga/MSIAfterburnerSetup470.exe"},
    {"name": "gpuz", "url": "https://www.techpowerup.com/download/techpowerup-gpu-z/"},
    {"name": "throttlestop", "url": "https://www.techpowerup.com/download/techpowerup-throttlestop/"},
    {"name": "precision_x1", "url": "https://www.evga.com/precisionx1/PrecisionX1Setup.exe"},
    {"name": "burnintest", "url": "https://www.passmark.com/downloads/bitdl.php"},
]


def find_embedded_drivers(data):
    results = []
    offset = 0
    while True:
        pos = data.find(b"MZ", offset)
        if pos == -1 or pos + 0x40 > len(data):
            break
        offset = pos + 2
        try:
            pe_off = struct.unpack_from("<I", data, pos + 0x3C)[0]
            if pos + pe_off + 4 > len(data):
                continue
            if data[pos+pe_off:pos+pe_off+4] != b"PE\x00\x00":
                continue
            coff = pos + pe_off + 4
            machine = struct.unpack_from("<H", data, coff)[0]
            opt = coff + 20
            magic = struct.unpack_from("<H", data, opt)[0]
            if magic not in (0x10B, 0x20B):
                continue
            subsystem = struct.unpack_from("<H", data, opt+68)[0]
            chunk = data[pos:min(pos+100000, len(data))]
            is_kernel = (subsystem == 1 or b"ntoskrnl" in chunk.lower()
                        or b"hal.dll" in chunk.lower() or b"wdfldr" in chunk.lower())
            if not is_kernel:
                continue
            opt_size = struct.unpack_from("<H", data, coff+16)[0]
            num_sec = struct.unpack_from("<H", data, coff+2)[0]
            sec_tab = opt + opt_size
            max_end = 0
            for i in range(min(num_sec, 20)):
                s = sec_tab + i*40
                if s + 40 > len(data):
                    break
                raw_sz = struct.unpack_from("<I", data, s+16)[0]
                raw_ptr = struct.unpack_from("<I", data, s+20)[0]
                if raw_ptr + raw_sz > max_end:
                    max_end = raw_ptr + raw_sz
            if max_end < 1000:
                continue
            arch = "x64" if machine == 0x8664 else "x86"
            results.append({"offset": pos, "size": max_end, "arch": arch,
                           "data": data[pos:pos+max_end]})
        except Exception:
            continue
    return results


def extract_sys(filepath, tag):
    extracted = []
    fp = Path(filepath)
    with tempfile.TemporaryDirectory(prefix="bh_") as tmp:
        tmp_path = Path(tmp)
        try:
            subprocess.run([SEVEN_ZIP, "x", "-y", f"-o{tmp_path}", str(fp)],
                          capture_output=True, timeout=120, encoding="utf-8", errors="replace")
        except Exception:
            pass
        for nested in list(tmp_path.rglob("*")):
            if nested.suffix.lower() in {".cab", ".zip", ".7z", ".msi", ".nupkg"} and nested.stat().st_size > 1000:
                nested_out = tmp_path / f"_n_{nested.stem}"
                nested_out.mkdir(exist_ok=True)
                try:
                    subprocess.run([SEVEN_ZIP, "x", "-y", f"-o{nested_out}", str(nested)],
                                  capture_output=True, timeout=60, encoding="utf-8", errors="replace")
                except Exception:
                    pass
        for sf in tmp_path.rglob("*.sys"):
            if sf.stat().st_size < 1000:
                continue
            try:
                if sf.read_bytes()[:2] != b"MZ":
                    continue
            except Exception:
                continue
            out_name = f"{tag}__{sf.name}"
            dst = DRIVERS_DIR / out_name
            if not dst.exists():
                shutil.copy2(sf, dst)
                extracted.append(dst)
        for exe in tmp_path.rglob("*.exe"):
            if exe.stat().st_size < 50000:
                continue
            try:
                data = exe.read_bytes()
                drivers = find_embedded_drivers(data)
                for i, drv in enumerate(drivers):
                    out_name = f"{tag}__{exe.stem}_{drv['arch']}_{i}.sys"
                    dst = DRIVERS_DIR / out_name
                    if not dst.exists():
                        dst.write_bytes(drv["data"])
                        extracted.append(dst)
            except Exception:
                continue
        for dll in tmp_path.rglob("*.dll"):
            if dll.stat().st_size < 50000:
                continue
            try:
                data = dll.read_bytes()
                drivers = find_embedded_drivers(data)
                for i, drv in enumerate(drivers):
                    out_name = f"{tag}__{dll.stem}_{drv['arch']}_{i}.sys"
                    dst = DRIVERS_DIR / out_name
                    if not dst.exists():
                        dst.write_bytes(drv["data"])
                        extracted.append(dst)
            except Exception:
                continue
    # scan the file itself for embedded drivers
    try:
        data = fp.read_bytes()
        if data[:2] == b"MZ":
            drivers = find_embedded_drivers(data)
            for i, drv in enumerate(drivers):
                out_name = f"{tag}__self_{drv['arch']}_{i}.sys"
                dst = DRIVERS_DIR / out_name
                if not dst.exists():
                    dst.write_bytes(drv["data"])
                    extracted.append(dst)
    except Exception:
        pass
    return extracted


def scan_physmem(filepath):
    try:
        data = Path(filepath).read_bytes()
    except Exception:
        return False, set()
    imports = set()
    for api in [b"MmMapIoSpace", b"ZwMapViewOfSection", b"ZwOpenSection",
                b"MmMapLockedPages", b"MmGetPhysicalAddress",
                b"HalGetBusDataByOffset", b"__readmsr"]:
        if api in data:
            imports.add(api.decode())
    return bool(imports), imports


async def main():
    print(f"=== Browser Driver Harvester (patchright) ===")
    print(f"targets: {len(TARGETS)}\n")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    DRIVERS_DIR.mkdir(parents=True, exist_ok=True)

    from patchright.async_api import async_playwright

    dl_results = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(accept_downloads=True)

        for t in TARGETS:
            name = t["name"]
            url = t["url"]
            ext = Path(url).suffix if Path(url).suffix in {".zip", ".exe", ".msi", ".7z"} else ".bin"
            staging_file = STAGING_DIR / f"{name}{ext}"

            if staging_file.exists() and staging_file.stat().st_size > 10000:
                print(f"  [cached] {name:<25} {staging_file.stat().st_size:>12,} bytes")
                dl_results[name] = {"status": "cached", "path": str(staging_file)}
                continue

            print(f"  [fetch]  {name:<25}", end=" ", flush=True)
            page = await context.new_page()
            try:
                # expect_download BEFORE goto - catches direct download URLs
                async with page.expect_download(timeout=120000) as dl_info:
                    try:
                        await page.goto(url, timeout=30000, wait_until="commit")
                    except Exception:
                        pass  # "Download is starting" is expected

                download = await dl_info.value
                await download.save_as(str(staging_file))
                sz = staging_file.stat().st_size
                print(f"-> {sz:>12,} bytes  ({download.suggested_filename})")
                dl_results[name] = {"status": "ok", "path": str(staging_file), "size": sz}

            except Exception as e:
                # try page-based download (click button)
                try:
                    await page.goto(url, timeout=30000, wait_until="domcontentloaded")
                    # look for download links
                    for sel in ['a[href$=".zip"]', 'a[href$=".exe"]', 'a[href*="download"]',
                               'a.download', '.download-btn a', '#download']:
                        link = await page.query_selector(sel)
                        if link:
                            try:
                                async with page.expect_download(timeout=60000) as dl2:
                                    await link.click()
                                download = await dl2.value
                                await download.save_as(str(staging_file))
                                sz = staging_file.stat().st_size
                                print(f"-> {sz:>12,} bytes  (click)")
                                dl_results[name] = {"status": "ok", "path": str(staging_file), "size": sz}
                                break
                            except Exception:
                                continue
                    if name not in dl_results:
                        err = str(e)[:60]
                        print(f"-> FAIL: {err}")
                        dl_results[name] = {"status": "error", "error": err}
                except Exception as e2:
                    print(f"-> FAIL: {str(e2)[:60]}")
                    dl_results[name] = {"status": "error", "error": str(e2)[:60]}
            finally:
                await page.close()
                await asyncio.sleep(0.5)

        await browser.close()

    # phase 2: extract
    print(f"\n--- Phase 2: Extract .sys ---")
    all_drivers = []
    for t in TARGETS:
        name = t["name"]
        r = dl_results.get(name, {})
        path = r.get("path")
        if not path or not Path(path).exists():
            continue
        drivers = extract_sys(path, name)
        print(f"  {name:<25} -> {len(drivers):>3} .sys")
        all_drivers.extend(drivers)

    # phase 3: physmem scan
    print(f"\n--- Phase 3: Physmem scan ---")
    physmem_hits = []
    for drv in all_drivers:
        has_physmem, imports = scan_physmem(drv)
        if has_physmem:
            sha = hashlib.sha256(drv.read_bytes()).hexdigest()
            physmem_hits.append({
                "file": str(drv), "name": drv.name,
                "size": drv.stat().st_size, "sha256": sha,
                "imports": sorted(imports),
            })
            print(f"  [HIT] {drv.name:<55} {', '.join(imports)}")

    print(f"\n{'='*70}")
    ok_count = sum(1 for r in dl_results.values() if r.get("status") in ("ok", "cached"))
    print(f"downloaded: {ok_count}/{len(TARGETS)}")
    print(f"extracted: {len(all_drivers)} .sys files")
    print(f"physmem hits: {len(physmem_hits)}")

    import json
    report = OUT_DIR / "harvest_report.json"
    report.write_text(json.dumps({
        "downloads": dl_results, "extracted_count": len(all_drivers),
        "physmem_hits": physmem_hits,
    }, indent=2), encoding="utf-8")
    print(f"report: {report}")


if __name__ == "__main__":
    asyncio.run(main())
