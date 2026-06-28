"""DriverScope CLI."""

import argparse
import json
import os
import sys
from pathlib import Path


def cmd_scan(args):
    from .scanner import (
        scan_driver, scan_directory, build_lol_index, enrich_with_lol,
        fetch_ms_blocklist, enrich_with_blocklist, vt_cache_init,
        vt_lookup_hash, vt_cache_save, VTQuotaExhausted, PRIMITIVE_CLASSES,
    )

    path = Path(args.path)
    if path.is_dir():
        results = scan_directory(str(path), recursive=not args.no_recursive)
    elif path.is_file():
        results = [scan_driver(str(path))]
    else:
        print(f"Error: {path} not found", file=sys.stderr)
        return 1

    if not results:
        print("No .sys files found.")
        return 0

    if args.lol:
        lol_index = build_lol_index()
        enrich_with_lol(results, lol_index)

    if args.blocklist:
        bl = fetch_ms_blocklist()
        enrich_with_blocklist(results, bl)

    if args.vt:
        api_key = args.vt_key or os.environ.get("VT_API_KEY")
        if not api_key:
            print("Error: VT API key required (--vt-key or VT_API_KEY env var)",
                  file=sys.stderr)
            return 1
        vt_cache_init("vt_cache.json")
        for r in results:
            if r.sha256:
                try:
                    vt = vt_lookup_hash(r.sha256, api_key)
                    r.vt_detections = vt.detections
                    r.vt_total = vt.total_engines
                    if vt.signature_info:
                        r.vt_signer = vt.signature_info
                except VTQuotaExhausted:
                    print("\n  VT quota exhausted, stopping VT lookups",
                          file=sys.stderr)
                    break
        vt_cache_save()

    ioctl_map = {}
    if args.ioctl:
        from .ioctl import extract_ioctl_surface, HAS_CAPSTONE
        method = "capstone" if HAS_CAPSTONE else "bytescan"
        print(f"\n  Extracting IOCTLs ({method})...", file=sys.stderr)
        flagged = [r for r in results if r.flagged_imports]
        for i, r in enumerate(flagged, 1):
            print(f"\r  [{i}/{len(flagged)}] {r.filename:<40}",
                  end="", file=sys.stderr, flush=True)
            try:
                surface = extract_ioctl_surface(r.path)
                if surface.ioctls:
                    ioctl_map[r.sha256] = surface
            except Exception:
                pass
        print(file=sys.stderr)

    if args.json:
        from dataclasses import asdict
        out = []
        for r in results:
            if not r.flagged_imports and not args.all:
                continue
            d = asdict(r)
            if r.sha256 in ioctl_map:
                surface = ioctl_map[r.sha256]
                d["ioctl_count"] = len(surface.ioctls)
                d["ioctls"] = [{
                    "code": hex(e.code),
                    "device_type": e.ctl.device_type_name,
                    "function": e.ctl.function,
                    "method": e.ctl.method_name,
                    "access": e.ctl.access_name,
                    "handler_imports": e.handler_imports,
                    "primitive_classes": e.primitive_classes,
                } for e in surface.ioctls]
            out.append(d)
        text = json.dumps(out, indent=2)
        print(text)
        if args.export:
            Path(args.export).write_text(text)
            print(f"\n  Exported to {args.export}", file=sys.stderr)
    else:
        flagged = [r for r in results if r.flagged_imports]
        clean = len(results) - len(flagged)

        print(f"\n{'='*100}")
        print(f"  SCAN RESULTS: {len(flagged)} flagged / {len(results)} total "
              f"({clean} clean)")
        print(f"{'='*100}\n")

        if not flagged:
            print("  No drivers with red-flag imports found.")
            return 0

        has_ioctls = bool(ioctl_map)
        hdr_ioctl = " {'IOCTLs':>6}" if has_ioctls else ""
        print(f"  {'#':<4} {'Driver':<30} {'Score':>5} {'Arch':<5} "
              f"{'Signed':<6} {'LOL':<4} {'BL':<3}"
              + (f" {'IOCTLs':>6}" if has_ioctls else "")
              + f" Primitive Classes")
        print(f"  {'-'*4} {'-'*30} {'-'*5} {'-'*5} {'-'*6} {'-'*4} "
              f"{'-'*3}"
              + (f" {'-'*6}" if has_ioctls else "")
              + f" {'-'*40}")

        for i, r in enumerate(flagged, 1):
            name = r.filename[:29] if len(r.filename) <= 29 else r.filename[:26] + "..."
            arch = "x64" if r.is_64bit else "x86"
            signed = "YES" if r.is_signed else "no"
            lol = "YES" if r.lol_known else ""
            bl = "BL" if r.ms_blocked else ""
            classes = ", ".join(r.primitive_classes)
            ioctl_col = ""
            if has_ioctls:
                surface = ioctl_map.get(r.sha256)
                ioctl_col = f" {len(surface.ioctls):>6}" if surface else f" {'':>6}"
            print(f"  {i:<4} {name:<30} {r.score:>5} {arch:<5} "
                  f"{signed:<6} {lol:<4} {bl:<3}{ioctl_col} {classes}")

        print(f"\n{'-'*100}")
        for r in flagged[:20]:
            print(f"\n  {r.filename}")
            print(f"    SHA256: {r.sha256}")
            print(f"    Size: {r.size:,} bytes")
            if r.signer:
                print(f"    Signer: {r.signer}")
            if r.device_names:
                print(f"    Devices: {', '.join(r.device_names[:3])}")
            if r.lol_known:
                print(f"    [LOLDrivers] {r.lol_id}: {r.lol_category}")
                if r.lol_cves:
                    print(f"    CVEs: {', '.join(r.lol_cves)}")
            if r.ms_blocked:
                print(f"    [MS BLOCKED]")
            for cls in r.primitive_classes:
                syms = [s for s in r.flagged_imports
                        if s in PRIMITIVE_CLASSES.get(cls, [])]
                if syms:
                    print(f"    [{cls}] {', '.join(syms)}")

            if r.sha256 in ioctl_map:
                surface = ioctl_map[r.sha256]
                print(f"    IOCTLs: {len(surface.ioctls)} (via {surface.method})")
                for e in surface.ioctls[:8]:
                    parts = f"0x{e.code:08X} {e.ctl.device_type_name} {e.ctl.method_name}"
                    if e.primitive_classes:
                        parts += f"  [{', '.join(e.primitive_classes)}]"
                    print(f"      {parts}")
                if len(surface.ioctls) > 8:
                    print(f"      ... +{len(surface.ioctls) - 8} more")

        if args.export:
            from dataclasses import asdict
            out = [asdict(r) for r in flagged]
            Path(args.export).write_text(json.dumps(out, indent=2))
            print(f"\n  Exported to {args.export}", file=sys.stderr)

    return 0


def cmd_hunt(args):
    from .hunter import hunt, format_results

    candidates = hunt(
        scan_paths=args.scan_path,
        deep=args.deep,
        extra_paths=args.extra_path,
        min_score=args.min_score,
    )

    output = format_results(candidates, json_output=args.json)
    print(output)

    if args.export and candidates:
        with open(args.export, "w") as f:
            f.write(format_results(candidates, json_output=True))
        print(f"\n  Exported {len(candidates)} candidates to {args.export}",
              file=sys.stderr)

    return 0


def cmd_ioctl(args):
    from .ioctl import extract_ioctl_surface

    paths = []
    target = Path(args.path)
    if target.is_dir():
        paths = sorted(target.glob("**/*.sys" if not args.no_recursive else "*.sys"))
    elif target.is_file():
        paths = [target]
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        return 1

    surfaces = []
    for i, p in enumerate(paths, 1):
        if len(paths) > 1:
            print(f"\r  [{i}/{len(paths)}] {p.name:<40}",
                  end="", file=sys.stderr, flush=True)
        surfaces.append(extract_ioctl_surface(str(p)))
    if len(paths) > 1:
        print(file=sys.stderr)

    surfaces = [s for s in surfaces if s.ioctls or not args.hits_only]

    if args.json:
        out = []
        for surface in surfaces:
            entry = {
                "filename": surface.filename,
                "sha256": surface.sha256,
                "method": surface.method,
                "dispatcher_rva": hex(surface.dispatcher_rva) if surface.dispatcher_rva else None,
                "ioctl_count": len(surface.ioctls),
                "ioctls": [],
                "errors": surface.errors,
            }
            for e in surface.ioctls:
                entry["ioctls"].append({
                    "code": hex(e.code),
                    "device_type": e.ctl.device_type_name,
                    "function": e.ctl.function,
                    "method": e.ctl.method_name,
                    "access": e.ctl.access_name,
                    "handler_rva": hex(e.handler_rva),
                    "handler_imports": e.handler_imports,
                    "primitive_classes": e.primitive_classes,
                })
            out.append(entry)
        text = json.dumps(out if len(out) != 1 else out[0], indent=2)
        print(text)
        if args.export:
            Path(args.export).write_text(text)
            print(f"\n  Exported to {args.export}", file=sys.stderr)
    else:
        for surface in surfaces:
            print(f"\n  {surface.filename}")
            print(f"  SHA256: {surface.sha256}")
            print(f"  Method: {surface.method}")
            if surface.dispatcher_rva:
                print(f"  Dispatcher RVA: {surface.dispatcher_rva:#x}")
            print(f"  IOCTLs found: {len(surface.ioctls)}")

            if surface.errors:
                for e in surface.errors:
                    print(f"  ERROR: {e}")

            if surface.ioctls:
                print(f"\n  {'Code':<14} {'DevType':<24} {'Fn':>4} "
                      f"{'Method':<18} {'Access':<28} Imports")
                print(f"  {'-'*14} {'-'*24} {'-'*4} {'-'*18} {'-'*28} {'-'*30}")

                for entry in surface.ioctls:
                    c = entry.ctl
                    imports = ", ".join(entry.handler_imports[:4]) if entry.handler_imports else ""
                    if len(entry.handler_imports) > 4:
                        imports += f" +{len(entry.handler_imports) - 4}"
                    print(f"  {entry.code:#010x}   {c.device_type_name:<24} "
                          f"{c.function:>4} {c.method_name:<18} {c.access_name:<28} {imports}")

    return 0


def cmd_harvest(args):
    from .harvester import harvest

    summary = harvest(
        output_dir=args.output,
        categories=args.category.split(",") if args.category else None,
    )

    if args.scan:
        from .scanner import scan_directory
        drivers_dir = summary.get("output_dir")
        if drivers_dir and Path(drivers_dir).exists():
            print(f"\n  Scanning extracted drivers...", file=sys.stderr)
            results = scan_directory(drivers_dir)
            flagged = [r for r in results if r.flagged_imports]
            print(f"  {len(flagged)} / {len(results)} drivers have red-flag imports")

    return 0


def cmd_regional(args):
    from .regional import search_regional

    regions = args.region.split(",") if args.region else None
    results = search_regional(regions=regions)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for region, entries in results.items():
            if not entries:
                continue
            print(f"\n{'='*80}")
            print(f"  Region: {region} ({len(entries)} drivers)")
            print(f"{'='*80}")
            for e in entries[:30]:
                classes = ", ".join(e["primitive_classes"]) or "none"
                hvci = " [HVCI-OK]" if e["hvci_bypass"] else ""
                print(f"  {e['filename']:<30} {classes}{hvci}")
                if e["publisher"]:
                    print(f"    Publisher: {e['publisher']}")
                print(f"    Keywords: {', '.join(e['matched_keywords'][:5])}")

    return 0


def cmd_wdm(args):
    from .wdm_filter import scan_for_wdm_physmem

    results = scan_for_wdm_physmem(
        paths=args.path if isinstance(args.path, list) else [args.path],
        recursive=not args.no_recursive,
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n  WDM PhysMem Drivers: {len(results)} found\n")
        for r in results:
            print(f"  {r['filename']:<30} score={r['score']}")
            print(f"    Dangerous: {', '.join(r['dangerous_imports'])}")
            if r['bonus_imports']:
                print(f"    Bonus: {', '.join(r['bonus_imports'])}")
            if r['device_names']:
                print(f"    Devices: {', '.join(r['device_names'][:3])}")

    return 0


def cmd_bulk(args):
    from .bulk_scrape import bulk_scrape, list_vendors, HAS_PLAYWRIGHT

    if args.list:
        targets = list_vendors()
        print(f"\n  {len(targets)} vendor targets:\n")
        print(f"  {'Name':<22} {'Category':<14} {'Region':<8} Notes")
        print(f"  {'-'*22} {'-'*14} {'-'*8} {'-'*40}")
        for t in targets:
            print(f"  {t.name:<22} {t.category:<14} {t.region:<8} {t.notes}")
        return 0

    if not HAS_PLAYWRIGHT:
        print("Error: pip install driverscope[bulk]  (playwright + httpx)",
              file=sys.stderr)
        print("Then: playwright install chromium", file=sys.stderr)
        return 1

    vendors = args.vendors.split(",") if args.vendors else None
    print(f"  Scraping vendor portals into {args.output}/", file=sys.stderr)
    results = bulk_scrape(
        vendors=vendors,
        category=args.category,
        region=args.region,
        output_dir=args.output,
        max_pages_per_vendor=args.max_pages,
        concurrency=args.concurrency,
    )

    total_dl = sum(len(r.saved_files) for r in results)
    total_urls = sum(len(r.download_urls) for r in results)
    total_errs = sum(len(r.errors) for r in results)
    print(f"\n  {len(results)} vendors scraped")
    print(f"  {total_urls} download URLs found")
    print(f"  {total_dl} files saved")
    if total_errs:
        print(f"  {total_errs} errors (see per-vendor reports)")

    print(f"\n  Per-vendor breakdown:")
    for r in results:
        print(f"    {r.vendor:<22}  urls={len(r.download_urls):>4}  "
              f"saved={len(r.saved_files):>4}  errs={len(r.errors)}")

    if args.scan:
        from .scanner import scan_directory
        print(f"\n  Scanning harvested .sys files...", file=sys.stderr)
        scan_results = scan_directory(args.output, recursive=True)
        flagged = [s for s in scan_results if s.flagged_imports]
        print(f"  {len(flagged)} / {len(scan_results)} flagged "
              f"({len(flagged) * 100 // max(1, len(scan_results))}%)")

    return 0


def cmd_emulate(args):
    from .emulate import emulate_batch, format_table, HAS_SPEAKEASY
    from dataclasses import asdict

    if not HAS_SPEAKEASY:
        print("Error: pip install driverscope[emulate]  (speakeasy-emulator)",
              file=sys.stderr)
        return 1

    paths = args.path if isinstance(args.path, list) else [args.path]
    print(f"  Emulating drivers via Speakeasy...", file=sys.stderr)
    results = emulate_batch(paths, recursive=not args.no_recursive)

    if not results:
        print("No .sys files found.")
        return 0

    if args.json:
        out = json.dumps([asdict(r) for r in results], indent=2)
        print(out)
        if args.export:
            Path(args.export).write_text(out)
            print(f"\n  Exported to {args.export}", file=sys.stderr)
    else:
        print(format_table(results))
        if args.export:
            out = json.dumps([asdict(r) for r in results], indent=2)
            Path(args.export).write_text(out)
            print(f"\n  Exported to {args.export}", file=sys.stderr)

    return 0


def cmd_triage(args):
    from .triage import (
        triage_findings, load_findings, format_report, HAS_ANTHROPIC
    )
    from dataclasses import asdict

    if not HAS_ANTHROPIC:
        print("Error: pip install driverscope[triage]  (anthropic)",
              file=sys.stderr)
        return 1

    findings = load_findings(args.findings)
    if not findings:
        print("No findings to triage.", file=sys.stderr)
        return 1

    print(f"  Triaging {len(findings)} findings via {args.model}...",
          file=sys.stderr)
    results = triage_findings(
        findings,
        api_key=args.api_key,
        model=args.model,
        concurrency=args.concurrency,
        max_tokens=args.max_tokens,
    )

    if args.json:
        out = json.dumps([asdict(r) for r in results], indent=2)
    else:
        out = format_report(results)

    if args.output:
        Path(args.output).write_text(out)
        print(f"  Report written to {args.output}", file=sys.stderr)
    else:
        print(out)

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="driverscope",
        description="DriverScope: Automated BYOVD hunting pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Pipeline stages:
  scan       Scan .sys files for dangerous kernel imports
  hunt       Zero-day hunter: find novel vulnerable drivers
  ioctl      Extract IOCTL dispatch surface from a driver
  emulate    Speakeasy emulation: trace DriverEntry, extract device names,
             PDB paths, debug strings, and primitive classifications
  harvest    Download OEM tools and extract kernel drivers
  regional   Search LOLDrivers by regional vendor (CN/KR/JP/TW/RU)
  wdm        Filter for WDM drivers with physmem primitives
  bulk       Bulk-scrape vendor portals via Playwright
  triage     Bulk Claude API triage of scan/ioctl findings

Examples:
  driverscope scan C:\\drivers --ioctl --json --export findings.json
  driverscope hunt --deep --export hits.json      Full system zero-day scan
  driverscope ioctl driver.sys                    Extract IOCTLs (single file)
  driverscope emulate driver.sys                  Trace DriverEntry via Speakeasy
  driverscope emulate C:\\drivers --json           Batch emulate a directory
  driverscope harvest ./output --scan             Download + scan OEM drivers
  driverscope regional --region CN,KR             Regional vendor search
  driverscope bulk --list                         List vendor portals
  driverscope bulk --vendors MSI-Support,ASRock-Support --scan
  driverscope triage findings.json --output triage.md
""",
    )
    sub = parser.add_subparsers(dest="command", help="Pipeline stage")

    # -- scan --
    p_scan = sub.add_parser("scan", help="Scan .sys files for dangerous imports")
    p_scan.add_argument("path", help="File or directory to scan")
    p_scan.add_argument("--no-recursive", action="store_true",
                        help="Don't recurse into subdirectories")
    p_scan.add_argument("--lol", action="store_true",
                        help="Cross-reference with LOLDrivers.io")
    p_scan.add_argument("--blocklist", action="store_true",
                        help="Cross-reference with MS Vulnerable Driver Blocklist")
    p_scan.add_argument("--vt", action="store_true",
                        help="Look up hashes on VirusTotal")
    p_scan.add_argument("--vt-key", help="VirusTotal API key")
    p_scan.add_argument("--ioctl", action="store_true",
                        help="Also extract IOCTLs from flagged drivers")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--export", help="Export results to JSON file")
    p_scan.add_argument("--all", action="store_true",
                        help="Include clean drivers in output")

    # -- hunt --
    p_hunt = sub.add_parser("hunt", help="Zero-day hunting pipeline")
    p_hunt.add_argument("--scan-path", nargs="*",
                        help="Paths to scan (default: System32\\drivers)")
    p_hunt.add_argument("--extra-path", nargs="*",
                        help="Additional paths to include")
    p_hunt.add_argument("--deep", action="store_true",
                        help="Include DriverStore + Program Files (slower)")
    p_hunt.add_argument("--min-score", type=int, default=0,
                        help="Minimum novelty score to report")
    p_hunt.add_argument("--json", action="store_true", help="JSON output")
    p_hunt.add_argument("--export", help="Export results to file")

    # -- ioctl --
    p_ioctl = sub.add_parser("ioctl", help="Extract IOCTL dispatch surface")
    p_ioctl.add_argument("path", help=".sys file or directory to analyze")
    p_ioctl.add_argument("--no-recursive", action="store_true",
                         help="Don't recurse into subdirectories")
    p_ioctl.add_argument("--hits-only", action="store_true",
                         help="Only show drivers that have IOCTLs")
    p_ioctl.add_argument("--json", action="store_true", help="JSON output")
    p_ioctl.add_argument("--export", help="Export results to JSON file")

    # -- harvest --
    p_harvest = sub.add_parser("harvest",
                               help="Download OEM tools and extract drivers")
    p_harvest.add_argument("--output", default="./harvested",
                           help="Output directory (default: ./harvested)")
    p_harvest.add_argument("--category",
                           help="Filter by category (comma-separated)")
    p_harvest.add_argument("--scan", action="store_true",
                           help="Scan extracted drivers after harvest")

    # -- regional --
    p_regional = sub.add_parser("regional",
                                help="Search LOLDrivers by regional vendor")
    p_regional.add_argument("--region",
                            help="Region codes (default: all). "
                                 "Options: CN,KR,JP,TW,RU")
    p_regional.add_argument("--json", action="store_true", help="JSON output")

    # -- wdm --
    p_wdm = sub.add_parser("wdm", help="Filter for WDM physmem drivers")
    p_wdm.add_argument("path", nargs="+", help="Paths to scan")
    p_wdm.add_argument("--no-recursive", action="store_true")
    p_wdm.add_argument("--json", action="store_true", help="JSON output")

    # -- bulk --
    p_bulk = sub.add_parser("bulk",
                            help="Bulk-scrape vendor portals via Playwright")
    p_bulk.add_argument("--output", default="./bulk_harvest",
                        help="Output directory")
    p_bulk.add_argument("--vendors",
                        help="Comma-separated vendor names (default: all). "
                             "Use --list to see available")
    p_bulk.add_argument("--category",
                        help="Filter by category (motherboard,chipset,audio,...)")
    p_bulk.add_argument("--region", help="Filter by region")
    p_bulk.add_argument("--max-pages", type=int, default=5,
                        help="Max pages per vendor (default: 5)")
    p_bulk.add_argument("--concurrency", type=int, default=4)
    p_bulk.add_argument("--list", action="store_true",
                        help="List available vendor targets and exit")
    p_bulk.add_argument("--scan", action="store_true",
                        help="Scan harvested .sys files after download")

    # -- emulate --
    p_emu = sub.add_parser("emulate",
                           help="Speakeasy emulation: trace DriverEntry, "
                                "extract device names, PDB, debug strings")
    p_emu.add_argument("path", nargs="+", help=".sys file(s) or directory")
    p_emu.add_argument("--no-recursive", action="store_true",
                       help="Don't recurse into subdirectories")
    p_emu.add_argument("--json", action="store_true", help="JSON output")
    p_emu.add_argument("--export", help="Export results to JSON file")

    # -- triage --
    p_triage = sub.add_parser("triage",
                              help="Bulk Claude API triage of scan/ioctl findings")
    p_triage.add_argument("findings", help="JSON file from scan/ioctl --json")
    p_triage.add_argument("--api-key",
                          help="Anthropic API key (or ANTHROPIC_API_KEY env)")
    p_triage.add_argument("--model", default="claude-opus-4-6",
                          help="Claude model (default: claude-opus-4-6)")
    p_triage.add_argument("--concurrency", type=int, default=4)
    p_triage.add_argument("--max-tokens", type=int, default=1024)
    p_triage.add_argument("--output", help="Write Markdown report to file")
    p_triage.add_argument("--json", action="store_true",
                          help="JSON output instead of Markdown")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "scan": cmd_scan,
        "hunt": cmd_hunt,
        "ioctl": cmd_ioctl,
        "harvest": cmd_harvest,
        "regional": cmd_regional,
        "wdm": cmd_wdm,
        "bulk": cmd_bulk,
        "triage": cmd_triage,
        "emulate": cmd_emulate,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
