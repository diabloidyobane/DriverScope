"""DriverScope CLI — unified entry point for all pipeline stages."""

import argparse
import json
import os
import sys
from pathlib import Path


def cmd_scan(args):
    """Scan .sys files for dangerous kernel imports."""
    from .scanner import (
        scan_driver, scan_directory, build_lol_index, enrich_with_lol,
        fetch_ms_blocklist, enrich_with_blocklist, vt_cache_init,
        vt_lookup_hash, vt_cache_save, VTQuotaExhausted,
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

    # Optional enrichment
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

    # Output
    if args.json:
        from dataclasses import asdict
        out = [asdict(r) for r in results if r.flagged_imports or args.all]
        print(json.dumps(out, indent=2))
    else:
        flagged = [r for r in results if r.flagged_imports]
        clean = len(results) - len(flagged)

        print(f"\n{'='*100}")
        print(f"  SCAN RESULTS — {len(flagged)} flagged / {len(results)} total "
              f"({clean} clean)")
        print(f"{'='*100}\n")

        if not flagged:
            print("  No drivers with red-flag imports found.")
            return 0

        print(f"  {'#':<4} {'Driver':<30} {'Score':>5} {'Arch':<5} "
              f"{'Signed':<6} {'LOL':<4} {'BL':<3} Primitive Classes")
        print(f"  {'-'*4} {'-'*30} {'-'*5} {'-'*5} {'-'*6} {'-'*4} "
              f"{'-'*3} {'-'*40}")

        for i, r in enumerate(flagged, 1):
            name = r.filename[:29] if len(r.filename) <= 29 else r.filename[:26] + "..."
            arch = "x64" if r.is_64bit else "x86"
            signed = "YES" if r.is_signed else "no"
            lol = "YES" if r.lol_known else ""
            bl = "BL" if r.ms_blocked else ""
            classes = ", ".join(r.primitive_classes)
            print(f"  {i:<4} {name:<30} {r.score:>5} {arch:<5} "
                  f"{signed:<6} {lol:<4} {bl:<3} {classes}")

        # Detail for top 20
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
                print(f"    [LOLDrivers] {r.lol_id} — {r.lol_category}")
                if r.lol_cves:
                    print(f"    CVEs: {', '.join(r.lol_cves)}")
            if r.ms_blocked:
                print(f"    [MS BLOCKED]")
            for cls in r.primitive_classes:
                from .scanner import PRIMITIVE_CLASSES
                syms = [s for s in r.flagged_imports
                        if s in PRIMITIVE_CLASSES.get(cls, [])]
                if syms:
                    print(f"    [{cls}] {', '.join(syms)}")

    return 0


def cmd_hunt(args):
    """Run the zero-day hunting pipeline."""
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
    """Extract IOCTL dispatch surface from a driver."""
    from .ioctl import extract_ioctl_surface

    surface = extract_ioctl_surface(args.path)

    if args.json:
        out = {
            "filename": surface.filename,
            "sha256": surface.sha256,
            "method": surface.method,
            "dispatcher_rva": hex(surface.dispatcher_rva) if surface.dispatcher_rva else None,
            "ioctl_count": len(surface.ioctls),
            "ioctls": [],
            "errors": surface.errors,
        }
        for entry in surface.ioctls:
            out["ioctls"].append({
                "code": hex(entry.code),
                "device_type": entry.ctl.device_type_name,
                "function": entry.ctl.function,
                "method": entry.ctl.method_name,
                "access": entry.ctl.access_name,
                "handler_rva": hex(entry.handler_rva),
            })
        print(json.dumps(out, indent=2))
    else:
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
                  f"{'Method':<18} {'Access'}")
            print(f"  {'-'*14} {'-'*24} {'-'*4} {'-'*18} {'-'*30}")

            for entry in surface.ioctls:
                c = entry.ctl
                print(f"  {entry.code:#010x}   {c.device_type_name:<24} "
                      f"{c.function:>4} {c.method_name:<18} {c.access_name}")

    return 0


def cmd_harvest(args):
    """Download OEM tools and extract kernel drivers."""
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
    """Search LOLDrivers by regional vendor."""
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
            print(f"  Region: {region} — {len(entries)} drivers")
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
    """Filter for WDM drivers with physmem primitives."""
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


def main():
    parser = argparse.ArgumentParser(
        prog="driverscope",
        description="DriverScope — Automated BYOVD hunting pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Pipeline stages:
  scan       Scan .sys files for dangerous kernel imports
  hunt       Zero-day hunter — find novel vulnerable drivers
  ioctl      Extract IOCTL dispatch surface from a driver
  harvest    Download OEM tools and extract kernel drivers
  regional   Search LOLDrivers by regional vendor (CN/KR/JP/TW/RU)
  wdm        Filter for WDM drivers with physmem primitives

Examples:
  driverscope scan C:\\drivers                    Scan a directory
  driverscope scan driver.sys --lol --blocklist  Scan with cross-ref
  driverscope hunt --deep                        Full system zero-day scan
  driverscope ioctl driver.sys                   Extract IOCTLs
  driverscope harvest ./output --scan            Download + scan OEM drivers
  driverscope regional --region CN,KR            Regional vendor search
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
    p_scan.add_argument("--json", action="store_true", help="JSON output")
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
    p_ioctl.add_argument("path", help=".sys file to analyze")
    p_ioctl.add_argument("--json", action="store_true", help="JSON output")

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
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
