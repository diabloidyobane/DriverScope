"""End-to-end DriverScope pipeline.

Runs the full novelty-hunting loop:

    harvest         (optional, sourcing pass)
        winget catalog walk
        MalwareBazaar + MalShare .sys pivots
        Wayback vendor snapshots
        OEM/RGB/storage/BMC/CN/VPN vendor sources
    scan            (driverscope.scanner against the expanded corpus)
    hvci-simulate   (offline WDAC verdict per candidate)
    cluster         (TLSH fuzzy-hash clustering vs LOLDrivers-known hashes)
    diff            (against the previous run stored in the SQLite DB)
    dossier         (markdown + HTML from scanner hunt functions)
    persist         (append everything to driverscope.db)

Each stage is opt-in. Default: --scan --cluster --dossier (safe, no
network sourcing).
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional


HERE = Path(__file__).resolve().parent


def _log(msg: str) -> None:
    print(f"[pipeline] {msg}", flush=True)


def run(args) -> int:
    from driverscope import db as ds_db
    from driverscope import corpus as ds_corpus
    from driverscope import diff as ds_diff
    from driverscope import hvci as ds_hvci
    from driverscope import tlsh_cluster as ds_tlsh
    from driverscope import html_dossier as ds_html

    out_dir = Path(args.out or (HERE.parent / "pipeline_out"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())

    # -- 1. Optional sourcing -----------------------------------------------
    if args.winget:
        _log("winget catalog walk starting")
        from driverscope import winget_walk as ds_winget
        ds_winget.harvest(out_dir=out_dir / "winget")
    if args.bazaar:
        _log("MalwareBazaar / MalShare sourcing")
        from driverscope import bazaar as ds_bazaar
        ds_bazaar.harvest(out_dir=out_dir / "bazaar")
    if args.wayback:
        _log("Wayback snapshot enumeration")
        from driverscope import wayback as ds_wayback
        patterns = args.wayback_url or []
        if not patterns:
            _log("  no --wayback-url passed, skipping")
        else:
            ds_wayback.harvest(patterns, out_dir=out_dir / "wayback",
                               fetch=True, fetch_max=args.wayback_max)
    if args.harvest:
        _log("harvesting vendor sources")
        from driverscope.harvester import harvest as _harvest
        _harvest(str(out_dir / "harvest"), extra=True)

    # -- 2. Build the corpus we'll scan ------------------------------------
    _log("building corpus")
    extra_roots = list(args.extra_root or [])
    if args.include_pipeline_out:
        extra_roots.append(str(out_dir))
    corpus = ds_corpus.build(
        include_system=not args.no_system,
        include_program_files=not args.no_program_files,
        include_wu_staged=not args.no_wu_staged,
        include_programdata=args.programdata,
        include_localappdata=args.localappdata,
        extra_roots=extra_roots,
        exclude_default=not args.include_common,
        dedup_by_name=args.dedup_by_name,
    )
    _log(ds_corpus.cli_summary(corpus).splitlines()[0])

    # -- 3. Scan ---------------------------------------------------------------
    _log("scanning")
    from driverscope import scanner
    results = [scanner.scan_driver(str(p)) for p in corpus.files]

    if args.enrich:
        blocklist = scanner.fetch_ms_blocklist()
        scanner.enrich_with_blocklist(results, blocklist)
        lol_index = scanner.build_lol_index()
        scanner.enrich_with_lol(results, lol_index)

    # -- 4. HVCI dry-run ---------------------------------------------------
    if args.hvci_simulate:
        _log("HVCI simulate")
        policies = ds_hvci.default_policies()
        for r in results:
            if not r.primitive_classes:
                continue
            v = ds_hvci.evaluate(r.sha256, driver_path=r.path,
                                  signer=r.signer, policies=policies)
            if v.blocked and not r.ms_blocked:
                r.ms_blocked = True
                r.ms_blocked_name = f"[hvci-sim] {v.reason} {v.matched}"

    # -- 5. Persist / diff --------------------------------------------------
    db = ds_db.open_db(args.db)
    scan_id = db.new_scan(
        target_path=str(args.target or corpus.roots[0] if corpus.roots else "<local>"),
        host=socket.gethostname(),
        corpus_size=len(corpus.files),
        cli_args=" ".join(sys.argv),
    )
    db.record_batch(scan_id, results)
    hits = sum(1 for r in results if r.primitive_classes)
    ms_blocked = sum(1 for r in results if getattr(r, "ms_blocked", False))
    db.finalize_scan(scan_id, len(corpus.files), hits, ms_blocked)
    _log(f"stored scan_id={scan_id}  corpus={len(corpus.files)}  hits={hits}  ms_blocked={ms_blocked}")

    diff_result = None
    if args.diff:
        prev_scan_id = None
        if args.diff_scan_id:
            prev_scan_id = int(args.diff_scan_id)
        else:
            ids = [r["id"] for r in db.scan_ids(limit=5)]
            for i in ids:
                if i != scan_id:
                    prev_scan_id = i
                    break
        if prev_scan_id is None:
            _log("diff: no prior scan in DB")
        else:
            prev = ds_diff.load_sqlite(db.path, scan_id=prev_scan_id)
            curr = ds_diff.load_iter(results)
            diff_result = ds_diff.diff(prev, curr)
            _log(f"diff vs scan_id={prev_scan_id}: "
                 + " ".join(f"{k}={v}" for k, v in sorted(diff_result.summary.items())))
            (out_dir / f"diff_{stamp}.txt").write_text(
                ds_diff.render_text(diff_result), encoding="utf-8"
            )

    # -- 6. Cluster --------------------------------------------------------
    if args.cluster:
        _log("TLSH clustering")
        members = ds_tlsh.compute_members(str(p) for p in corpus.files)
        ds_tlsh.enrich_members(members, results)
        clusters = ds_tlsh.cluster(members, threshold=args.tlsh_threshold)
        # persist cluster memberships
        for c in clusters:
            for m in c.members:
                db.record_cluster(c.id, m.sha256, m.digest)
        # highlight LOL-known hashes
        lol_hashes: set[str] = set()
        try:
            lol_index = scanner.build_lol_index()
            lol_hashes = set(lol_index.keys())
        except Exception:
            pass
        cluster_txt = ds_tlsh.render_text(clusters, min_size=2, lol_hashes=lol_hashes)
        (out_dir / f"clusters_{stamp}.txt").write_text(cluster_txt, encoding="utf-8")
        _log(f"wrote clusters_{stamp}.txt ({len(clusters)} clusters)")

    # -- 7. Dossiers -------------------------------------------------------
    if args.dossier:
        _log("writing hunt dossier (markdown + HTML)")
        ranked = scanner.hunt_rank(results)
        md = scanner.hunt_dossier_markdown(
            results, ranked,
            str(args.target or "<local>"), top_n=args.top,
        )
        md_path = out_dir / f"hunt_{stamp}.md"
        md_path.write_text(md, encoding="utf-8")

        extract = None
        try:
            from driverscope.ioctl import extract_ioctl_surface as _ext
            extract = _ext
        except Exception:
            pass
        html_text = ds_html.render(
            results, ranked, str(args.target or "<local>"),
            top_n=args.top, extract_ioctl=extract,
            diff_result=diff_result,
        )
        html_path = out_dir / f"hunt_{stamp}.html"
        ds_html.write(html_path, html_text)
        _log(f"markdown: {md_path}")
        _log(f"html:     {html_path}")

    db.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="DriverScope pipeline orchestrator")

    ap.add_argument("--out", type=str, default=None,
                    help="Output directory (default: tools/pipeline_out)")
    ap.add_argument("--db", type=str, default=None,
                    help="SQLite DB path (default: tools/driverscope.db)")
    ap.add_argument("--target", type=str, default=None,
                    help="Human-readable label for the scan target")
    ap.add_argument("--top", type=int, default=5,
                    help="Top N picks in the dossier")

    # sourcing
    src = ap.add_argument_group("sourcing")
    src.add_argument("--harvest", action="store_true",
                     help="Run vendor source harvesting")
    src.add_argument("--winget", action="store_true",
                     help="Run winget catalog walk")
    src.add_argument("--bazaar", action="store_true",
                     help="Run MalwareBazaar + MalShare .sys pivots")
    src.add_argument("--wayback", action="store_true",
                     help="Run Wayback Machine snapshot enumeration")
    src.add_argument("--wayback-url", action="append", default=[],
                     help="URL pattern for Wayback (may end in *). Repeat.")
    src.add_argument("--wayback-max", type=int, default=40)

    # corpus
    corp = ap.add_argument_group("corpus")
    corp.add_argument("--no-system", action="store_true")
    corp.add_argument("--no-program-files", action="store_true")
    corp.add_argument("--no-wu-staged", action="store_true")
    corp.add_argument("--programdata", action="store_true")
    corp.add_argument("--localappdata", action="store_true")
    corp.add_argument("--extra-root", action="append", default=[],
                      help="Extra directory to include in the scan. Repeat.")
    corp.add_argument("--include-pipeline-out", action="store_true",
                      help="Include this run's pipeline_out/ in the corpus")
    corp.add_argument("--include-common", action="store_true",
                      help="Do not exclude common OS drivers")
    corp.add_argument("--dedup-by-name", action="store_true")

    # scan behavior
    scan = ap.add_argument_group("scan")
    scan.add_argument("--enrich", action="store_true", default=True,
                      help="Enrich with LOLDrivers + MS blocklist (default on)")

    # analysis
    ana = ap.add_argument_group("analysis")
    ana.add_argument("--cluster", action="store_true",
                     help="Run TLSH clustering (default off)")
    ana.add_argument("--tlsh-threshold", type=int, default=60)
    ana.add_argument("--hvci-simulate", action="store_true",
                     help="Offline WDAC/HVCI verdict per candidate")
    ana.add_argument("--diff", action="store_true",
                     help="Diff against the previous scan in the DB")
    ana.add_argument("--diff-scan-id", type=str, default=None,
                     help="Explicit prior scan id (default: previous)")
    ana.add_argument("--dossier", action="store_true", default=True,
                     help="Write markdown + HTML dossier (default on)")

    # convenience: --all turns everything on
    ap.add_argument("--all", action="store_true",
                    help="Enable all optional stages "
                         "(harvest, winget, bazaar, cluster, hvci-simulate, diff)")

    args = ap.parse_args()

    if args.all:
        args.harvest = args.winget = args.bazaar = True
        args.cluster = args.hvci_simulate = args.diff = True

    return run(args)


if __name__ == "__main__":
    sys.exit(main())
