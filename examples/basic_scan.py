from driverscope.scanner import scan_directory, build_lol_index, enrich_with_lol

if __name__ == "__main__":
    results = scan_directory(r"C:\Windows\System32\drivers", recursive=False)
    flagged = [r for r in results if r.flagged_imports]

    lol_index = build_lol_index()
    enrich_with_lol(flagged, lol_index)

    for r in flagged[:10]:
        lol_tag = " [LOLDrivers]" if r.lol_known else ""
        print(f"{r.filename:<30} score={r.score}  classes={r.primitive_classes}{lol_tag}")
