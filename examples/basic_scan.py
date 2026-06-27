"""Example: scan a directory and print results as JSON."""

from driverscope.scanner import scan_directory, build_lol_index, enrich_with_lol

results = scan_directory(r"C:\Windows\System32\drivers", recursive=False)

# Filter to only flagged drivers
flagged = [r for r in results if r.flagged_imports]

# Optional: cross-reference with LOLDrivers
lol_index = build_lol_index()
enrich_with_lol(flagged, lol_index)

for r in flagged[:10]:
    lol_tag = " [LOLDrivers]" if r.lol_known else ""
    print(f"{r.filename:<30} score={r.score}  classes={r.primitive_classes}{lol_tag}")
