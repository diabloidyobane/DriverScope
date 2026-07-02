"""HTML dossier for a DriverScope hunt run.

Standalone (no jinja2 dependency). Takes the same inputs the markdown
dossier does: the DriverResult list, the ranked (result, score) pairs,
and the target path.

Sections:
  Top picks           IOCTL surface, links to VT, LOLDrivers.io, MSRC search
  Runners-up          compact scored table
  Corpus breakdown    counts by signer and by primitive class
  Diff (optional)     added / removed / changed drivers since a previous run
"""
from __future__ import annotations

import datetime
import html
import json
from dataclasses import is_dataclass, asdict
from pathlib import Path
from typing import Any, Iterable, Optional


CSS = """
* { box-sizing: border-box; }
body {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: #101216; color: #cfd6df;
  margin: 0; padding: 24px;
  line-height: 1.45;
}
h1, h2, h3 { color: #f0f4f9; margin-top: 1.6em; }
h1 { font-size: 20px; letter-spacing: 0.4px; }
h2 { font-size: 16px; border-bottom: 1px solid #2a3038; padding-bottom: 4px; }
h3 { font-size: 14px; color: #ffd170; }
a { color: #7fb3ff; text-decoration: none; border-bottom: 1px dotted #35496b; }
a:hover { color: #cfe0ff; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12px; }
th, td { padding: 4px 8px; text-align: left; border-bottom: 1px solid #22262d; }
th { color: #a6afba; font-weight: normal; text-transform: uppercase; letter-spacing: 0.6px; }
tr:hover td { background: #171b21; }
code { color: #ffcf7a; background: #191d24; padding: 1px 4px; border-radius: 3px; }
.pill { display: inline-block; padding: 1px 6px; border-radius: 10px;
        font-size: 11px; margin-left: 4px; }
.pill.hvci  { background: #382c00; color: #ffcf7a; }
.pill.msbl  { background: #3a1416; color: #ff8a90; }
.pill.lol   { background: #172a3a; color: #7fb3ff; }
.pill.novel { background: #1c332a; color: #9bf0c2; }
.pill.chg   { background: #2c1a3b; color: #d8a9ff; }
.small { font-size: 11px; color: #7d8794; }
.detail { margin: 8px 0 20px 0; padding: 10px 14px; background: #14181e; border-left: 3px solid #2a3040; }
.hit  { color: #9bf0c2; }
.bad  { color: #ff8a90; }
.warn { color: #ffcf7a; }
pre { background: #14181e; padding: 8px 12px; border-radius: 4px; overflow-x: auto; }
"""


def _esc(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _vt_link(sha: str) -> str:
    return f"https://www.virustotal.com/gui/file/{sha}/detection"


def _lol_link(lol_id: str) -> str:
    if not lol_id:
        return ""
    return f"https://www.loldrivers.io/drivers/{lol_id}/"


def _msrc_search_link(term: str) -> str:
    return f"https://msrc.microsoft.com/update-guide/en-US?search={_esc(term)}"


def _google_cve(term: str) -> str:
    return f"https://www.google.com/search?q=cve+%22{_esc(term)}%22"


def _tag(kind: str, label: str) -> str:
    return f'<span class="pill {kind}">{_esc(label)}</span>'


def _row_pills(r: Any) -> str:
    parts: list[str] = []
    if getattr(r, "ms_blocked", False):
        parts.append(_tag("msbl", "MS-BLOCKED"))
    if getattr(r, "lol_hvci_bypass", False):
        parts.append(_tag("hvci", "HVCI-BYPASS"))
    if getattr(r, "lol_known", False) and not getattr(r, "lol_hvci_bypass", False):
        parts.append(_tag("lol", "LOL"))
    if not getattr(r, "lol_known", False):
        parts.append(_tag("novel", "novel-to-LOL"))
    return " ".join(parts)


def _ioctl_block(surface: Any) -> str:
    """Given an IOCTLSurface (from driverscope.ioctl) render top codes."""
    if surface is None:
        return ""
    codes = getattr(surface, "ioctls", None) or []
    if not codes:
        return ""
    total = len(codes)
    method_neither = sum(1 for c in codes if getattr(c, "method", None) == 3)
    any_access = sum(1 for c in codes if getattr(c, "access", None) == 0)
    disp = f"0x{getattr(surface, 'dispatcher_rva', 0):x}"
    parts = [
        f"<p class='small'>IOCTL surface: <b>{total}</b> codes  "
        f"(METHOD_NEITHER: <b class='warn'>{method_neither}</b>, "
        f"FILE_ANY_ACCESS: <b class='warn'>{any_access}</b>)  "
        f"dispatcher at <code>{disp}</code></p>"
    ]
    interesting = [c for c in codes
                   if getattr(c, "primitive_classes", None) or getattr(c, "danger_flags", None)]
    if interesting:
        parts.append("<table>")
        parts.append("<tr><th>code</th><th>method</th><th>access</th><th>flags</th><th>classes</th></tr>")
        for c in interesting[:20]:
            parts.append(
                "<tr>"
                f"<td><code>{_esc(getattr(c, 'code', ''))}</code></td>"
                f"<td>{_esc(getattr(c, 'method_name', ''))}</td>"
                f"<td>{_esc(getattr(c, 'access_name', ''))}</td>"
                f"<td class='warn'>{_esc(','.join(getattr(c, 'danger_flags', []) or []))}</td>"
                f"<td class='hit'>{_esc(','.join(getattr(c, 'primitive_classes', []) or []))}</td>"
                "</tr>"
            )
        parts.append("</table>")
    return "\n".join(parts)


def render(results: list[Any],
           ranked: list[tuple[Any, int]],
           target_path: str,
           top_n: int = 5,
           extract_ioctl=None,
           diff_result: Any = None) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    ms_blocked = sum(1 for r in results if getattr(r, "ms_blocked", False))
    flagged = [r for r in results if getattr(r, "primitive_classes", None)]

    parts: list[str] = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>DriverScope — {_esc(Path(target_path).name)}</title>",
        f"<style>{CSS}</style>",
        "</head><body>",
        f"<h1>DriverScope hunt dossier</h1>",
        f"<p class='small'>Target: <code>{_esc(target_path)}</code> · Generated: {_esc(now)}</p>",
        f"<p>Corpus: <b>{len(results)}</b> files scanned, "
        f"<b class='hit'>{len(flagged)}</b> flagged, "
        f"<b class='bad'>{ms_blocked}</b> MS-blocked.</p>",
    ]

    # -- top picks -----------------------------------------------------------
    parts.append("<h2>Top picks</h2>")
    if not ranked:
        parts.append("<p class='bad'>No viable candidates.</p>")
    else:
        for i, (r, score) in enumerate(ranked[:top_n], 1):
            sha = getattr(r, "sha256", "") or ""
            filename = getattr(r, "filename", "") or Path(getattr(r, "path", "")).name
            signer = getattr(r, "signer", "") or ""
            size = getattr(r, "size_bytes", 0) or 0
            classes = getattr(r, "primitive_classes", []) or []
            imports = getattr(r, "matched_imports", []) or []
            parts.append(f"<h3>#{i} — {_esc(filename)}  (score {score})  {_row_pills(r)}</h3>")
            parts.append("<div class='detail'>")
            parts.append("<table>")
            parts.append(f"<tr><th>sha256</th><td><a href='{_vt_link(sha)}'><code>{_esc(sha)}</code></a></td></tr>")
            parts.append(f"<tr><th>path</th><td><code>{_esc(getattr(r, 'path', ''))}</code></td></tr>")
            parts.append(f"<tr><th>size</th><td>{size/1024:.0f} KB</td></tr>")
            parts.append(f"<tr><th>machine</th><td>{_esc(getattr(r, 'machine', ''))}</td></tr>")
            parts.append(f"<tr><th>signed</th><td>{'yes' if getattr(r, 'signed', False) else 'NO'}</td></tr>")
            if signer and signer not in ("(signed)", "(no authenticode)"):
                parts.append(f"<tr><th>signer</th><td>{_esc(signer)}  "
                             f"<a class='small' href='{_msrc_search_link(signer)}'>[MSRC search]</a></td></tr>")
            parts.append(f"<tr><th>primitives</th><td class='hit'>{_esc(', '.join(classes))}</td></tr>")
            parts.append(f"<tr><th>matched imports</th><td>{_esc(', '.join(imports))}</td></tr>")

            if getattr(r, "lol_known", False):
                lol_id = getattr(r, "lol_id", "")
                cves = list(getattr(r, "lol_cves", []) or [])
                link = _lol_link(lol_id)
                cve_links = " ".join(f"<a href='{_google_cve(c)}'>{_esc(c)}</a>" for c in cves[:5])
                parts.append(f"<tr><th>LOLDrivers</th>"
                             f"<td><a href='{link}'>{_esc(lol_id)}</a> — {cve_links}</td></tr>")

            vt = getattr(r, "vt", None)
            if vt is not None and getattr(vt, "total_engines", 0):
                parts.append(f"<tr><th>VirusTotal</th>"
                             f"<td>{vt.detections}/{vt.total_engines} detections, "
                             f"reputation {vt.reputation}, first seen {_esc(vt.first_seen)}</td></tr>")
            parts.append("</table>")

            if extract_ioctl is not None:
                try:
                    surface = extract_ioctl(getattr(r, "path", ""))
                    parts.append(_ioctl_block(surface))
                except Exception:
                    pass
            parts.append("</div>")

        # runners-up
        if len(ranked) > top_n:
            parts.append(f"<h2>Runners-up ({len(ranked) - top_n})</h2>")
            parts.append("<table>")
            parts.append("<tr><th>#</th><th>driver</th><th>score</th><th>classes</th>"
                         "<th>HVCI</th><th>VT</th><th>signed</th></tr>")
            for i, (r, score) in enumerate(ranked[top_n: top_n + 40], top_n + 1):
                vt = getattr(r, "vt", None)
                vt_cell = ""
                if vt is not None and getattr(vt, "total_engines", 0):
                    vt_cell = f"{vt.detections}/{vt.total_engines}"
                hvci = "✓" if getattr(r, "lol_hvci_bypass", False) else ""
                parts.append(
                    "<tr>"
                    f"<td>{i}</td>"
                    f"<td>{_esc(getattr(r, 'filename', ''))}</td>"
                    f"<td>{score}</td>"
                    f"<td>{len(getattr(r, 'primitive_classes', []) or [])}</td>"
                    f"<td class='warn'>{hvci}</td>"
                    f"<td>{vt_cell}</td>"
                    f"<td>{'yes' if getattr(r, 'signed', False) else 'NO'}</td>"
                    "</tr>"
                )
            parts.append("</table>")

    # -- corpus breakdown ----------------------------------------------------
    parts.append("<h2>Primitive-class frequency</h2>")
    cls_counts: dict[str, int] = {}
    for r in flagged:
        for c in getattr(r, "primitive_classes", []) or []:
            cls_counts[c] = cls_counts.get(c, 0) + 1
    if cls_counts:
        parts.append("<table><tr><th>class</th><th>count</th><th>%</th></tr>")
        tot = len(flagged) or 1
        for c, n in sorted(cls_counts.items(), key=lambda x: -x[1]):
            parts.append(f"<tr><td>{_esc(c)}</td><td>{n}</td><td>{n / tot * 100:.0f}%</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Signers seen</h2>")
    sig_counts: dict[str, int] = {}
    for r in flagged:
        s = getattr(r, "signer", "") or "(unsigned)"
        sig_counts[s] = sig_counts.get(s, 0) + 1
    if sig_counts:
        parts.append("<table><tr><th>signer</th><th>hits</th></tr>")
        for s, n in sorted(sig_counts.items(), key=lambda x: -x[1])[:60]:
            parts.append(f"<tr><td>{_esc(s)}</td><td>{n}</td></tr>")
        parts.append("</table>")

    # -- diff section --------------------------------------------------------
    if diff_result is not None:
        parts.append("<h2>Diff vs prior snapshot</h2>")
        parts.append("<table><tr><th>kind</th><th>count</th></tr>")
        for k, v in sorted(diff_result.summary.items()):
            parts.append(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>")
        parts.append("</table>")
        for kind in ("new", "changed", "moved", "removed"):
            entries = diff_result.by_kind(kind)
            if not entries:
                continue
            parts.append(f"<h3>{kind} ({len(entries)})</h3>")
            parts.append("<table><tr><th>sha256</th><th>path</th><th>classes</th></tr>")
            for e in entries[:100]:
                parts.append(
                    "<tr>"
                    f"<td><code>{_esc(e.sha256[:16])}</code></td>"
                    f"<td>{_esc(e.path)}</td>"
                    f"<td>{_esc(','.join(e.primitive_classes) or '-')}</td>"
                    "</tr>"
                )
            parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


def write(path: str | Path, html_text: str) -> None:
    Path(path).write_text(html_text, encoding="utf-8")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Render an HTML dossier from a scan JSON file")
    ap.add_argument("scan_json", help="driverscope scan --json output")
    ap.add_argument("--out", type=str, default="dossier.html")
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()

    class _Fake:
        pass

    with open(args.scan_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    fake_results: list[Any] = []
    for d in data:
        f = _Fake()
        for k, v in d.items():
            setattr(f, k, v)
        f.matched_imports = d.get("matched_imports", [])
        f.primitive_classes = d.get("primitive_classes", [])
        fake_results.append(f)

    # naive rank: by class count
    ranked = [(r, len(r.primitive_classes)) for r in fake_results
              if getattr(r, "primitive_classes", None)]
    ranked.sort(key=lambda x: -x[1])
    html_text = render(fake_results, ranked, target_path=args.scan_json, top_n=args.top)
    write(args.out, html_text)
    print(f"wrote {args.out}")
