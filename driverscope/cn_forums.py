"""Chinese RE forum thread scraper for driver-related posts.

Covers two forums:
  - Kanxue (bbs.kanxue.com) — Xiuno BBS engine
  - 52pojie (www.52pojie.cn) — Discuz! engine

Both allow guest reading of thread content. Attachments (.sys/.zip/.7z)
inside threads typically require login to download.

This module:
  1. Searches each forum for driver-related Chinese keywords
  2. Collects matching thread URLs + titles
  3. Optionally scrapes thread bodies for attachment links
  4. Outputs a JSON manifest for manual review / authenticated download

Usage:
    python -m driverscope.cn_forums search          # search both forums
    python -m driverscope.cn_forums search --kanxue  # Kanxue only
    python -m driverscope.cn_forums search --52pojie # 52pojie only
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) driverscope/0.1"
FETCH_DELAY = 2.0
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "cn_forum_threads.json"

SEARCH_KEYWORDS = [
    "驱动 漏洞",       # driver vulnerability
    "签名驱动",         # signed driver
    "内核驱动 提权",    # kernel driver privilege escalation
    "physmem",
    "MmMapIoSpace",
    "BYOVD",
    "IOCTL 驱动",       # IOCTL driver
    "反rootkit 驱动",   # anti-rootkit driver
    "ARK工具",          # ARK tool (anti-rootkit kit)
    "驱动加载",         # driver loading
    "sys 签名",         # .sys signed
]


@dataclass
class ThreadHit:
    forum: str
    url: str
    title: str
    keyword: str
    attachments: list[str] = field(default_factory=list)


# ── HTTP helpers ─────────────────────────────────────────────────────────

def fetch_page(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ── Kanxue (Xiuno BBS) ──────────────────────────────────────────────────

KANXUE_BASE = "https://bbs.kanxue.com"

KANXUE_TAG_PAGES = {
    "驱动开发":  "forum-41-{page}-132_0_0_0.htm",
    "系统内核":  "forum-41-{page}-131_0_0_0.htm",
    "HOOK/注入": "forum-41-{page}-133_0_0_0.htm",
    "虚拟化":    "forum-41-{page}-136_0_0_0.htm",
}


def kanxue_scrape_tag(tag_name: str, url_template: str,
                      max_pages: int = 5) -> list[ThreadHit]:
    hits: list[ThreadHit] = []
    seen_urls: set[str] = set()

    for page in range(1, max_pages + 1):
        rel = url_template.format(page=page)
        url = f"{KANXUE_BASE}/{rel}"
        try:
            body = fetch_page(url)
        except Exception as e:
            print(f"  [!] {url}: {e}")
            break

        for m in re.finditer(r'href="(thread-\d+\.htm)"[^>]*>([^<]+)', body):
            thread_url = f"{KANXUE_BASE}/{m.group(1)}"
            title = html.unescape(m.group(2)).strip()
            if thread_url in seen_urls:
                continue
            seen_urls.add(thread_url)
            hits.append(ThreadHit(
                forum="kanxue",
                url=thread_url,
                title=title,
                keyword=tag_name,
            ))

        time.sleep(FETCH_DELAY)

    return hits


def kanxue_search(max_pages: int = 3) -> list[ThreadHit]:
    all_hits: list[ThreadHit] = []
    for tag_name, template in KANXUE_TAG_PAGES.items():
        print(f"  [kanxue] Scraping tag: {tag_name}")
        hits = kanxue_scrape_tag(tag_name, template, max_pages)
        print(f"    {len(hits)} threads")
        all_hits.extend(hits)
    return all_hits


# ── 52pojie (Discuz!) ───────────────────────────────────────────────────

POJIE_BASE = "https://www.52pojie.cn"

POJIE_FORUMS = {
    "病毒分析区": "forum-32-{page}.html",
    "安全工具区": "forum-41-{page}.html",
    "逆向资源区": "forum-4-{page}.html",
    "软件调试区": "forum-37-{page}.html",
}


def pojie_scrape_forum(forum_name: str, url_template: str,
                       max_pages: int = 3,
                       keywords: list[str] | None = None) -> list[ThreadHit]:
    kw = keywords or ["驱动", "driver", "内核", "kernel", ".sys",
                       "IOCTL", "physmem", "rootkit", "ARK"]
    hits: list[ThreadHit] = []
    seen_urls: set[str] = set()

    for page in range(1, max_pages + 1):
        rel = url_template.format(page=page)
        url = f"{POJIE_BASE}/{rel}"
        try:
            body = fetch_page(url)
        except Exception as e:
            print(f"  [!] {url}: {e}")
            break

        for m in re.finditer(
            r'href="(thread-\d+-\d+-\d+\.html)"[^>]*>([^<]+)', body
        ):
            thread_url = f"{POJIE_BASE}/{m.group(1)}"
            title = html.unescape(m.group(2)).strip()
            if thread_url in seen_urls:
                continue
            matched_kw = next((k for k in kw if k.lower() in title.lower()), None)
            if matched_kw:
                seen_urls.add(thread_url)
                hits.append(ThreadHit(
                    forum="52pojie",
                    url=thread_url,
                    title=title,
                    keyword=matched_kw,
                ))

        time.sleep(FETCH_DELAY)

    return hits


def pojie_search(max_pages: int = 3) -> list[ThreadHit]:
    all_hits: list[ThreadHit] = []
    for forum_name, template in POJIE_FORUMS.items():
        print(f"  [52pojie] Scraping forum: {forum_name}")
        hits = pojie_scrape_forum(forum_name, template, max_pages)
        print(f"    {len(hits)} matching threads")
        all_hits.extend(hits)
    return all_hits


# ── attachment extraction ────────────────────────────────────────────────

ATTACH_RE_DISCUZ = re.compile(
    r'href="(forum\.php\?mod=attachment&aid=[^"]+)"', re.I
)
ATTACH_RE_KANXUE = re.compile(
    r'href="([^"]*(?:\.sys|\.zip|\.7z|\.rar)[^"]*)"', re.I
)


def scrape_attachments(hit: ThreadHit) -> list[str]:
    try:
        body = fetch_page(hit.url)
    except Exception:
        return []

    attachments = []
    if hit.forum == "52pojie":
        for m in ATTACH_RE_DISCUZ.finditer(body):
            url = m.group(1)
            if not url.startswith("http"):
                url = f"{POJIE_BASE}/{url}"
            attachments.append(html.unescape(url))
    elif hit.forum == "kanxue":
        for m in ATTACH_RE_KANXUE.finditer(body):
            url = m.group(1)
            if not url.startswith("http"):
                url = f"{KANXUE_BASE}/{url}"
            attachments.append(html.unescape(url))

    return attachments


# ── orchestration ────────────────────────────────────────────────────────

def search(kanxue: bool = True, pojie: bool = True,
           max_pages: int = 3, scrape_attach: bool = False,
           out_path: Path = DEFAULT_OUT) -> list[ThreadHit]:
    all_hits: list[ThreadHit] = []

    if kanxue:
        print("[+] Searching Kanxue (bbs.kanxue.com)")
        all_hits.extend(kanxue_search(max_pages))

    if pojie:
        print("[+] Searching 52pojie (www.52pojie.cn)")
        all_hits.extend(pojie_search(max_pages))

    if scrape_attach:
        print(f"\n[+] Scraping attachments from {len(all_hits)} threads...")
        for i, hit in enumerate(all_hits):
            hit.attachments = scrape_attachments(hit)
            if hit.attachments:
                print(f"  [{i+1}] {hit.title}: {len(hit.attachments)} attachments")
            time.sleep(FETCH_DELAY)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "total": len(all_hits),
        "kanxue": len([h for h in all_hits if h.forum == "kanxue"]),
        "pojie": len([h for h in all_hits if h.forum == "52pojie"]),
        "with_attachments": len([h for h in all_hits if h.attachments]),
        "threads": [asdict(h) for h in all_hits],
    }
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"\n[+] {len(all_hits)} threads written to {out_path}")
    return all_hits


# ── CLI ──────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="Chinese RE forum driver thread scraper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_s = sub.add_parser("search", help="search forums for driver-related threads")
    ap_s.add_argument("--kanxue", action="store_true", help="Kanxue only")
    ap_s.add_argument("--52pojie", dest="pojie", action="store_true",
                      help="52pojie only")
    ap_s.add_argument("--pages", type=int, default=3,
                      help="max pages per forum/tag to scrape")
    ap_s.add_argument("--attachments", action="store_true",
                      help="also scrape thread bodies for attachment links")
    ap_s.add_argument("--out", type=Path, default=DEFAULT_OUT)

    args = ap.parse_args()

    if args.cmd == "search":
        do_kanxue = not args.pojie or args.kanxue
        do_pojie = not args.kanxue or args.pojie
        if args.kanxue and args.pojie:
            do_kanxue = do_pojie = True
        search(kanxue=do_kanxue, pojie=do_pojie,
               max_pages=args.pages, scrape_attach=args.attachments,
               out_path=args.out)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
