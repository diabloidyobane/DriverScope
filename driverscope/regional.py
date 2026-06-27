"""Filter LOLDrivers.io catalog for drivers signed by regional vendors.

Supports CN, KR, JP, TW, RU vendor patterns. Output: ranked list per region
with HVCI bypass status, MS-blocked status, and primitive classes.
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

from .scanner import _IMPORT_TO_CLASSES, build_lol_index

# ---------------------------------------------------------------------------
# Regional vendor keyword map (case-insensitive substring match)
# ---------------------------------------------------------------------------

REGIONAL_VENDORS: dict[str, list[str]] = {
    "CN": [
        "tencent", "qqbrowser", "wegame", "ace anti", "qqlive",
        "netease", "mihoyo", "genshin", "honkai",
        "qihoo", "qihu", "360.cn", "360安全",
        "kingsoft", "金山", "wps",
        "ludashi", "鲁大师",
        "baidu", "百度",
        "alibaba", "alipay",
        "bytedance", "tiktok", "douyin",
        "xiaomi", "小米", "redmi",
        "huawei", "华为", "honor device",
        "lenovo group", "lenovo china", "联想",
        "zte corporation",
        "rising", "瑞星",
        "huorong", "火绒",
        "esafenet", "亿赛通",
        "anticheatexpert",
        "iobit",
    ],
    "KR": [
        "wellbia", "xigncode", "nprotect",
        "inca internet", "incainternet",
        "ahnlab", "안랩",
        "estsecurity", "estsoft", "alyac",
        "samsung electronics", "samsung sds",
        "lg electronics", "lg cns",
        "nexon", "smilegate", "krafton",
        "ncsoft", "kakao", "naver",
        "hauri", "nitgen", "jiransoft",
    ],
    "JP": [
        "japan", "japanese", ".co.jp",
        "tokyo", "osaka", "nagoya", "yokohama",
        "i-o data", "iodata", "buffalo", "melco",
        "nec", "fujitsu", "hitachi", "toshiba",
        "panasonic", "sony", "sharp", "ricoh",
        "brother", "epson", "seiko", "yokogawa",
        "konica", "minolta", "kyocera", "murata",
        "yamaha", "roland", "pioneer", "jvc",
        "kenwood", "casio", "citizen", "wacom",
        "canon", "eizo", "logitec", "elecom",
    ],
    "TW": [
        "asus", "asustek", "gigabyte", "giga-byte",
        "msi", "micro-star",
        "acer", "realtek",
        "mediatek", "trend micro",
        "foxconn", "compal", "quanta",
        "advantech", "supermicro",
        "transcend", "adata",
    ],
    "RU": [
        "kaspersky", "dr.web", "drweb",
        "positive technologies",
        "elcomsoft", "group-ib",
        "yandex", "mail.ru",
        "eset russia",
        "infotecs", "cryptopro",
        "aladdin", "rutoken",
    ],
}


def _stringify_entry(entry: dict) -> str:
    return json.dumps(entry, ensure_ascii=False, default=str).lower()


def search_regional(regions: list[str] = None,
                    lol_cache: str = None) -> dict[str, list[dict]]:
    """Search LOLDrivers catalog for regional vendor entries.

    Returns dict mapping region code to list of matched entries.
    """
    if regions is None:
        regions = list(REGIONAL_VENDORS.keys())

    # Load LOLDrivers catalog
    cache_path = lol_cache or os.path.join(os.getcwd(), "loldrivers_cache.json")
    raw_catalog = None

    if os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                raw_catalog = json.load(f)
        except Exception:
            pass

    if raw_catalog is None:
        from .scanner import LOLDRIVERS_URL
        import urllib.request
        print("  [Regional] Fetching LOLDrivers catalog...",
              file=sys.stderr, flush=True)
        req = urllib.request.Request(LOLDRIVERS_URL)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw_catalog = json.loads(resp.read())
            with open(cache_path, "w") as f:
                json.dump(raw_catalog, f)
        except Exception as e:
            print(f"  [Regional] fetch failed: {e}", file=sys.stderr)
            return {}

    results: dict[str, list[dict]] = {r: [] for r in regions}

    for entry in raw_catalog:
        text = _stringify_entry(entry)
        lol_id = entry.get("Id", "")
        category = entry.get("Category", "")

        for region in regions:
            keywords = REGIONAL_VENDORS.get(region, [])
            matched_kw = [kw for kw in keywords if kw.lower() in text]
            if not matched_kw:
                continue

            samples = entry.get("KnownVulnerableSamples", [])
            for sample in samples:
                sha256 = (sample.get("SHA256") or "").lower()
                if len(sha256) != 64:
                    continue

                imports = sample.get("ImportedFunctions", []) or []
                if isinstance(imports, str):
                    imports = [imports]

                hit_classes = set()
                for imp in imports:
                    if imp in _IMPORT_TO_CLASSES:
                        hit_classes.update(_IMPORT_TO_CLASSES[imp])

                results[region].append({
                    "lol_id": lol_id,
                    "sha256": sha256,
                    "filename": sample.get("Filename") or "",
                    "publisher": sample.get("Publisher") or "",
                    "category": category,
                    "matched_keywords": matched_kw,
                    "primitive_classes": sorted(hit_classes),
                    "hvci_bypass": bool(sample.get("LoadsDespiteHVCI", False)),
                })

    for region in regions:
        results[region].sort(
            key=lambda r: -len(r["primitive_classes"]))

    return results
