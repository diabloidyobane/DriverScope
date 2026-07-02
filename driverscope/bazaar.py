"""MalwareBazaar + MalShare .sys pivots.

Given no starting point, or given a signer / imphash / hash, fetch signed
kernel drivers from public malware feeds. Keys are read from
yara/hunt.py-style config (env vars MB_API_KEY, MALSHARE_API_KEY) OR passed
inline. This module does not commit key material.

Both feeds have per-day quota. We rate-limit conservatively and cache the
resulting metadata under `bazaar_cache.json`.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Optional


CACHE_PATH = Path(__file__).resolve().parent.parent / "bazaar_cache.json"
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "bazaar_harvest"

MB_QUERY_URL = "https://mb-api.abuse.ch/api/v1/"
MB_DOWNLOAD_URL = MB_QUERY_URL
MB_ZIP_PASSWORD = "infected"

MALSHARE_URL = "https://malshare.com/api.php"

USER_AGENT = "driverscope/0.1 (+contact@localhost)"


# ── config -------------------------------------------------------------

def env_key(names: Iterable[str]) -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v.strip()
    return ""


@dataclass
class Sample:
    sha256: str
    md5: str = ""
    sha1: str = ""
    filename: str = ""
    tags: list[str] = field(default_factory=list)
    signature: str = ""
    file_type: str = ""
    imphash: str = ""
    first_seen: str = ""
    source: str = ""  # "mb" | "malshare"


# ── cache -------------------------------------------------------------

def _load_cache() -> dict:
    if not CACHE_PATH.exists():
        return {}
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(c: dict) -> None:
    try:
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(c, indent=2), encoding="utf-8")
        tmp.replace(CACHE_PATH)
    except Exception:
        pass


# ── MalwareBazaar ------------------------------------------------------

def mb_post(payload: dict, api_key: str, timeout: int = 30) -> Optional[dict]:
    data = urllib.parse.urlencode(payload).encode("ascii")
    req = urllib.request.Request(MB_QUERY_URL, data=data, method="POST",
                                 headers={"User-Agent": USER_AGENT,
                                          "Auth-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def mb_query_by_tag(tag: str, api_key: str, limit: int = 100) -> list[Sample]:
    r = mb_post({"query": "get_taginfo", "tag": tag, "limit": str(limit)}, api_key)
    if not r or r.get("query_status") not in ("ok", "unknown_tag"):
        return []
    out: list[Sample] = []
    for item in r.get("data", []) or []:
        out.append(Sample(
            sha256=(item.get("sha256_hash") or "").lower(),
            md5=(item.get("md5_hash") or "").lower(),
            sha1=(item.get("sha1_hash") or "").lower(),
            filename=item.get("file_name") or "",
            tags=list(item.get("tags") or []),
            signature=item.get("signature") or "",
            file_type=item.get("file_type") or "",
            imphash=(item.get("imphash") or "").lower(),
            first_seen=item.get("first_seen") or "",
            source="mb",
        ))
    return out


def mb_query_by_signature(signer: str, api_key: str, limit: int = 100) -> list[Sample]:
    r = mb_post({"query": "get_siginfo", "signature": signer, "limit": str(limit)}, api_key)
    if not r or r.get("query_status") not in ("ok", "no_results"):
        return []
    out: list[Sample] = []
    for item in r.get("data", []) or []:
        out.append(Sample(
            sha256=(item.get("sha256_hash") or "").lower(),
            md5=(item.get("md5_hash") or "").lower(),
            sha1=(item.get("sha1_hash") or "").lower(),
            filename=item.get("file_name") or "",
            tags=list(item.get("tags") or []),
            signature=item.get("signature") or "",
            file_type=item.get("file_type") or "",
            imphash=(item.get("imphash") or "").lower(),
            first_seen=item.get("first_seen") or "",
            source="mb",
        ))
    return out


def mb_query_recent(api_key: str, limit: int = 500) -> list[Sample]:
    r = mb_post({"query": "get_recent", "selector": "100"}, api_key)
    if not r or r.get("query_status") != "ok":
        return []
    out: list[Sample] = []
    for item in r.get("data", []) or []:
        out.append(Sample(
            sha256=(item.get("sha256_hash") or "").lower(),
            md5=(item.get("md5_hash") or "").lower(),
            sha1=(item.get("sha1_hash") or "").lower(),
            filename=item.get("file_name") or "",
            tags=list(item.get("tags") or []),
            signature=item.get("signature") or "",
            file_type=item.get("file_type") or "",
            imphash=(item.get("imphash") or "").lower(),
            first_seen=item.get("first_seen") or "",
            source="mb",
        ))
    return out


def mb_download(sha256: str, api_key: str, out_dir: Path,
                timeout: int = 60) -> Optional[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{sha256}.sys"
    if target.exists() and target.stat().st_size > 0:
        return target
    data = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode("ascii")
    req = urllib.request.Request(MB_DOWNLOAD_URL, data=data, method="POST",
                                 headers={"User-Agent": USER_AGENT, "Auth-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
    except Exception:
        return None
    if not payload or payload[:2] != b"PK":
        return None
    # MB uses WinZip AES-256 (compression method 99); pyzipper handles it,
    # stdlib zipfile does not.
    try:
        import pyzipper  # type: ignore
        _ZipCls = pyzipper.AESZipFile
    except ImportError:
        _ZipCls = zipfile.ZipFile
    try:
        zf = _ZipCls(io.BytesIO(payload))
        zf.setpassword(MB_ZIP_PASSWORD.encode("ascii"))
        for name in zf.namelist():
            try:
                blob = zf.read(name)
            except Exception:
                continue
            if blob[:2] == b"MZ":
                target.write_bytes(blob)
                return target
    except Exception:
        return None
    return None


# ── MalShare -----------------------------------------------------------

def _malshare_get(params: dict, timeout: int = 30) -> Optional[str]:
    url = f"{MALSHARE_URL}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def malshare_search_type(file_type: str, api_key: str) -> list[Sample]:
    """MalShare supports file-type search via typesearch (returns SHA256 list)."""
    txt = _malshare_get({"api_key": api_key, "action": "typesearch", "type": file_type})
    if not txt:
        return []
    out: list[Sample] = []
    for line in txt.splitlines():
        line = line.strip()
        if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
            out.append(Sample(sha256=line, source="malshare"))
    return out


def malshare_recent_list(api_key: str, days_back: int = 30) -> list[Sample]:
    """Walk MalShare's per-day upload list for the past `days_back` days.
    Returns SHA256 lists (no filetype info). Caller must verify each is a PE
    by checking MZ magic after download.
    """
    import datetime
    out: list[Sample] = []
    seen: set[str] = set()
    for offset in range(days_back):
        # getlist returns yesterday-through-today of latest 100 uploads;
        # there is no per-date query — instead we page via getlist repeatedly.
        # This call returns the freshest set at each call time; we dedup.
        txt = _malshare_get({"api_key": api_key, "action": "getlistraw"})
        if not txt:
            break
        for line in txt.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and len(parts[2]) == 64:
                sha = parts[2].lower()
                if sha in seen:
                    continue
                seen.add(sha)
                out.append(Sample(sha256=sha, source="malshare"))
        if offset < days_back - 1:
            time.sleep(2)  # gentle pacing
    return out


def malshare_head_check(sha256: str, api_key: str) -> bool:
    """Cheap check: fetch details() to know if we should bother downloading."""
    txt = _malshare_get({"api_key": api_key, "action": "details", "hash": sha256})
    if not txt:
        return False
    low = txt.lower()
    return any(k in low for k in ("pe32", "peexe", "driver", "sys"))


def malshare_download(sha256: str, api_key: str, out_dir: Path,
                      timeout: int = 60) -> Optional[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{sha256}.sys"
    if target.exists() and target.stat().st_size > 0:
        return target
    url = f"{MALSHARE_URL}?" + urllib.parse.urlencode(
        {"api_key": api_key, "action": "getfile", "hash": sha256}
    )
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            blob = resp.read()
    except Exception:
        return None
    if not blob or blob[:2] != b"MZ":
        return None
    target.write_bytes(blob)
    return target


# ── orchestrator -------------------------------------------------------

def harvest(mb_key: str = "", malshare_key: str = "",
            tags: Iterable[str] = ("driver", "kernel_driver", "byovd"),
            signers: Iterable[str] = (),
            out_dir: Path = DEFAULT_OUT,
            per_query_limit: int = 200,
            fetch_max: int = 100) -> dict:
    mb_key = mb_key or env_key(("MB_API_KEY", "MALWAREBAZAAR_API_KEY"))
    malshare_key = malshare_key or env_key(("MALSHARE_API_KEY",))
    out_dir.mkdir(parents=True, exist_ok=True)
    drivers_dir = out_dir / "drivers"
    drivers_dir.mkdir(parents=True, exist_ok=True)

    cache = _load_cache()
    manifest: dict = {"queried": [], "candidates": [], "fetched": []}
    all_samples: list[Sample] = []

    if mb_key:
        for tag in tags:
            samples = mb_query_by_tag(tag, mb_key, limit=per_query_limit)
            manifest["queried"].append({"source": "mb", "tag": tag, "hits": len(samples)})
            all_samples.extend(samples)
            time.sleep(1)
        for signer in signers:
            samples = mb_query_by_signature(signer, mb_key, limit=per_query_limit)
            manifest["queried"].append({"source": "mb", "signature": signer, "hits": len(samples)})
            all_samples.extend(samples)
            time.sleep(1)

    if malshare_key:
        # Walk recent uploads (MalShare only exposes freshest 100 via getlist).
        # Their typesearch endpoint is 24h-scoped and rarely useful for driver hunting.
        samples = malshare_recent_list(malshare_key, days_back=8)
        manifest["queried"].append({"source": "malshare", "action": "getlistraw",
                                     "hits": len(samples)})
        all_samples.extend(samples)
        time.sleep(1)

    # dedupe by sha256
    dedup: dict[str, Sample] = {}
    for s in all_samples:
        if not s.sha256 or s.sha256 in dedup:
            continue
        # heuristic: only pursue .sys / native PE / signed kernel driver
        f_low = (s.filename or "").lower()
        types_low = (s.file_type or "").lower()
        tags_low = " ".join(s.tags).lower()
        looks_kernel = (
            f_low.endswith(".sys") or "kernel" in tags_low or "driver" in tags_low
            or "sys" in types_low or "native" in types_low
        )
        if not looks_kernel and s.source == "mb":
            continue
        dedup[s.sha256] = s

    manifest["candidates"] = [asdict(s) for s in dedup.values()]

    # fetch
    fetched_paths: list[str] = []
    count = 0
    for sha, s in dedup.items():
        if count >= fetch_max:
            break
        if sha in cache and cache[sha].get("fetched"):
            continue
        path: Optional[Path] = None
        if s.source == "mb" and mb_key:
            path = mb_download(sha, mb_key, drivers_dir)
        elif s.source == "malshare" and malshare_key:
            path = malshare_download(sha, malshare_key, drivers_dir)
        if path is not None:
            cache[sha] = {"fetched": True, "path": str(path),
                          "signature": s.signature, "source": s.source,
                          "filename": s.filename, "tags": s.tags}
            fetched_paths.append(str(path))
            count += 1
        time.sleep(0.2)

    manifest["fetched"] = fetched_paths
    _save_cache(cache)
    with open(out_dir / "bazaar_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="MalwareBazaar + MalShare .sys harvester")
    ap.add_argument("--mb-key", type=str, default="")
    ap.add_argument("--malshare-key", type=str, default="")
    ap.add_argument("--tag", action="append", default=None,
                    help="MB tag (repeat). Defaults: driver, kernel_driver, byovd.")
    ap.add_argument("--signer", action="append", default=[],
                    help="MB signer query (repeat).")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT))
    ap.add_argument("--fetch-max", type=int, default=50)
    ap.add_argument("--per-query-limit", type=int, default=200)
    args = ap.parse_args()

    tags = args.tag if args.tag else ["driver", "kernel_driver", "byovd"]
    m = harvest(mb_key=args.mb_key, malshare_key=args.malshare_key,
                tags=tags, signers=args.signer,
                out_dir=Path(args.out),
                per_query_limit=args.per_query_limit,
                fetch_max=args.fetch_max)
    print(f"[bazaar] candidates={len(m.get('candidates', []))} "
          f"fetched={len(m.get('fetched', []))}")
