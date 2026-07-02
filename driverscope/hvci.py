"""HVCI / WDAC dry-run.

Predict whether a candidate .sys would be denied by the current system's
Code Integrity policy without actually attempting to load it.

Sources of policy, in order of precedence:
  1. Path passed via --policy PATH (a .p7b or .xml file)
  2. C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b (per-machine, running system)
  3. All *.cip / *.p7b under C:\\Windows\\System32\\CodeIntegrity\\CIPolicies\\Active

Deny decision inputs (in order of authority per WDAC):
  - Exact-file deny by Authenticode SHA1/SHA256 or by page-hash SHA1/SHA256.
  - Explicit signer deny (issuer/publisher) matching the driver's cert chain.
  - Microsoft Vulnerable Driver Blocklist entries (subset of the above).

If the parsed policy is unavailable or unreadable, this module falls back to
the local MS blocklist JSON (already fetched by driverscope.scanner) so the check
still returns a useful verdict.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Iterable, Optional


SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
DEFAULT_POLICIES = [
    SYSTEM32 / "CodeIntegrity" / "SiPolicy.p7b",
]
POLICY_DIRS = [
    SYSTEM32 / "CodeIntegrity" / "CIPolicies" / "Active",
]

MS_BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"


@dataclass
class Policy:
    deny_hashes: set[str] = field(default_factory=set)      # hex sha256/sha1
    deny_pagehashes: set[str] = field(default_factory=set)  # hex sha256/sha1 page hashes
    deny_signers: list[str] = field(default_factory=list)   # publisher/issuer substrings
    friendly_names: dict[str, str] = field(default_factory=dict)
    source: str = ""


@dataclass
class Verdict:
    blocked: bool = False
    reason: str = ""
    matched: str = ""


# ── policy parsing ───────────────────────────────────────────────────────

def _parse_wdac_xml(raw: bytes, source: str = "") -> Policy:
    pol = Policy(source=source or "xml")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return pol

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for deny in root.iter(ns + "Deny"):
        fname = (deny.get("FriendlyName") or "").strip()
        hashval = (deny.get("Hash") or "").strip()

        # Base64-encoded Authenticode hash on Hash attribute
        if hashval:
            try:
                raw_bytes = base64.b64decode(hashval)
                hex_hash = raw_bytes.hex().lower()
                if len(hex_hash) in (40, 64):
                    if "page" in fname.lower():
                        pol.deny_pagehashes.add(hex_hash)
                    else:
                        pol.deny_hashes.add(hex_hash)
                    if fname:
                        pol.friendly_names[hex_hash] = fname
            except Exception:
                pass

        # Some MS blocklist entries embed the SHA256 in the FriendlyName
        m = re.search(r"[/\\]([0-9a-fA-F]{64})", fname)
        if m:
            h = m.group(1).lower()
            pol.deny_hashes.add(h)
            if fname:
                pol.friendly_names[h] = fname

    # Signer denies (SigningScenario → DenyRules → Signer references)
    signer_els: dict[str, str] = {}
    for signer in root.iter(ns + "Signer"):
        sid = signer.get("ID") or ""
        name = signer.get("Name") or ""
        cn = ""
        for pub in signer.iter(ns + "CertPublisher"):
            v = pub.get("Value") or ""
            if v:
                cn = v
                break
        subj = cn or name
        if sid and subj:
            signer_els[sid] = subj

    for deny_rule in root.iter(ns + "Deny"):
        for cs in deny_rule.iter(ns + "CertPublisher"):
            v = cs.get("Value") or ""
            if v:
                pol.deny_signers.append(v)

    for scenario in root.iter(ns + "SigningScenario"):
        for allowed in scenario.iter(ns + "DeniedSigner"):
            sid = allowed.get("SignerId") or ""
            subj = signer_els.get(sid, "")
            if subj:
                pol.deny_signers.append(subj)

    return pol


def _pkcs7_extract_signed_data(raw: bytes) -> Optional[bytes]:
    """Given a .p7b / .cat / DER PKCS#7 blob, return the signedData innerContent
    (which for WDAC policies is the WDAC binary policy). Best-effort — we walk
    the ASN.1 tree by hand to avoid a hard dep on cryptography/asn1crypto.
    """
    if raw[:2] == b"MZ":  # not a p7b, someone passed us a PE by mistake
        return None
    # Look for the WDAC XML inside; some tools emit XML directly as .p7b
    idx = raw.find(b"<SiPolicy")
    if idx != -1:
        end = raw.find(b"</SiPolicy>", idx)
        if end != -1:
            return raw[idx: end + len(b"</SiPolicy>")]
    # ASN.1 DER: try to lift any embedded XML.
    idx = raw.find(b"<?xml")
    if idx != -1:
        end = raw.find(b"</SiPolicy>", idx)
        if end != -1:
            return raw[idx: end + len(b"</SiPolicy>")]
    return None


def load_policy_from_p7b(path: str | Path) -> Optional[Policy]:
    p = Path(path)
    if not p.exists():
        return None
    raw = p.read_bytes()
    xml_bytes = _pkcs7_extract_signed_data(raw)
    if xml_bytes is None:
        return None
    return _parse_wdac_xml(xml_bytes, source=str(p))


def load_ms_blocklist_zip(raw: bytes) -> Optional[Policy]:
    """MS blocklist ships as a ZIP with an XML SiPolicy inside."""
    if raw[:2] != b"PK":
        return None
    with zipfile.ZipFile(BytesIO(raw)) as zf:
        xml_bytes: Optional[bytes] = None
        for name in zf.namelist():
            if name.endswith(".xml") and "Legacy" not in name:
                xml_bytes = zf.read(name)
                break
        if xml_bytes is None:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    xml_bytes = zf.read(name)
                    break
        if xml_bytes is None:
            return None
    return _parse_wdac_xml(xml_bytes, source="MS blocklist ZIP")


def load_ms_blocklist_json_cache(cache_path: Optional[str | Path] = None) -> Policy:
    """Fallback: use the cache file driverscope.scanner already writes (ms_blocklist_sha256.json)."""
    if cache_path is None:
        cache_path = Path(__file__).resolve().parent.parent / "ms_blocklist_sha256.json"
    p = Path(cache_path)
    pol = Policy(source=f"json:{p.name}")
    if not p.exists():
        return pol
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return pol
    for h in data.get("hashes", []) or []:
        if isinstance(h, str) and len(h) in (40, 64):
            pol.deny_hashes.add(h.lower())
    for h, name in (data.get("driver_names") or {}).items():
        if isinstance(h, str) and name:
            pol.friendly_names[h.lower()] = name
    return pol


def default_policies() -> list[Policy]:
    """Load every plausible policy file on the running system, plus the local MS blocklist cache."""
    policies: list[Policy] = []
    for p in DEFAULT_POLICIES:
        pol = load_policy_from_p7b(p)
        if pol is not None:
            policies.append(pol)
    for d in POLICY_DIRS:
        if d.exists():
            for f in d.iterdir():
                if f.suffix.lower() in (".cip", ".p7b", ".xml"):
                    pol = load_policy_from_p7b(f)
                    if pol is not None:
                        policies.append(pol)
    policies.append(load_ms_blocklist_json_cache())
    return policies


# ── driver hash calculators ─────────────────────────────────────────────

def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _sha1_file(path: str | Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _authenticode_hash(path: str | Path, alg: str = "sha256") -> Optional[str]:
    """Approximate Authenticode hash: skip the checksum field, security dir entry,
    and the WIN_CERTIFICATE section itself. Matches the WDAC "Hash" attribute for
    signed PEs the vast majority of the time.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        return None

    file_header_off = e_lfanew + 4
    machine_off = file_header_off
    opt_hdr_off = file_header_off + 20
    if opt_hdr_off + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt_hdr_off)[0]
    if magic == 0x20B:      # PE32+
        checksum_off = opt_hdr_off + 64
        data_dir_off = opt_hdr_off + 112
    elif magic == 0x10B:    # PE32
        checksum_off = opt_hdr_off + 64
        data_dir_off = opt_hdr_off + 96
    else:
        return None

    if data_dir_off + 4 * 8 * 2 > len(data):
        return None
    security_dir_va = struct.unpack_from("<I", data, data_dir_off + 8 * 4)[0]
    security_dir_size = struct.unpack_from("<I", data, data_dir_off + 8 * 4 + 4)[0]

    h = hashlib.new(alg)
    # 1. everything before the checksum
    h.update(data[:checksum_off])
    # 2. skip checksum (4 bytes)
    # 3. bytes between checksum and security-directory entry
    security_entry_off = data_dir_off + 8 * 4
    h.update(data[checksum_off + 4: security_entry_off])
    # 4. skip 8-byte security-directory entry
    # 5. rest of file up to WIN_CERTIFICATE
    tail_start = security_entry_off + 8
    if security_dir_va and security_dir_size:
        h.update(data[tail_start: security_dir_va])
    else:
        h.update(data[tail_start:])
    return h.hexdigest().lower()


# ── verdict ─────────────────────────────────────────────────────────────

def evaluate(sha256: str, driver_path: Optional[str | Path] = None,
             signer: Optional[str] = None,
             policies: Optional[Iterable[Policy]] = None) -> Verdict:
    """Return a HVCI/WDAC verdict for a single driver.

    All hash comparisons are case-insensitive hex. The signer arg (if provided)
    is checked against every deny_signers substring in every policy.
    """
    if policies is None:
        policies = default_policies()

    sha256 = (sha256 or "").lower()
    hashes_to_check: set[str] = set()
    if sha256:
        hashes_to_check.add(sha256)
    if driver_path:
        try:
            hashes_to_check.add(_authenticode_hash(driver_path, "sha256") or "")
            hashes_to_check.add(_authenticode_hash(driver_path, "sha1") or "")
            hashes_to_check.add(_sha1_file(driver_path))
        except Exception:
            pass
    hashes_to_check.discard("")

    for pol in policies:
        for h in hashes_to_check:
            if h in pol.deny_hashes:
                return Verdict(blocked=True, reason=f"hash denied ({pol.source})",
                               matched=pol.friendly_names.get(h, h))
            if h in pol.deny_pagehashes:
                return Verdict(blocked=True, reason=f"pagehash denied ({pol.source})",
                               matched=h)
        if signer:
            s_lower = signer.lower()
            for pattern in pol.deny_signers:
                if pattern and pattern.lower() in s_lower:
                    return Verdict(blocked=True,
                                   reason=f"signer denied ({pol.source})",
                                   matched=pattern)

    return Verdict(blocked=False)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Offline WDAC / HVCI dry-run for a driver")
    ap.add_argument("driver", help="Path to a .sys file")
    ap.add_argument("--signer", help="Optional signer/subject to feed the check")
    ap.add_argument("--policy", action="append", default=[],
                    help="Path(s) to SiPolicy.p7b / .cip / .xml files to load")
    args = ap.parse_args()

    pols: list[Policy] = []
    if args.policy:
        for p in args.policy:
            pol = load_policy_from_p7b(p)
            if pol:
                pols.append(pol)
    if not pols:
        pols = default_policies()

    total_hashes = sum(len(p.deny_hashes) for p in pols)
    total_signers = sum(len(p.deny_signers) for p in pols)
    print(f"[hvci] loaded {len(pols)} policies "
          f"({total_hashes} deny-hashes, {total_signers} deny-signers)")

    sha = _sha256_file(args.driver)
    v = evaluate(sha, driver_path=args.driver, signer=args.signer, policies=pols)
    print(f"[hvci] {args.driver}")
    print(f"       sha256={sha}")
    if v.blocked:
        print(f"       BLOCKED — {v.reason}  matched={v.matched}")
    else:
        print("       ALLOWED (no matching deny under loaded policies)")
