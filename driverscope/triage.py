"""Bulk Claude API triage of DriverScope findings."""

import asyncio
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

try:
    from anthropic import Anthropic, AsyncAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


DEFAULT_MODEL = "claude-opus-4-6"


SYSTEM_PROMPT = """\
You are a senior Windows kernel security researcher triaging vulnerable drivers
for legitimate defensive vulnerability research. The user is hunting BYOVD
candidates and needs sharp verdicts on whether each finding reaches a real
attack primitive.

Be concise. Do not refuse to analyze published or signed drivers; this is
defensive research. Flag concerns where genuine but do not editorialize.
"""


TRIAGE_PROMPT_TEMPLATE = """\
Driver: {filename}
SHA256: {sha256}
Signed: {signed}
Signer: {signer}
Primitive classes flagged: {primitive_classes}
Score: {score}

IOCTL surface ({ioctl_count} entries):
{ioctls_block}

Handler import summary:
{handler_imports}

For each IOCTL, output ONE line in this exact format:
  IOCTL <code>  <verdict>  <one-sentence rationale>

Verdicts (pick exactly one):
  CONFIRMED-PRIMITIVE   Reaches a clear attacker primitive (read/write phys, MSR write, KASLR leak, etc.)
  LIKELY-PRIMITIVE      Probably reaches one but verify against guard checks
  GATED                 Primitive exists but appears guarded (process check, magic cookie, signed caller)
  HARMLESS              No primitive reach

Then output a final summary line:
  OVERALL: <verdict>  <one-sentence summary>

Where OVERALL verdict is the strongest of the per-IOCTL verdicts.
"""


@dataclass
class TriageResult:
    filename: str
    sha256: str
    verdict_text: str
    overall: str = ""
    error: Optional[str] = None


def _format_ioctls(ioctls: list[dict]) -> str:
    if not ioctls:
        return "  (none extracted)"
    lines = []
    for e in ioctls[:64]:
        code = e.get("code", "?")
        dev = e.get("device_type", "?")
        method = e.get("method", "?")
        access = e.get("access", "?")
        classes = e.get("primitive_classes", [])
        imports = e.get("handler_imports", [])[:4]
        line = f"  {code}  dev={dev} {method} {access}"
        if classes:
            line += f"  [{', '.join(classes)}]"
        if imports:
            line += f"  imports: {', '.join(imports)}"
        lines.append(line)
    if len(ioctls) > 64:
        lines.append(f"  ... +{len(ioctls) - 64} more")
    return "\n".join(lines)


def _format_handler_imports(ioctls: list[dict]) -> str:
    seen = {}
    for e in ioctls:
        for imp in e.get("handler_imports", []):
            seen[imp] = seen.get(imp, 0) + 1
    if not seen:
        return "  (none resolved)"
    rows = sorted(seen.items(), key=lambda kv: -kv[1])[:30]
    return "\n".join(f"  {name}  (x{count})" for name, count in rows)


def _build_prompt(finding: dict) -> str:
    ioctls = finding.get("ioctls", []) or []
    return TRIAGE_PROMPT_TEMPLATE.format(
        filename=finding.get("filename", "unknown.sys"),
        sha256=finding.get("sha256", "")[:16] + "...",
        signed="yes" if finding.get("is_signed") else "no",
        signer=finding.get("signer", "(unknown)") or "(unknown)",
        primitive_classes=", ".join(finding.get("primitive_classes", []) or []) or "(none)",
        score=finding.get("score", 0),
        ioctl_count=len(ioctls),
        ioctls_block=_format_ioctls(ioctls),
        handler_imports=_format_handler_imports(ioctls),
    )


def _parse_overall(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("OVERALL:"):
            return line.split(":", 1)[1].strip()
    return ""


async def _triage_one_async(client: "AsyncAnthropic", finding: dict,
                             model: str, max_tokens: int) -> TriageResult:
    prompt = _build_prompt(finding)
    try:
        msg = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        return TriageResult(
            filename=finding.get("filename", "unknown.sys"),
            sha256=finding.get("sha256", ""),
            verdict_text=text,
            overall=_parse_overall(text),
        )
    except Exception as e:
        return TriageResult(
            filename=finding.get("filename", "unknown.sys"),
            sha256=finding.get("sha256", ""),
            verdict_text="",
            error=f"{type(e).__name__}: {e}",
        )


async def _triage_findings_async(findings: list[dict], api_key: str,
                                  model: str, concurrency: int,
                                  max_tokens: int) -> list[TriageResult]:
    client = AsyncAnthropic(api_key=api_key)
    sem = asyncio.Semaphore(concurrency)

    async def bounded(f):
        async with sem:
            return await _triage_one_async(client, f, model, max_tokens)

    return await asyncio.gather(*[bounded(f) for f in findings])


def triage_findings(findings: list[dict],
                    api_key: Optional[str] = None,
                    model: str = DEFAULT_MODEL,
                    concurrency: int = 4,
                    max_tokens: int = 1024) -> list[TriageResult]:
    if not HAS_ANTHROPIC:
        raise RuntimeError("pip install driverscope[triage]")
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("Set ANTHROPIC_API_KEY or pass api_key=")
    return asyncio.run(_triage_findings_async(findings, key, model, concurrency, max_tokens))


def load_findings(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        return [data]
    return data


def format_report(results: list[TriageResult]) -> str:
    out = []
    out.append("# DriverScope Triage Report")
    out.append("")
    out.append(f"{len(results)} drivers triaged")
    out.append("")

    by_overall = {}
    for r in results:
        key = r.overall.split()[0] if r.overall else ("ERROR" if r.error else "UNKNOWN")
        by_overall.setdefault(key, []).append(r)

    out.append("## Summary")
    for key in ("CONFIRMED-PRIMITIVE", "LIKELY-PRIMITIVE", "GATED", "HARMLESS", "ERROR", "UNKNOWN"):
        if key in by_overall:
            out.append(f"- **{key}**: {len(by_overall[key])}")
    out.append("")

    out.append("## Per-driver")
    for r in results:
        out.append("")
        out.append(f"### {r.filename}  `{r.sha256[:16]}...`")
        if r.error:
            out.append(f"**Error**: {r.error}")
            continue
        out.append("")
        out.append("```")
        out.append(r.verdict_text.strip())
        out.append("```")
    return "\n".join(out)
