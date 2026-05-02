#!/usr/bin/env python3
"""
LLM-assisted audit for EU AI Act high-risk template prompts.

This script reviews prompt text from high-risk-domain templates with an LLM and
produces structured compliance judgments for standards (I)-(IV) used in the paper.
Default backend is OpenAI Chat Completions with model gpt-5.2; use --backend gemini for Google Gemini.

Usage example (defaults are under repo data/EUAI/; you can omit most flags):

  # 1) Extract prompts only (no API key). Default input: high_risk_templates_641.jsonl
  python llm_high_risk_prompt_audit.py --extract-prompts

  # 2) LLM audit on the extract file. Default input: high_risk_templates_641.prompts_extract.jsonl
  #    Default: OpenAI gpt-5.2 — export OPENAI_API_KEY=... or set _LOCAL_OPENAI_API_KEY.
  #    By default only 5 templates are audited (smoke test). Full batch: --max-items 0
  python llm_high_risk_prompt_audit.py
  # Writes data/EUAI/llm_high_risk_prompt_audit_results.jsonl and *_table8.txt next to it.

  # Re-bucket overall_judgment in an existing audit JSONL (no API; backs up to .jsonl.bak):
  #   python llm_high_risk_prompt_audit.py --normalize-jsonl-output --input data/EUAI/llm_high_risk_prompt_audit_results.jsonl

  # Google Gemini instead: --backend gemini (default model gemini-2.0-flash), e.g. GEMINI_API_KEY
  # Optional: --model <id>  (override if your account uses a different slug)

  Override only when needed: --input, --output, --backend, --model, etc.

API key (first non-empty by backend):
- OpenAI (default): --api-key, OPENAI_API_KEY, _LOCAL_OPENAI_API_KEY
- Gemini: --api-key, GEMINI_API_KEY, _LOCAL_GEMINI_API_KEY
Do not commit a real key to git.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


TARGET_PROMPT_KEYS = {"text", "prompt", "systemMessage", "messages"}

# When --output is omitted, results are written next to --input under this filename.
DEFAULT_AUDIT_OUTPUT_NAME = "llm_high_risk_prompt_audit_results.jsonl"
# When --extract-prompts and --extract-output is omitted: <input_stem>.prompts_extract.jsonl
EXTRACT_OUTPUT_SUFFIX = ".prompts_extract.jsonl"

# Repo layout: this file is n8n/code/pipeline/eu_ai/llm_high_risk_prompt_audit.py
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEFAULT_EUAI_DIR = _REPO_ROOT / "data" / "EUAI"

# -----------------------------------------------------------------------------
# Study defaults — edit here to limit CLI (paths + optional API key for local use)
# -----------------------------------------------------------------------------
DEFAULT_RAW_TEMPLATES = _DEFAULT_EUAI_DIR / ""
DEFAULT_PROMPTS_EXTRACT_INPUT = _DEFAULT_EUAI_DIR / ""

# OpenAI (default backend): `OPENAI_API_KEY` or `--api-key` also work.
_LOCAL_OPENAI_API_KEY = ""
# LLM audit only: when --max-items is omitted, process this many rows (smoke test). Use --max-items 0 for all.
DEFAULT_LLM_AUDIT_MAX_ITEMS = 5
# -----------------------------------------------------------------------------

# Overall audit outcome (paper): two buckets only — no third "uncertain" overall label.
VALID_OVERALL_JUDGMENT_VALUES: frozenset[str] = frozenset(
    ("confirmed_missing_safeguards", "no_clear_issue")
)


def normalize_overall_judgment(raw: str) -> str:
    """Map LLM / legacy labels onto confirmed_missing_safeguards | no_clear_issue."""
    r = (raw or "").strip()
    if r in VALID_OVERALL_JUDGMENT_VALUES:
        return r
    if r == "likely_non_compliant":
        return "confirmed_missing_safeguards"
    if r in (
        "likely_compliant",
        "uncertain",
        "needs_manual_review",
        "unknown",
        "",
    ):
        return "no_clear_issue"
    # Unknown slug → conservative bucket
    return "no_clear_issue"


def apply_overall_judgment_normalization(result: dict[str, Any]) -> None:
    """Normalize overall_judgment in-place on parsed LLM JSON."""
    if "overall_judgment" not in result:
        result["overall_judgment"] = "no_clear_issue"
        return
    result["overall_judgment"] = normalize_overall_judgment(str(result["overall_judgment"]))


EU_AI_ACT_CONTEXT = """
[Annex III high-risk domains]
- Biometric identification
- Education and vocational training
- Employment and workers' management
- Essential private and public services
- Law enforcement
- Migration, asylum and border control
- Administration of justice and democratic processes

[Appendix A legal provisions (verbatim from paper)]
- Article 9(2)(d): The adoption of appropriate and targeted risk management measures designed to address the risks identified.
- Article 10(2)(f): Examination of possible biases likely to affect health/safety, fundamental rights, or lead to discrimination.
- Article 10(2)(g): Appropriate measures to detect, prevent and mitigate possible biases.
- Article 13(1): High-risk AI systems should be sufficiently transparent so deployers can interpret outputs and use them appropriately.
- Article 14(4)(b): Users should remain aware of over-reliance / automation bias and retain human oversight.

[Table 15 keyword families (used by static scan, weak baseline)]
- (I) risk, limitation, disclaimer, warning, no warranty, use at your own risk, not liable, as-is, no guarantee
- (II) bias, discrimination, unfair, fair, equitable, prejudice, stereotyp*, bias mitigation
- (III) interpret, explain, transparency, verify, validate, may be incorrect, confidence, accuracy
- (IV) over-reliance, human oversight, not legal advice, not medical advice, not a substitute, human review, expert review
"""

AUDIT_INSTRUCTION = """
You are a strict compliance reviewer for AI workflow templates.
Task: decide whether this template's prompt text is truly non-compliant, or potentially a false positive from keyword-only static matching.

Important rules:
1) Use legal meaning first (Articles 9/10/13/14), not mere keyword presence.
2) Quote concrete evidence spans from the provided prompt text.
3) If evidence is missing or ambiguous, mark "uncertain" instead of guessing.
4) Be concise, factual, and deterministic.
5) Return ONLY valid JSON following the schema.

Judgment standards:
- I (Art 9(2)(d)): risk/limitation disclosure and targeted cautionary framing.
- II (Art 10(2)(f)(g)): bias/discrimination risk acknowledgement and mitigation intent.
- III (Art 13(1)): transparency/interpretability and guidance for appropriate use/verification.
- IV (Art 14(4)(b)): explicit warning against over-reliance and human oversight expectation.

Status labels per standard:
- "pass": clear and specific evidence exists.
- "fail": missing or materially insufficient.
- "uncertain": cannot reliably judge from available text.

Overall label (exactly two values — no separate "uncertain" overall bucket):
- "confirmed_missing_safeguards": strong evidence that prompt text lacks meaningful safeguards
  aligned with Articles 9/10/13/14 for this template's apparent use (typically >=2 standards fail
  with clear textual evidence, and no offsetting safeguard language).
- "no_clear_issue": safeguards appear adequate from the text, OR evidence is mixed/ambiguous,
  OR you cannot reliably justify "confirmed_missing_safeguards". When in doubt, choose this label.

Return schema:
{
  "overall_judgment": "confirmed_missing_safeguards|no_clear_issue",
  "confidence": "high|medium|low",
  "standards": {
    "I": {"status":"pass|fail|uncertain","reason":"...","evidence":["..."]},
    "II": {"status":"pass|fail|uncertain","reason":"...","evidence":["..."]},
    "III": {"status":"pass|fail|uncertain","reason":"...","evidence":["..."]},
    "IV": {"status":"pass|fail|uncertain","reason":"...","evidence":["..."]}
  },
  "false_positive_risk": "low|medium|high",
  "recommended_fixes": ["...", "..."]
}
"""


@dataclass
class TemplateRecord:
    template_id: str
    name: str
    domains: list[str]
    prompt_text: str
    raw: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM audit for high-risk template prompts.",
        epilog=(
            f"Defaults: --extract-prompts uses {DEFAULT_RAW_TEMPLATES}; "
            f"LLM audit uses {DEFAULT_PROMPTS_EXTRACT_INPUT} (run extract first)."
        ),
    )
    parser.add_argument(
        "--input",
        default=None,
        help=(
            "Input file (.json, .jsonl, .csv). If omitted: with --extract-prompts, "
            f"defaults to {DEFAULT_RAW_TEMPLATES.name}; else LLM audit defaults to "
            f"{DEFAULT_PROMPTS_EXTRACT_INPUT.name} (extract output)."
        ),
    )
    parser.add_argument(
        "--output",
        default="",
        help=(
            f"Output JSONL path (default: same directory as --input / {DEFAULT_AUDIT_OUTPUT_NAME})"
        ),
    )
    parser.add_argument(
        "--summary-output",
        default="",
        help="Optional summary JSON path (default: <output>.summary.json)",
    )
    parser.add_argument(
        "--backend",
        choices=("gemini", "openai"),
        default="openai",
        help="LLM API: OpenAI Chat Completions (default, model gpt-5.2) or google Gemini",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model id (default: gpt-5.2 for openai, gemini-2.0-flash for gemini)",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="API key: for openai (default), OPENAI_API_KEY or _LOCAL_OPENAI_API_KEY; for gemini, GEMINI_API_KEY or _LOCAL_GEMINI_API_KEY",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Process at most N records. Use 0 for all. "
            f"Omitted: all rows for --extract-prompts; {DEFAULT_LLM_AUDIT_MAX_ITEMS} for LLM audit (smoke test)."
        ),
    )
    parser.add_argument("--sleep-seconds", type=float, default=0.2, help="Delay between API calls")
    parser.add_argument("--max-prompt-chars", type=int, default=15000, help="Max chars sent per template")
    parser.add_argument(
        "--no-domain-table",
        action="store_true",
        help="Do not print the Table-8-style domain x (I)-(IV) summary to stdout",
    )
    parser.add_argument(
        "--table-output",
        default="",
        help="Optional path to write the Table-8-style summary as .txt (markdown-friendly plain text)",
    )
    parser.add_argument(
        "--extract-prompts",
        action="store_true",
        help="Only extract prompt text from each input row, write JSONL + summary, then exit (no LLM).",
    )
    parser.add_argument(
        "--extract-output",
        default="",
        help=(
            "Output path for --extract-prompts (default: same directory as --input, "
            f"<input_stem>{EXTRACT_OUTPUT_SUFFIX})"
        ),
    )
    parser.add_argument(
        "--normalize-jsonl-output",
        action="store_true",
        help=(
            "Do not call LLMs: read existing audit JSONL (--input), normalize "
            "overall_judgment to confirmed_missing_safeguards|no_clear_issue, write "
            "--output (default: overwrite input; backup as .bak), refresh .summary.json "
            "and Table-8-style .txt next to output."
        ),
    )
    args = parser.parse_args()
    if args.input is None:
        if args.extract_prompts:
            args.input = str(DEFAULT_RAW_TEMPLATES)
        else:
            args.input = str(DEFAULT_PROMPTS_EXTRACT_INPUT)
    if not str(args.output).strip() and not args.extract_prompts:
        if args.normalize_jsonl_output:
            args.output = args.input
        else:
            input_dir = Path(args.input).expanduser().resolve().parent
            args.output = str(input_dir / DEFAULT_AUDIT_OUTPUT_NAME)
    if args.extract_prompts and not str(args.extract_output).strip():
        inp = Path(args.input).expanduser().resolve()
        args.extract_output = str(inp.parent / f"{inp.stem}{EXTRACT_OUTPUT_SUFFIX}")
    if args.model is None:
        args.model = "gpt-5.2" if args.backend == "openai" else "gemini-2.0-flash"
    if args.max_items is None:
        args.max_items = 0 if args.extract_prompts else DEFAULT_LLM_AUDIT_MAX_ITEMS
    return args


def load_input(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        items: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                items.append(json.loads(line))
        return items

    if suffix == ".json":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Common wrappers
            for key in ("items", "data", "templates", "records"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            return [data]
        raise ValueError("Unsupported JSON structure")

    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]

    raise ValueError(f"Unsupported input format: {suffix}")


def parse_domains(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        if value.startswith("[") and value.endswith("]"):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return [str(v).strip() for v in parsed if str(v).strip()]
            except json.JSONDecodeError:
                pass
        return [s.strip() for s in re.split(r"[;,|/]", value) if s.strip()]
    return [str(value).strip()]


def walk_collect_prompt_fields(node: Any, out: list[str], parent_key: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in TARGET_PROMPT_KEYS:
                if isinstance(value, str):
                    out.append(f"[{key}] {value}")
                elif isinstance(value, list):
                    try:
                        out.append(f"[{key}] {json.dumps(value, ensure_ascii=False)}")
                    except TypeError:
                        out.append(f"[{key}] {str(value)}")
                elif isinstance(value, dict):
                    try:
                        out.append(f"[{key}] {json.dumps(value, ensure_ascii=False)}")
                    except TypeError:
                        out.append(f"[{key}] {str(value)}")
            walk_collect_prompt_fields(value, out, key)
    elif isinstance(node, list):
        for item in node:
            walk_collect_prompt_fields(item, out, parent_key)


def coerce_record(raw: dict[str, Any]) -> TemplateRecord:
    template_id = str(
        raw.get("template_id")
        or raw.get("id")
        or raw.get("workflowId")
        or raw.get("workflow_id")
        or raw.get("uuid")
        or ""
    ).strip()
    if not template_id:
        template_id = f"row_{abs(hash(json.dumps(raw, sort_keys=True, default=str))) % 10**10}"

    name = str(raw.get("name") or raw.get("template_name") or raw.get("title") or "").strip()

    domains = parse_domains(
        raw.get("high_risk_domains")
        or raw.get("domains")
        or raw.get("domain")
        or raw.get("eu_ai_act_domains")
    )

    prompt_candidates: list[str] = []
    for k in ("prompt_text", "prompt", "systemMessage", "messages", "text", "llm_text"):
        if isinstance(raw.get(k), str) and raw[k].strip():
            prompt_candidates.append(f"[{k}] {raw[k].strip()}")

    # Attempt extraction from nested workflow/template JSON
    for blob_key in ("workflow_json", "workflow", "template_json", "json"):
        blob = raw.get(blob_key)
        parsed: Any = None
        if isinstance(blob, dict) or isinstance(blob, list):
            parsed = blob
        elif isinstance(blob, str):
            blob_str = blob.strip()
            if blob_str.startswith("{") or blob_str.startswith("["):
                try:
                    parsed = json.loads(blob_str)
                except json.JSONDecodeError:
                    parsed = None
        if parsed is not None:
            walk_collect_prompt_fields(parsed, prompt_candidates)

    prompt_text = "\n".join(dict.fromkeys([p.strip() for p in prompt_candidates if p.strip()]))
    return TemplateRecord(template_id=template_id, name=name, domains=domains, prompt_text=prompt_text, raw=raw)


def build_user_payload(rec: TemplateRecord, max_chars: int) -> str:
    prompt_text = rec.prompt_text[:max_chars]
    return (
        f"{EU_AI_ACT_CONTEXT}\n\n"
        f"{AUDIT_INSTRUCTION}\n\n"
        f"[Template metadata]\n"
        f"- template_id: {rec.template_id}\n"
        f"- name: {rec.name or '<empty>'}\n"
        f"- high_risk_domains: {rec.domains}\n\n"
        f"[Prompt text to audit]\n{prompt_text}\n"
    )


def call_gemini_json(model: str, api_key: str, prompt: str, retries: int = 4) -> dict[str, Any]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
        },
    }
    payload = json.dumps(body).encode("utf-8")

    for attempt in range(retries + 1):
        try:
            req = Request(
                url=url,
                data=payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            with urlopen(req, timeout=90) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            text = (
                result.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
            )
            if not text:
                raise ValueError(f"Empty Gemini response: {result}")
            return parse_model_json(text)
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            if attempt >= retries:
                raise RuntimeError(f"Gemini call failed after {retries + 1} attempts: {exc}") from exc
            backoff = 2 ** attempt
            time.sleep(backoff)

    raise RuntimeError("Unreachable")


def call_openai_json(model: str, api_key: str, prompt: str, retries: int = 4) -> dict[str, Any]:
    """OpenAI Chat Completions with JSON object mode (same schema as Gemini path)."""
    url = "https://api.openai.com/v1/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {api_key}",
    }

    for attempt in range(retries + 1):
        try:
            req = Request(url=url, data=payload, headers=headers, method="POST")
            with urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            text = (result.get("choices") or [{}])[0].get("message", {}).get("content", "")
            if not text:
                raise ValueError(f"Empty OpenAI response: {result}")
            return parse_model_json(text)
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            if attempt >= retries:
                raise RuntimeError(
                    f"OpenAI call failed after {retries + 1} attempts: {exc}"
                ) from exc
            backoff = 2**attempt
            time.sleep(backoff)

    raise RuntimeError("Unreachable")


def parse_model_json(text: str) -> dict[str, Any]:
    text = text.strip()
    # Remove markdown fences if model returns them unexpectedly.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


# Order aligned with paper Table~\\ref{tab:eu_ai_act_compliance_by_domain} (04-measurement.tex)
TABLE8_DOMAIN_ROW_ORDER: tuple[str, ...] = (
    "Administration of Justice and Democratic Processes",
    "Education and Vocational Training",
    "Employment and Workers Management",
    "Essential Private and Public Services",
    "Migration, Asylum and Border Control",
    "Biometric Identification",
    "Law Enforcement",
)

# Map normalized lowercase labels (as in data / Annex III list) to paper Table~8 row labels
_CANONICAL_DOMAIN: dict[str, str] = {
    "administration of justice and democratic processes": "Administration of Justice and Democratic Processes",
    "biometric identification": "Biometric Identification",
    "education and vocational training": "Education and Vocational Training",
    "employment and workers' management": "Employment and Workers Management",
    "employment and workers management": "Employment and Workers Management",
    "essential private and public services": "Essential Private and Public Services",
    "law enforcement": "Law Enforcement",
    "migration, asylum and border control": "Migration, Asylum and Border Control",
    "migration, asylum, and border control": "Migration, Asylum and Border Control",
}


def _normalize_domain_key(name: str) -> str:
    return " ".join(name.split()).strip()


def canonical_domain_key(dom: str) -> str:
    """Merge variants (casing, apostrophe) into paper Table~8 spelling when known."""
    n = _normalize_domain_key(str(dom))
    if not n:
        return n
    return _CANONICAL_DOMAIN.get(n.lower(), n)


def update_summary(
    summary: dict[str, Any], result: dict[str, Any], rec: TemplateRecord
) -> None:
    summary["processed"] += 1
    overall = normalize_overall_judgment(str(result.get("overall_judgment", "")))
    summary["overall"][overall] = summary["overall"].get(overall, 0) + 1
    for std in ("I", "II", "III", "IV"):
        status = (
            result.get("standards", {})
            .get(std, {})
            .get("status", "unknown")
        )
        summary["standards"][std][status] = summary["standards"][std].get(status, 0) + 1

    domains = rec.domains or []
    if not domains:
        domains = ["(no domain in input)"]
    for dom in domains:
        dom_key = canonical_domain_key(str(dom))
        if not dom_key:
            continue
        if dom_key not in summary["by_domain"]:
            summary["by_domain"][dom_key] = {
                "n": 0,
                "I": {"fail": 0, "pass": 0, "uncertain": 0, "unknown": 0},
                "II": {"fail": 0, "pass": 0, "uncertain": 0, "unknown": 0},
                "III": {"fail": 0, "pass": 0, "uncertain": 0, "unknown": 0},
                "IV": {"fail": 0, "pass": 0, "uncertain": 0, "unknown": 0},
            }
        summary["by_domain"][dom_key]["n"] += 1
        for std in ("I", "II", "III", "IV"):
            status = (
                result.get("standards", {})
                .get(std, {})
                .get("status", "unknown")
            )
            if status not in ("fail", "pass", "uncertain"):
                status = "unknown"
            bucket = summary["by_domain"][dom_key][std]
            bucket[status] = bucket.get(status, 0) + 1  # type: ignore[union-attr]


def _noncompliance_rate_pct(std_counts: dict[str, int]) -> float:
    """Share of 'fail' among pass/fail/uncertain/unknown (Table 8 analog: non-compliance)."""
    n = sum(std_counts.get(s, 0) for s in ("fail", "pass", "uncertain", "unknown"))
    if n == 0:
        return 0.0
    return 100.0 * std_counts.get("fail", 0) / n


def build_table8_style_rows(
    by_domain: dict[str, Any],
) -> list[dict[str, Any]]:
    """One row per domain with I–IV non-compliance % (LLM 'fail' rate)."""
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for dom in TABLE8_DOMAIN_ROW_ORDER:
        if dom in by_domain and dom not in seen:
            seen.add(dom)
            r = by_domain[dom]
            row = {
                "domain": dom,
                "n": r["n"],
                "I_pct": round(_noncompliance_rate_pct(r["I"]), 2),
                "II_pct": round(_noncompliance_rate_pct(r["II"]), 2),
                "III_pct": round(_noncompliance_rate_pct(r["III"]), 2),
                "IV_pct": round(_noncompliance_rate_pct(r["IV"]), 2),
            }
            rows.append(row)
    for dom in sorted(by_domain.keys()):
        if dom in seen:
            continue
        r = by_domain[dom]
        rows.append(
            {
                "domain": dom,
                "n": r["n"],
                "I_pct": round(_noncompliance_rate_pct(r["I"]), 2),
                "II_pct": round(_noncompliance_rate_pct(r["II"]), 2),
                "III_pct": round(_noncompliance_rate_pct(r["III"]), 2),
                "IV_pct": round(_noncompliance_rate_pct(r["IV"]), 2),
            }
        )
    return rows


def format_table8_style_text(
    rows: list[dict[str, Any]],
    title: str = "LLM audit: non-compliance rates by high-risk domain (analog to Table 8)",
) -> str:
    """Plain-text table: Domain + (I)–(IV) %; same layout as paper Table 8."""
    lines: list[str] = [
        title,
        "Non-compliance = share of 'fail' per standard in LLM audit (pass / fail / uncertain).",
        "",
    ]
    colw = 46
    head = f"{'Domain':<{colw}}  {'(I)':>7}  {'(II)':>7}  {'(III)':>7}  {'(IV)':>7}  {'n':>4}"
    lines.append(head)
    lines.append("-" * len(head))
    for r in rows:
        dom = r["domain"]
        if len(dom) > colw:
            dom = dom[: colw - 1] + "…"
        lines.append(
            f"{dom:<{colw}}  {r['I_pct']:6.2f}%  {r['II_pct']:6.2f}%  {r['III_pct']:6.2f}%  {r['IV_pct']:6.2f}%  {r['n']:4d}"
        )
    return "\n".join(lines) + "\n"


def run_normalize_jsonl_audit_output(
    input_path: Path,
    output_path: Path,
    summary_path: Path,
    table_output: str,
    no_domain_table: bool,
) -> int:
    """
    Rewrite audit JSONL with normalized overall_judgment; rebuild summary + table8 text.
    Backs up existing output_path to output_path.bak when overwriting.
    """
    rows_in = load_input(input_path)
    if output_path.resolve() == input_path.resolve():
        bak = output_path.with_suffix(output_path.suffix + ".bak")
        bak.write_bytes(input_path.read_bytes())

    summary: dict[str, Any] = {
        "input": str(input_path),
        "backend": "normalize-jsonl-output",
        "model": "(none)",
        "processed": 0,
        "overall": {},
        "standards": {"I": {}, "II": {}, "III": {}, "IV": {}},
        "by_domain": {},
        "errors": [],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out_f:
        for raw in rows_in:
            audit = raw.get("llm_audit")
            if not isinstance(audit, dict):
                summary["errors"].append(f"{raw.get('template_id', '?')}: missing llm_audit")
                out_f.write(json.dumps(raw, ensure_ascii=False) + "\n")
                continue
            apply_overall_judgment_normalization(audit)
            raw = {**raw, "llm_audit": audit}
            out_f.write(json.dumps(raw, ensure_ascii=False) + "\n")

            rec = TemplateRecord(
                template_id=str(raw.get("template_id", "")),
                name=str(raw.get("name", "")),
                domains=list(raw.get("domains") or []),
                prompt_text="",
                raw={},
            )
            update_summary(summary, audit, rec)

    t8_rows = build_table8_style_rows(summary.get("by_domain", {}))
    summary["table8_style"] = {
        "title": "EU AI Act (LLM audit): non-compliance rates by high-risk domain — analog to "
        "Table 8 (tab:eu_ai_act_compliance_by_domain); static scan uses keyword gaps, here "
        "cells are % with LLM per-standard status 'fail'.",
        "rows": t8_rows,
    }

    with summary_path.open("w", encoding="utf-8") as sf:
        json.dump(summary, sf, ensure_ascii=False, indent=2)

    t8_title = summary["table8_style"]["title"]
    table_text = format_table8_style_text(t8_rows, title=t8_title)
    if not no_domain_table and t8_rows:
        print()
        print(table_text, end="")
    to_path = table_output.strip()
    if not to_path:
        to_path = str(output_path.with_name(f"{output_path.stem}_table8.txt"))
    if to_path:
        table_out = Path(to_path).expanduser().resolve()
        table_out.parent.mkdir(parents=True, exist_ok=True)
        table_out.write_text(table_text, encoding="utf-8")
        print(f"Table-8-style summary: {table_out}")

    print(f"Normalized audit rows: {output_path}")
    if output_path.resolve() == input_path.resolve():
        print(f"Backup of original file: {output_path.with_suffix(output_path.suffix + '.bak')}")
    print(f"Summary: {summary_path}")
    return 0 if not summary["errors"] else 1


def run_extract_prompts(
    input_path: Path,
    extract_path: Path,
    max_items: int,
) -> int:
    """
    For each input row, run coerce_record and write one JSONL line with extracted prompt_text.
    Writes <extract_path>.summary.json with counts and empty-template_id list.
    Returns 0 if all rows have non-empty prompt_text, else 1.
    """
    rows = load_input(input_path)
    if max_items > 0:
        rows = rows[:max_items]

    extract_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = extract_path.parent / f"{extract_path.stem}.summary.json"

    n_empty = 0
    n_non_empty = 0
    empty_ids: list[str] = []

    with extract_path.open("w", encoding="utf-8") as out_f:
        for raw in rows:
            rec = coerce_record(raw)
            empty = not rec.prompt_text.strip()
            if empty:
                n_empty += 1
                empty_ids.append(rec.template_id)
            else:
                n_non_empty += 1
            row = {
                "template_id": rec.template_id,
                "name": rec.name,
                "domains": rec.domains,
                "prompt_text": rec.prompt_text,
                "prompt_char_count": len(rec.prompt_text),
                "extraction_empty": empty,
            }
            out_f.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary: dict[str, Any] = {
        "mode": "extract-prompts",
        "input": str(input_path),
        "output": str(extract_path),
        "n_rows": len(rows),
        "n_non_empty": n_non_empty,
        "n_empty": n_empty,
        "empty_template_ids": empty_ids,
    }
    with summary_path.open("w", encoding="utf-8") as sf:
        json.dump(summary, sf, ensure_ascii=False, indent=2)

    print(f"Extracted prompts: {extract_path} ({n_non_empty} non-empty, {n_empty} empty of {len(rows)})")
    print(f"Extraction summary: {summary_path}")
    if n_empty:
        print(
            f"Warning: {n_empty} row(s) have empty prompt after extraction. See 'empty_template_ids' in summary.",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    args = parse_args()

    if args.normalize_jsonl_output:
        input_path = Path(args.input).expanduser().resolve()
        if not input_path.is_file():
            print(f"ERROR: Input JSONL not found: {input_path}", file=sys.stderr)
            return 2
        output_path = Path(args.output).expanduser().resolve()
        summary_path = (
            Path(args.summary_output).expanduser().resolve()
            if args.summary_output
            else output_path.with_suffix(output_path.suffix + ".summary.json")
        )
        return run_normalize_jsonl_audit_output(
            input_path,
            output_path,
            summary_path,
            args.table_output,
            args.no_domain_table,
        )

    if args.extract_prompts:
        input_path = Path(args.input).expanduser().resolve()
        extract_path = Path(args.extract_output).expanduser().resolve()
        return run_extract_prompts(input_path, extract_path, args.max_items)

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.is_file():
        print(
            f"ERROR: Input file not found: {input_path}\n"
            f"For the default LLM-audit path, run extract first:\n"
            f"  python {Path(__file__).name} --extract-prompts",
            file=sys.stderr,
        )
        return 2

    if args.backend == "openai":
        api_key = args.api_key or os.getenv("OPENAI_API_KEY", "") or _LOCAL_OPENAI_API_KEY
        if not api_key:
            print(
                "ERROR: Missing OpenAI API key. Use --api-key, OPENAI_API_KEY, or set _LOCAL_OPENAI_API_KEY in the script.",
                file=sys.stderr,
            )
            return 2
    else:
        api_key = args.api_key or os.getenv("GEMINI_API_KEY", "") or _LOCAL_GEMINI_API_KEY
        if not api_key:
            print(
                "ERROR: Missing Gemini API key. Use --api-key, GEMINI_API_KEY, or set _LOCAL_GEMINI_API_KEY in the script.",
                file=sys.stderr,
            )
            return 2

    output_path = Path(args.output).expanduser().resolve()
    summary_path = (
        Path(args.summary_output).expanduser().resolve()
        if args.summary_output
        else output_path.with_suffix(output_path.suffix + ".summary.json")
    )

    rows = load_input(input_path)
    if args.max_items > 0:
        rows = rows[: args.max_items]

    summary: dict[str, Any] = {
        "input": str(input_path),
        "backend": args.backend,
        "model": args.model,
        "processed": 0,
        "overall": {},
        "standards": {"I": {}, "II": {}, "III": {}, "IV": {}},
        "by_domain": {},
        "errors": [],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out_f:
        for idx, raw in enumerate(rows, start=1):
            rec = coerce_record(raw)
            if not rec.prompt_text.strip():
                err = f"{rec.template_id}: empty prompt text after extraction"
                summary["errors"].append(err)
                continue

            payload = build_user_payload(rec, args.max_prompt_chars)
            try:
                if args.backend == "openai":
                    result = call_openai_json(args.model, api_key, payload)
                else:
                    result = call_gemini_json(args.model, api_key, payload)
                apply_overall_judgment_normalization(result)
                row = {
                    "template_id": rec.template_id,
                    "name": rec.name,
                    "domains": rec.domains,
                    "llm_audit": result,
                }
                out_f.write(json.dumps(row, ensure_ascii=False) + "\n")
                update_summary(summary, result, rec)
            except Exception as exc:  # noqa: BLE001
                summary["errors"].append(f"{rec.template_id}: {exc}")

            if args.sleep_seconds > 0:
                time.sleep(args.sleep_seconds)

            if idx % 25 == 0:
                print(f"Processed {idx}/{len(rows)} ...", file=sys.stderr)

    t8_rows = build_table8_style_rows(summary.get("by_domain", {}))
    summary["table8_style"] = {
        "title": "EU AI Act (LLM audit): non-compliance rates by high-risk domain — analog to "
        "Table 8 (tab:eu_ai_act_compliance_by_domain); static scan uses keyword gaps, here "
        "cells are % with LLM per-standard status 'fail'.",
        "rows": t8_rows,
    }

    with summary_path.open("w", encoding="utf-8") as sf:
        json.dump(summary, sf, ensure_ascii=False, indent=2)

    t8_title = summary["table8_style"]["title"]
    table_text = format_table8_style_text(t8_rows, title=t8_title)
    if not args.no_domain_table and t8_rows:
        print()
        print(table_text, end="")
    to_path = args.table_output.strip()
    if not to_path:
        to_path = str(output_path.with_name(f"{output_path.stem}_table8.txt"))
    if to_path:
        table_out = Path(to_path).expanduser().resolve()
        table_out.parent.mkdir(parents=True, exist_ok=True)
        table_out.write_text(table_text, encoding="utf-8")
        print(f"Table-8-style summary: {table_out}")

    print(f"Done. Results: {output_path}")
    print(f"Summary: {summary_path}")
    if summary["errors"]:
        print(f"Completed with {len(summary['errors'])} errors. Check summary file.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
