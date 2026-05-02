#!/usr/bin/env python3

import io
import os
import re
import json
import argparse
import tarfile
import zipfile
import shutil
import sys
import tempfile
import gc
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable, Pattern, Match
from datetime import datetime

INPUT_CSV    = "../data/node_fetch_result/n8n_nodes_final_2025-11-15_11-36-26.csv"
OUTPUT_FILE  = "../data/scan_result/scan_report.json"
# When using --packages-txt and no --output, default report path:
DEFAULT_PACKAGES_TXT_OUTPUT = "../data/scan_result/scan_report_community_packages.json"
KEEP_WORKDIR = False
OFFICIAL_N8N_REPO = "https://github.com/n8n-io/n8n"
USER_AGENT   = "n8n-node-audit/5.0-n9-npm"

try:
    import requests
except Exception:
    print("Please install: pip install requests pandas")
    raise


# ---------------------------------------------------------------------------
# Paper taxonomy (N1–N9) + Table 3 node-layer helpers (inlined).
# ---------------------------------------------------------------------------
PAPER_N_ORDER: Tuple[str, ...] = tuple(f"N{i}" for i in range(1, 10))

PAPER_N_RULE_NAME_EN: Dict[str, str] = {
    "N1": "Dynamic Code Execution",
    "N2": "Outbound Data Exfiltration",
    "N3": "File-System Access Risk",
    "N4": "SSRF / Internal Reachability",
    "N5": "Credential Handling Misuse",
    "N6": "Dependency Supply-Chain Risk",
    "N7": "Approved third-party node Non-Compliance",
    "N8": "UI/Output Injection Surface",
    "N9": "Prompt Injection",
}

PAPER_N_CWES: Dict[str, Tuple[str, ...]] = {
    "N1": ("CWE-78", "CWE-94"),
    "N2": ("CWE-201", "CWE-359"),
    "N3": ("CWE-73", "CWE-22"),
    "N4": ("CWE-918",),
    "N5": ("CWE-798", "CWE-532", "CWE-256"),
    "N6": ("CWE-1104", "CWE-1357"),
    "N7": (),
    "N8": ("CWE-79",),
    "N9": ("CWE-74",),
}

PAPER_N_DETECTION_LOGIC: Dict[str, str] = {
    "N1": "Usage of eval, vm, new Function, or child_process.",
    "N2": "Outbound HTTP with data adjacent to files or secrets.",
    "N3": "fs.* on tainted or user-influenced paths.",
    "N4": "Attacker-influenced URLs reaching internal or non-public addresses.",
    "N5": "Env vars or hardcoded secrets near network or file sinks.",
    "N6": "Install scripts, risky package.json dependencies, weak provenance.",
    "N7": "I/O, dependencies, provenance, licensing, documentation vs platform policy.",
    "N8": "HTML/DOM write sinks (e.g. innerHTML, document.write).",
    "N9": "User input passed into LLM or tool prompts.",
}

GRANULAR_TO_PAPER_N: Dict[str, str] = {
    "COMMAND_EXEC": "N1",
    "VM_DYNAMIC": "N1",
    "EVAL_DYNAMIC": "N1",
    "DYNAMIC_REQUIRE": "N1",
    "DYNAMIC_IMPORT": "N1",
    "DYNAMIC_REGEX": "N1",
    "DESERIALIZE": "N1",
    "REMOTE_SHELL_CALL": "N1",
    "EXT_HTTP_CALL": "N2",
    "EXT_HTTP_IMPORT": "N2",
    "EXT_HTTP_DEP": "N7",
    "RAW_NET": "N2",
    "HTTP_PROTO": "N2",
    "SSRF_HOST": "N4",
    "PROXY_TUNNEL": "N2",
    "EXFIL_SDK_CALL": "N2",
    "BROWSER_STEALTH": "N2",
    "FS_CHILD_IMPORT": "N3",
    "PROCESS_ENV": "N5",
    "LOG_SENSITIVE": "N5",
    "DATAURL_JSON": "N5",
    "BINARY_PREPARE": "N5",
    "BINARY_PREPARE_WEAK": "N5",
    "CRED_DECL": "N5",
    "INPUT_SECRET_UNMASKED": "N5",
    "DELETE_RET_BOOL": "N7",
    "OFFICIAL_REPO_IMPERSONATION": "N6",
    "EXT_SUS_DEP": "N7",
    "EXT_SUS_IMPORT": "N7",
    "PKG_JSON_INVALID": "N7",
    "PKG_JSON_MISSING": "N7",
    "LICENSE": "N7",
    "I18N_NON_EN": "N7",
    "VERSION_MISMATCH": "N7",
    "HTML_UNSANITIZED": "N8",
    "PROMPT_INJECTION_CANDIDATE": "N9",
}

BASE_TIER_BY_PAPER_N: Dict[str, str] = {
    "N1": "Sv",
    "N2": "Sv",
    "N3": "Md",
    "N4": "Md",
    "N5": "Sv",
    "N6": "Md",
    "N7": "Md",
    "N8": "Md",
    "N9": "Md",
}

# Table 6 policy themes (third-party packages): prohibited deps, version misalignment,
# duplicate-node API pattern, package.json verification, license, non-English docs.
# Env / file-process access use other paper Ns here (e.g. PROCESS_ENV -> N5, FS_CHILD_IMPORT -> N3).
N7_PLATFORM_POLICY_BY_RULE: Dict[str, str] = {
    "DELETE_RET_BOOL": "duplicate_nodes",
    "EXT_HTTP_DEP": "prohibited_external_dependencies",
    "EXT_SUS_DEP": "prohibited_external_dependencies",
    "EXT_SUS_IMPORT": "prohibited_external_dependencies",
    "VERSION_MISMATCH": "version_misalignment",
    "PKG_JSON_INVALID": "package_source_verification_failure",
    "PKG_JSON_MISSING": "package_source_verification_failure",
    "LICENSE": "non_mit_license_compliance",
    "I18N_NON_EN": "non_english_documentation",
}


def resolve_paper_n_for_rule(rule: Optional[str]) -> str:
    if not rule:
        return "N7"
    return GRANULAR_TO_PAPER_N.get(rule, "N7")


def paper_n_from_finding(entry: Dict[str, Any], rule: Optional[str]) -> str:
    pn = entry.get("paper_n")
    if isinstance(pn, str) and pn.startswith("N") and pn[1:].isdigit():
        return pn
    return resolve_paper_n_for_rule(rule)


def attach_paper_n_to_finding(entry: Dict[str, Any], rule: str) -> None:
    pn = resolve_paper_n_for_rule(rule)
    entry["paper_n"] = pn
    if pn == "N7":
        pp = N7_PLATFORM_POLICY_BY_RULE.get(rule)
        if pp:
            entry["n7_platform_policy"] = pp


def _slug_family(name: str) -> str:
    return (
        name.lower()
        .replace(" / ", "_")
        .replace("/", "_")
        .replace(" ", "_")
    )


def attach_node_layer_table3_to_finding(entry: Dict[str, Any], rule: str) -> None:
    pn = paper_n_from_finding(entry, rule)
    name = PAPER_N_RULE_NAME_EN.get(pn, "")
    tier = BASE_TIER_BY_PAPER_N.get(pn, "Md")
    cwes = list(PAPER_N_CWES.get(pn, ()))
    logic = PAPER_N_DETECTION_LOGIC.get(pn, "")
    entry["node_layer_rule_id"] = pn
    entry["node_layer_rule_name"] = name
    entry["node_layer_severity_tier"] = tier
    entry["node_layer_cwes"] = cwes
    entry["node_layer_detection_logic"] = logic
    entry["n9_rule_id"] = pn
    entry["n9_family"] = _slug_family(name) if name else None


def node_layer_rule_catalog() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for nid in PAPER_N_ORDER:
        out.append(
            {
                "id": nid,
                "rule": PAPER_N_RULE_NAME_EN.get(nid, ""),
                "severity_tier": BASE_TIER_BY_PAPER_N.get(nid, "Md"),
                "cwes": list(PAPER_N_CWES.get(nid, ())),
                "detection_logic": PAPER_N_DETECTION_LOGIC.get(nid, ""),
            }
        )
    return out


# ---------------------------------------------------------------------------
# §4 labeling (tier / confidence / evidence); self-contained in this file.
# Optional paper_m on a finding adds tier_m when present (Paper M1–M9 table).
# ---------------------------------------------------------------------------
TE_STRUCT_NOT_COMPUTED_NOTE = (
    "Structural exposure TE^struct was not computed in this pipeline run; field te_struct is null."
)

BASE_TIER_BY_PAPER_M: Dict[str, str] = {
    "M1": "Sv",
    "M2": "Sv",
    "M3": "Md",
    "M4": "Md",
    "M5": "Md",
    "M6": "Md",
    "M7": "Md",
    "M8": "Sv",
    "M9": "Sv",
}


def _label_non_empty(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return len(v.strip()) > 0
    if isinstance(v, (list, dict)):
        return len(v) > 0
    return True


def tier_from_paper_m(paper_m: str) -> Optional[str]:
    return BASE_TIER_BY_PAPER_M.get(paper_m)


def static_evidence_score(finding: Dict[str, Any]) -> int:
    """Count static evidential signals (0–6): file, line_*, match_lines, matched_text, code_snippet, message, rule."""
    score = 0
    if _label_non_empty(finding.get("file")):
        score += 1
    if finding.get("line_start") is not None or finding.get("line_end") is not None:
        score += 1
    if _label_non_empty(finding.get("match_lines")):
        score += 1
    if _label_non_empty(finding.get("matched_text")):
        score += 1
    if _label_non_empty(finding.get("code_snippet")):
        score += 1
    if _label_non_empty(finding.get("message")):
        score += 1
    if _label_non_empty(finding.get("rule")):
        score += 1
    return min(score, 6)


def confidence_from_evidence(score: int) -> int:
    """1 = Uncertain, 2 = Probable (score >= 4 → 2, else 1)."""
    return 2 if score >= 4 else 1


def tier_from_paper_n(paper_n: str) -> str:
    return BASE_TIER_BY_PAPER_N.get(paper_n, "Md")


def label_finding(
    finding: Dict[str, Any],
    *,
    rule: Optional[str] = None,
    npm_package: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enriched labels for one finding. Primary severity tier follows paper_n (npm scanner axis).
    Optional paper_m on the finding adds tier_m when present.
    """
    r = rule if rule is not None else finding.get("rule")
    paper_n = paper_n_from_finding(finding, str(r) if r else None)
    tier_n = tier_from_paper_n(paper_n)

    pm_raw = finding.get("paper_m")
    paper_m: Optional[str] = None
    tier_m: Optional[str] = None
    if isinstance(pm_raw, str) and pm_raw.startswith("M") and pm_raw[1:].isdigit():
        paper_m = pm_raw
        tier_m = tier_from_paper_m(paper_m)

    ev = static_evidence_score(finding)
    conf = confidence_from_evidence(ev)

    te_struct = finding.get("te_struct")
    if te_struct is None and "te_struct" not in finding:
        te_struct = None

    reasoning_parts = [
        f"paper_n={paper_n}→tier {tier_n}",
    ]
    if paper_m:
        reasoning_parts.append(f"paper_m={paper_m}→tier_m {tier_m}")
    reasoning_parts.append(f"confidence={conf} (evidence_score={ev}/6)")
    if te_struct is None:
        reasoning_parts.append("te_struct=null")

    out: Dict[str, Any] = {
        "npm_package": npm_package,
        "rule": r,
        "paper_n": paper_n,
        "tier": tier_n,
        "tier_n": tier_n,
        "scanner_severity": finding.get("severity"),
        "confidence": conf,
        "confidence_label": "Probable" if conf == 2 else "Uncertain",
        "evidence_score": ev,
        "te_struct": te_struct,
    }
    if paper_m:
        out["paper_m"] = paper_m
        out["tier_m"] = tier_m
    if te_struct is None:
        out["te_struct_note"] = TE_STRUCT_NOT_COMPUTED_NOTE
    out["reasoning"] = "; ".join(reasoning_parts)
    return out


def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def http_get(
    url: str,
    *,
    method: str = "GET",
    timeout: int = 30,
    headers: Optional[Dict[str, str]] = None,
    max_retry: int = 2,
    backoff: float = 1.5,
) -> requests.Response:
    hs = {"User-Agent": USER_AGENT}
    if headers:
        hs.update(headers)

    last_exc = None
    for attempt in range(max_retry):
        try:
            if method.upper() == "HEAD":
                r = requests.head(url, headers=hs, timeout=timeout, allow_redirects=True)
            else:
                r = requests.get(url, headers=hs, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504):
                import time
                time.sleep((backoff ** attempt) * 0.6 + 0.4)
                continue
            return r
        except Exception as e:
            last_exc = e
            import time
            time.sleep((backoff ** attempt) * 0.6 + 0.4)
    if last_exc:
        raise last_exc
    raise RuntimeError(f"{method} failed: {url}")


RULE_CATEGORY = {
    "COMMAND_EXEC": "CODE_EXEC",
    "VM_DYNAMIC": "CODE_EXEC",
    "EVAL_DYNAMIC": "CODE_EXEC",
    "DYNAMIC_REQUIRE": "CODE_EXEC",
    "DYNAMIC_IMPORT": "CODE_EXEC",
    "DYNAMIC_REGEX": "CODE_EXEC",
    "DESERIALIZE": "CODE_EXEC",
    "EXT_HTTP_CALL": "NET_RISK",
    "EXT_HTTP_IMPORT": "NET_RISK",
    "EXT_HTTP_DEP": "NET_RISK",
    "RAW_NET": "NET_RISK",
    "HTTP_PROTO": "NET_RISK",
    "SSRF_HOST": "NET_RISK",
    "PROXY_TUNNEL": "NET_RISK",
    "EXFIL_SDK_CALL": "NET_RISK",
    "REMOTE_SHELL_CALL": "NET_RISK",
    "EXT_SUS_DEP": "SUSPICIOUS_IMPORT",
    "EXT_SUS_IMPORT": "SUSPICIOUS_IMPORT",
    "BROWSER_STEALTH": "SUSPICIOUS_IMPORT",
    "ENV_FS": "DATA_PRIVACY",
    "PROCESS_ENV": "DATA_PRIVACY",
    "FS_CHILD_IMPORT": "DATA_PRIVACY",
    "LOG_SENSITIVE": "DATA_PRIVACY",
    "DATAURL_JSON": "DATA_PRIVACY",
    "BINARY_PREPARE": "DATA_PRIVACY",
    "BINARY_PREPARE_WEAK": "DATA_PRIVACY",
    "DELETE_RET_BOOL": "DATA_PRIVACY",
    "CRED_DECL": "DATA_PRIVACY",
    "INPUT_SECRET_UNMASKED": "DATA_PRIVACY",
    "HTML_UNSANITIZED": "HTML_XSS",
    "PROMPT_INJECTION_CANDIDATE": "PROMPT_INJECTION",
    "LICENSE": "CONFIG",
    "PKG_JSON_INVALID": "CONFIG",
    "PKG_JSON_MISSING": "CONFIG",
    "I18N_NON_EN": "CONFIG",

    "OFFICIAL_REPO_IMPERSONATION": "SUPPLYCHAIN",
    "VERSION_MISMATCH": "SUPPLYCHAIN",
}


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for e in findings:
        key = (
            e.get("rule"),
            e.get("file"),
            e.get("message"),
            e.get("npm_name"),
            e.get("line_start"),
            e.get("line_end"),
            tuple(e.get("match_lines") or ()),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


PROCESS_ENV_RE = re.compile(r"\bprocess\.env\b")
FS_CHILD_IMPORT_RE = re.compile(
    r"^\s*import\s+(?!type\b).*from\s+['\"]fs['\"]"
    r"|require\(\s*['\"]fs['\"]\s*\)"
    r"|require\(\s*['\"]child_process['\"]\s*\)",
    re.M,
)
HTTP_PROTO_RE = re.compile(r"http://", re.I)
SSRF_HOST_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)",
    re.I,
)
EVAL_CALL_RE = re.compile(r"\beval\s*\(")
NEW_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(")
CRED_DECL_RE = re.compile(r"credentials\s*:\s*\[\s*{[^}]*name\s*:\s*['\"]([^'\"]+)['\"]", re.M)
DATA_URL_RE = re.compile(r"toDataURL\s*\(")
JSON_DATA_RETURN_RE = re.compile(r"\.json\s*:\s*{[^}]*data", re.M | re.S)
BINARY_PROP_RE = re.compile(r"\bbinary\s*:\s*{", re.M)
RAW_NET_IMPORT_RE = re.compile(
    r"(?:import\s+[^'\";]*\s+from\s+['\"](?:(?:node:)?(?:http|https|net))['\"])|"
    r"(?:require\(\s*['\"](?:(?:node:)?(?:http|https|net))['\"]\s*\))",
    re.I | re.M,
)

MIT_LICENSE_RE = re.compile(r"mit", re.I)

IGNORE_DIRS = {
    "node_modules",
    "dist-tests",
    "build-tests",
    ".git",
    "coverage",
    "__tests__",
    "__mocks__",
}


SCANNABLE_EXTENSIONS = {

    ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",

    ".json",

    ".html", ".hbs", ".ejs", ".pug",
}

UI_TEXT_KEYS = (
    "placeholder",
    "default",
    "example",
    "examples",
    "hint",
    "help",
    "tooltip",
    "sample",
    "description",
    "displayName",
)
UI_KEY_RE = re.compile(rf"\b({'|'.join(map(re.escape, UI_TEXT_KEYS))})\s*:\s*['\"`]", re.I)
UI_VALUE_QUOTED_RE = re.compile(
    rf"\b({'|'.join(map(re.escape, UI_TEXT_KEYS))})\s*:\s*(['\"])(?P<val>.*?)(?<!\\)\2",
    re.S | re.I,
)
UI_VALUE_TPL_RE = re.compile(
    rf"\b({'|'.join(map(re.escape, UI_TEXT_KEYS))})\s*:\s*`(?P<val>.*?)`",
    re.S | re.I,
)
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")

HTML_RENDER_PATTERNS = [
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"dangerouslySetInnerHTML", re.I),
    re.compile(r"\bres\.send\s*\(", re.I),
    re.compile(r"\bres\.render\s*\(", re.I),
    re.compile(r"\breturn\s+[`'\"]\s*<", re.I),
    re.compile(r"\bdocument\.write\s*\(", re.I),
]
HTML_SANITIZER_INDICATORS = [
    "sanitizeHtml(",
    "DOMPurify",
    "xss(",
    "sanitize(",
    "filterXSS",
    "dompurify",
]

COMMAND_EXEC_RE = re.compile(
    r"\bchild_process\.(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(",
    re.I,
)
VM_DYNAMIC_RE = re.compile(r"\bvm\.(runInNewContext|runInThisContext|Script)\b", re.I)
REQUIRE_VAR_RE = re.compile(r"require\s*\(\s*[A-Za-z_$][\w$]*\s*\)", re.I)
REQUIRE_CONCAT_RE = re.compile(r"require\s*\(\s*[^)\"']*\+[^)]+\)", re.I)
IMPORT_DYNAMIC_RE = re.compile(r"\bimport\(\s*[^)]+?\s*\)", re.I)
EXT_HTTP_CALL_RE = re.compile(
    r"\b(fetch|axios|request|got|superagent)\s*\(|\bhttp\.request\s*\(|\bhttps\.request\s*\(",
    re.I,
)
DYNAMIC_REGEX_RE = re.compile(r"\bnew\s+RegExp\s*\(", re.I)
SETTIME_STRING_RE = re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*(['\"])", re.I)
YAML_LOAD_RE = re.compile(r"\byaml\.load\b", re.I)

BINARY_HAND_ROLL_RE = re.compile(
    r"(toString\(\s*['\"]base64['\"]\s*\)|Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]\s*\)|data:\w+\/[\w.+-]+;base64,)",
    re.I,
)
BINARY_PROP_NAME_RE = re.compile(r"\bbinary(PropertyName)?\b", re.I)
PREPARE_BINARY_CALL_RE = re.compile(r"\bprepareBinaryData\s*\(", re.I)
OP_DELETE_HINT_RE = re.compile(
    r"\b(operation|resource|method)\s*:\s*['\"](delete|remove|destroy)[\"']",
    re.I,
)
RET_BOOL_DELETED_ARR_RE = re.compile(
    r"return\s+\[\s*{\s*['\"]deleted['\"]\s*:\s*(true|false)\s*}\s*\]",
    re.S | re.I,
)

SECRET_FIELD_NAME_RE = re.compile(
    r"\b(name|displayName)\s*:\s*['\"]\s*(?P<key>(api[_-]?key|apikey|api key|token|access[_-]?token|bearer|password|pass|secret|client[_-]?secret|private[_-]?key|auth|authorization|cookie))\s*['\"]",
    re.I,
)
TYPEOPTIONS_PASSWORD_TRUE_RE = re.compile(
    r"typeOptions\s*:\s*{[^}]*\bpassword\s*:\s*true\b[^}]*}",
    re.S | re.I,
)
ALT_MASK_HINT_RE = re.compile(
    r"(inputType\s*:\s*['\"]password['\"]|ui\s*:\s*{[^}]*\bpassword\b)",
    re.S | re.I,
)

SUS_FAMILIES = {
    "stealth": {
        "modules": {"puppeteer-extra-plugin-stealth", "puppeteer-extra", "@extra/stealth"},
    },
    "captcha": {
        "modules": {
            "2captcha",
            "node-2captcha",
            "anticaptcha",
            "anti-captcha",
            "capsolver",
            "hcaptcha-solver",
            "deathbycaptcha",
        },
    },
    "tunnel_proxy": {
        "modules": {
            "proxy-chain",
            "socks-proxy-agent",
            "https-proxy-agent",
            "http-proxy-agent",
            "tunnel",
            "tunnel-agent",
            "ngrok",
            "localtunnel",
            "node-tor",
            "tor-request",
        },
    },
    "remote_shell": {
        "modules": {"node-pty", "pty.js", "ssh2", "shelljs", "ws-shell", "wetty"},
    },
    "exfil_sdk": {
        "modules": {
            "@sentry/node",
            "sentry",
            "mixpanel",
            "analytics-node",
            "@segment/analytics-node",
            "amplitude",
            "rollbar",
            "bugsnag",
        },
    },
}

EXFIL_CALL_HINT_RE = re.compile(
    r"\b(Sentry\.capture|mixpanel\.(track|people)|analytics\.)",
    re.I,
)
REMOTE_SHELL_HINT_RE = re.compile(
    r"\b(node-pty|pty\.js|ssh2|spawn\(\s*['\"]sh|spawn\(\s*['\"]bash)",
    re.I,
)

# N9: LLM / chat API surface + n8n getNodeParameter keys that typically feed model text (static candidate).
LLM_API_SURFACE_RE = re.compile(
    r"(?is)\b(?:"
    r"openai|@openai/|anthropic|@anthropic-ai/|ollama|@langchain|langchain|"
    r"ChatOpenAI|ChatAnthropic|AzureOpenAI|GoogleGenerativeAI|GenerativeModel|"
    r"createChatCompletion|chat\.completions|\.messages\.|client\.chat|bedrock|"
    r"cohere|mistral|together\.ai|replicate|huggingface|@google/generative-ai|"
    r"google\.generativeai|VertexAI|ai\.google"
    r")\b",
)
GET_NODE_PARAMETER_KEY_RE = re.compile(
    r"getNodeParameter\s*\(\s*['\"](?P<key>[^'\"]+)['\"]",
    re.M,
)
# Keys that are usually not model-bound text (reduce obvious false positives)
_PROMPT_KEY_DENYLIST = frozenset(
    {
        "operation",
        "resource",
        "model",
        "models",
        "version",
        "baseUrl",
        "url",
        "endpoint",
        "authentication",
    }
)


def _node_parameter_key_suggests_llm_prompt(key: str) -> bool:
    k = key.strip().lower()
    if not k or k in _PROMPT_KEY_DENYLIST:
        return False
    needles = (
        "prompt",
        "message",
        "messages",
        "system",
        "instruction",
        "chat",
        "query",
        "completion",
        "user",
        "assistant",
        "input",
        "context",
        "text",
    )
    return any(n in k for n in needles)


def get_comment_spans_js(text: str) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    i, n = 0, len(text)
    NORMAL, BLOCK_COMMENT, STR_S, STR_D, TPL, TPL_EXPR = range(6)
    state = NORMAL
    stack = []
    block_start = -1
    while i < n:
        ch = text[i]
        if state == NORMAL:
            if ch == "/":
                if i + 1 < n and text[i + 1] == "/":
                    start = i
                    i += 2
                    while i < n and text[i] != "\n":
                        i += 1
                    spans.append((start, i))
                elif i + 1 < n and text[i + 1] == "*":
                    block_start = i
                    i += 2
                    state = BLOCK_COMMENT
                else:
                    i += 1
            elif ch == "'":
                i += 1
                state = STR_S
            elif ch == '"':
                i += 1
                state = STR_D
            elif ch == "`":
                i += 1
                state = TPL
            else:
                i += 1
        elif state == BLOCK_COMMENT:
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                i += 2
                spans.append((block_start, i))
                state = NORMAL
            else:
                i += 1
        elif state == STR_S:
            if ch == "\\":
                i += 2
            elif ch == "'":
                i += 1
                state = NORMAL
            else:
                i += 1
        elif state == STR_D:
            if ch == "\\":
                i += 2
            elif ch == '"':
                i += 1
                state = NORMAL
            else:
                i += 1
        elif state == TPL:
            if ch == "\\":
                i += 2
            elif ch == "`":
                i += 1
                state = NORMAL
            elif ch == "$" and i + 1 < n and text[i + 1] == "{":
                i += 2
                stack.append("TPL_EXPR")
                state = TPL_EXPR
            else:
                i += 1
        elif state == TPL_EXPR:
            if ch in "'\"`":
                q = ch
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                    elif text[j] == q:
                        j += 1
                        break
                    else:
                        j += 1
                i = j
            elif ch == "/":
                if i + 1 < n and text[i + 1] == "/":
                    i += 2
                    while i < n and text[i] != "\n":
                        i += 1
                elif i + 1 < n and text[i + 1] == "*":
                    i += 2
                    while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                        i += 1
                    i = min(i + 2, n)
                else:
                    i += 1
            elif ch == "}":
                i += 1
                if stack:
                    stack.pop()
                if not stack:
                    state = TPL
            else:
                i += 1
    return spans


def is_in_spans(pos: int, spans: List[Tuple[int, int]]) -> bool:
    for s, e in spans:
        if s <= pos < e:
            return True
    return False


def finditer_nocomment(
    regex: Pattern[str], text: str, spans: List[Tuple[int, int]]
) -> Iterable[Match[str]]:
    for m in regex.finditer(text):
        if not is_in_spans(m.start(), spans):
            yield m


def build_line_index(s: str) -> List[int]:
    idx = [0]
    for m in re.finditer(r"\n", s):
        idx.append(m.end())
    return idx


def pos_to_line(line_index: List[int], pos: int) -> int:
    lo, hi = 0, len(line_index) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if line_index[mid] <= pos:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi + 1


def extract_snippet(
    text: str, span: Tuple[int, int], before: int = 3, after: int = 3
) -> Dict[str, Any]:
    start, end = span
    line_idx = build_line_index(text)
    start_line = pos_to_line(line_idx, start)
    end_line = pos_to_line(line_idx, end)
    total = len(line_idx)
    sline = max(1, start_line - before)
    eline = min(total, end_line + after)
    cstart = line_idx[sline - 1]
    cend = line_idx[eline] - 1 if eline < total else len(text)
    return {
        "snippet": text[cstart:cend],
        "line_start": sline,
        "line_end": eline,
        "match_lines": [start_line, end_line],
    }


def add_finding(
    findings: List[Dict[str, Any]],
    severity: str,
    rule: str,
    rel: str,
    message: str,
    *,
    pkg: Optional[str] = None,
    text: Optional[str] = None,
    span: Optional[Tuple[int, int]] = None,
    matched_text: Optional[str] = None,
):
    entry: Dict[str, Any] = {
        "severity": severity,
        "rule": rule,
        "file": rel,
        "message": message,
    }
    if pkg:
        entry["npm_name"] = pkg
    cat = RULE_CATEGORY.get(rule)
    if cat:
        entry["category"] = cat
    if text is not None and span is not None:
        snip = extract_snippet(text, span)
        entry.update(
            {
                "line_start": snip["line_start"],
                "line_end": snip["line_end"],
                "match_lines": snip["match_lines"],
                "matched_text": matched_text
                if matched_text is not None
                else text[span[0] : span[1]],
                "code_snippet": snip["snippet"],
            }
        )
    elif matched_text is not None:
        entry["matched_text"] = matched_text
    attach_paper_n_to_finding(entry, rule)
    attach_node_layer_table3_to_finding(entry, rule)
    findings.append(entry)



def iter_source_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.is_file():
            if p.suffix.lower() in SCANNABLE_EXTENSIONS:
                yield p


IMPORT_PATTERNS = [
    re.compile(r"""import\s+[^'"]*\s+from\s+['"](?P<mod>[^'"]+)['"]""", re.I),
    re.compile(r"""import\s*\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""", re.I),
    re.compile(r"""require\s*\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""", re.I),
]


def iter_imported_modules(
    text: str, comment_spans: List[Tuple[int, int]]
) -> List[str]:
    mods: List[str] = []
    for rx in IMPORT_PATTERNS:
        for m in rx.finditer(text):
            if is_in_spans(m.start(), comment_spans):
                continue
            base = normalize_module_base(m.group("mod"))
            if base:
                mods.append(base)
    return mods


def _is_within_directory(directory: Path, target: Path) -> bool:
    try:
        directory = directory.resolve()
        target = target.resolve()
    except Exception:
        return False
    return str(target).startswith(str(directory) + os.sep)


def extract_tgz_to_dir(tgz_bytes: bytes, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:gz") as tf:
        members = []
        for m in tf.getmembers():
            target_path = dest_dir / m.name
            if not _is_within_directory(dest_dir, target_path):
                continue
            if m.isdir():
                m.mode = (m.mode | 0o755) & 0o777
            else:
                m.mode = (m.mode | 0o644) & 0o777
            members.append(m)
        tf.extractall(dest_dir, members=members)

    for p in dest_dir.rglob("*"):
        try:
            if p.is_dir():
                p.chmod((p.stat().st_mode | 0o755) & 0o777)
            else:
                p.chmod((p.stat().st_mode | 0o644) & 0o777)
        except Exception:
            pass
    subs = [p for p in dest_dir.iterdir() if p.is_dir()]
    return subs[0] if subs else dest_dir


def normalize_module_base(spec: str) -> str:
    if not spec:
        return ""
    s = spec.strip()
    if s.startswith("node:"):
        s = s[5:]
    s = re.split(r"[?#]", s, 1)[0]
    if s.startswith("@"):
        parts = s.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else s
    else:
        return s.split("/", 1)[0]


def is_tooling_module(mod_base: str) -> bool:
    mb = mod_base.lower()
    if mb.startswith("@types/"):
        return True
    prefixes = (
        "@types/",
        "eslint",
        "@eslint",
        "prettier",
        "@prettier",
        "ts-node",
        "typescript",
        "tslib",
        "babel",
        "@babel",
        "rollup",
        "webpack",
        "vite",
        "esbuild",
        "swc",
        "@swc",
        "jest",
        "mocha",
        "vitest",
    )
    return any(mb.startswith(pref) for pref in prefixes)


def is_networky_module_name(mod_base: str) -> Tuple[bool, str]:
    mb = mod_base.lower()
    for pref in ("http", "https", "ws", "socket", "net", "tls"):
        if mb.startswith(pref):
            return True, f"name_prefix:{pref}"
    for kw in (
        "http",
        "https",
        "fetch",
        "request",
        "undici",
        "ws",
        "websocket",
        "socket",
        "net",
        "tls",
        "redis",
        "mysql",
        "pg",
        "postgres",
        "mongo",
        "mongodb",
        "mssql",
        "ftp",
        "sftp",
        "smtp",
        "imap",
        "pop3",
        "s3",
        "oss",
        "minio",
        "grpc",
        "mqtt",
        "kafka",
    ):
        if kw in mb:
            return True, f"name_keyword:{kw}"
    return False, ""


def load_rows_from_csv(path: str) -> List[Dict[str, str]]:
    import pandas as pd

    df = pd.read_csv(path)
    if "name" not in df.columns:
        raise ValueError("CSV must have column 'name'")
    if "repository_url" not in df.columns:
        raise ValueError("CSV must have column 'repository_url'")
    rows: List[Dict[str, str]] = []
    for _, r in df.iterrows():
        rows.append(
            {
                "name": str(r.get("name", "")).strip(),
                "repository_url": str(r.get("repository_url", "")).strip(),
            }
        )
    return rows


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def resolve_scan_path(p: str) -> Path:
    path = Path(p)
    if path.is_absolute():
        return path
    return (_script_dir() / path).resolve()


def load_rows_from_package_txt(path: str) -> List[Dict[str, str]]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"package list not found: {path}")
    rows: List[Dict[str, str]] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        rows.append({"name": name, "repository_url": ""})
    if not rows:
        raise ValueError(f"no package names in {path}")
    return rows


def should_ignore_as_ui_text(text: str, pos: int, rel: str) -> bool:
    window_left = max(0, pos - 300)
    window_right = min(len(text), pos + 300)
    window = text[window_left:window_right]
    if not UI_KEY_RE.search(window):
        return False
    rel_pos = pos - window_left
    q1_pos = max(window.rfind('"', 0, rel_pos), window.rfind("'", 0, rel_pos))
    if q1_pos == -1:
        return False
    quote_char = window[q1_pos]
    q2_pos = window.find(quote_char, q1_pos + 1)
    if q2_pos == -1:
        return False
    return q1_pos < rel_pos < q2_pos


def scan_tree(root_dir: str, npm_name_for_pkg: Optional[str]) -> Dict[str, Any]:
    root = Path(root_dir)
    findings: List[Dict[str, Any]] = []
    dep_items: List[Dict[str, Any]] = []

    pkg_path = root / "package.json"
    pkg_json: Dict[str, Any] = {}
    pkg_name = None
    pkg_version = None

    # ---- package.json ----
    if pkg_path.exists():
        try:
            try:
                pkg_json = json.loads(
                    pkg_path.read_text(encoding="utf-8", errors="ignore")
                )
            except PermissionError:
                pkg_path.chmod((pkg_path.stat().st_mode | 0o644) & 0o777)
                pkg_json = json.loads(
                    pkg_path.read_text(encoding="utf-8", errors="ignore")
                )
            pkg_name = pkg_json.get("name")
            pkg_version = pkg_json.get("version")
        except Exception:
            add_finding(
                findings,
                "error",
                "PKG_JSON_INVALID",
                "package.json",
                "package.json parse failed",
                pkg=npm_name_for_pkg,
            )
    else:
        add_finding(
            findings,
            "warn",
            "PKG_JSON_MISSING",
            "package.json",
            "package.json missing",
            pkg=npm_name_for_pkg,
        )

    if pkg_json:
        license_field = pkg_json.get("license") or pkg_json.get("licenses")
        if (not license_field) or (
            isinstance(license_field, str)
            and not MIT_LICENSE_RE.search(license_field or "")
        ):
            add_finding(
                findings,
                "warn",
                "LICENSE",
                "package.json",
                "License not MIT or missing",
                pkg=npm_name_for_pkg,
            )

        buckets = {
            "dependencies": pkg_json.get("dependencies") or {},
            "peerDependencies": pkg_json.get("peerDependencies") or {},
            "optionalDependencies": pkg_json.get("optionalDependencies") or {},
            "devDependencies": pkg_json.get("devDependencies") or {},
        }
        for kind, deps in buckets.items():
            for spec, ver in deps.items():
                base = normalize_module_base(spec)
                tooling = is_tooling_module(base)
                networky, why = is_networky_module_name(base)
                dep_items.append(
                    {
                        "package": npm_name_for_pkg or (pkg_name or ""),
                        "module": base,
                        "full_spec": spec,
                        "version_spec": ver,
                        "dep_kind": kind,
                        "is_tooling": "yes" if tooling else "no",
                        "is_network_suspect": "yes" if (networky and not tooling) else "no",
                        "reason": (why if networky else ("ignored_tooling" if tooling else "")),
                    }
                )

                if networky and not tooling:
                    sev = (
                        "error"
                        if kind in ("dependencies", "optionalDependencies")
                        else "warn"
                    )
                    add_finding(
                        findings,
                        sev,
                        "EXT_HTTP_DEP",
                        "package.json",
                        f"{kind} includes network-capable dep: {base} ({why})",
                        pkg=npm_name_for_pkg,
                    )

                for fam, cfg in SUS_FAMILIES.items():
                    if base in cfg["modules"]:
                        if fam == "tunnel_proxy":
                            add_finding(
                                findings,
                                "warn",
                                "PROXY_TUNNEL",
                                "package.json",
                                f"{kind} includes proxy/tunnel dep: {base}",
                                pkg=npm_name_for_pkg,
                                matched_text=base,
                            )
                        elif fam == "remote_shell":
                            add_finding(
                                findings,
                                "error",
                                "REMOTE_SHELL_CALL",
                                "package.json",
                                f"{kind} includes remote shell dep: {base}",
                                pkg=npm_name_for_pkg,
                                matched_text=base,
                            )
                        elif fam == "exfil_sdk":
                            add_finding(
                                findings,
                                "warn",
                                "EXFIL_SDK_CALL",
                                "package.json",
                                f"{kind} includes telemetry/exfil SDK: {base}",
                                pkg=npm_name_for_pkg,
                                matched_text=base,
                            )
                        else:  # stealth/captcha
                            add_finding(
                                findings,
                                "error",
                                "EXT_SUS_DEP",
                                "package.json",
                                f"{kind} includes suspicious dep: {base}",
                                pkg=npm_name_for_pkg,
                                matched_text=base,
                            )

    js_like_exts = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
    files_scanned = 0


    for fpath in iter_source_files(root):
        files_scanned += 1
        rel = str(fpath.relative_to(root))

        try:
            txt = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not txt:
            continue

        ext = fpath.suffix.lower()
        if ext in js_like_exts:
            comment_spans = get_comment_spans_js(txt)
        else:
            comment_spans = []

        def matches_filtered(regex: Pattern[str]):
            for m in finditer_nocomment(regex, txt, comment_spans):
                if regex in (HTTP_PROTO_RE, SSRF_HOST_PATTERNS):
                    if should_ignore_as_ui_text(txt, m.start(), rel):
                        continue
                yield m


        for m in matches_filtered(PROCESS_ENV_RE):
            add_finding(
                findings,
                "error",
                "PROCESS_ENV",
                rel,
                "process.env usage",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(FS_CHILD_IMPORT_RE):
            add_finding(
                findings,
                "error",
                "FS_CHILD_IMPORT",
                rel,
                "fs/child_process import",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(RAW_NET_IMPORT_RE):
            add_finding(
                findings,
                "error",
                "RAW_NET",
                rel,
                "Raw http/https/net import",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(HTTP_PROTO_RE):
            add_finding(
                findings,
                "error",
                "HTTP_PROTO",
                rel,
                "http:// detected",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(SSRF_HOST_PATTERNS):
            add_finding(
                findings,
                "error",
                "SSRF_HOST",
                rel,
                "localhost/127.0.0.1/private range detected",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(EVAL_CALL_RE):
            add_finding(
                findings,
                "error",
                "EVAL_DYNAMIC",
                rel,
                "eval() detected",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(NEW_FUNCTION_RE):
            add_finding(
                findings,
                "error",
                "EVAL_DYNAMIC",
                rel,
                "new Function() detected",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )


        for m in matches_filtered(COMMAND_EXEC_RE):
            add_finding(
                findings,
                "error",
                "COMMAND_EXEC",
                rel,
                "child_process.* command execution",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(VM_DYNAMIC_RE):
            add_finding(
                findings,
                "error",
                "VM_DYNAMIC",
                rel,
                "vm.* dynamic code execution",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(SETTIME_STRING_RE):
            add_finding(
                findings,
                "error",
                "EVAL_DYNAMIC",
                rel,
                "setTimeout/Interval with string code",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )

        for m in matches_filtered(REQUIRE_VAR_RE):
            add_finding(
                findings,
                "warn",
                "DYNAMIC_REQUIRE",
                rel,
                "require(var) dynamic module load",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(REQUIRE_CONCAT_RE):
            add_finding(
                findings,
                "warn",
                "DYNAMIC_REQUIRE",
                rel,
                "require(a+b) dynamic module load",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(IMPORT_DYNAMIC_RE):
            add_finding(
                findings,
                "warn",
                "DYNAMIC_IMPORT",
                rel,
                "import(expr) dynamic module load",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )

        for m in matches_filtered(EXT_HTTP_CALL_RE):
            add_finding(
                findings,
                "error",
                "EXT_HTTP_CALL",
                rel,
                "External HTTP call function detected",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )

        # ---- Dynamic RegExp / yaml.load ----
        for m in matches_filtered(DYNAMIC_REGEX_RE):
            add_finding(
                findings,
                "warn",
                "DYNAMIC_REGEX",
                rel,
                "new RegExp(...) from variable input",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )
        for m in matches_filtered(YAML_LOAD_RE):
            add_finding(
                findings,
                "warn",
                "DESERIALIZE",
                rel,
                "yaml.load (use safeLoad/safeLoadAll)",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
            )

        dataurl_hits = list(matches_filtered(DATA_URL_RE))
        if dataurl_hits and JSON_DATA_RETURN_RE.search(txt):
            for m in dataurl_hits:
                add_finding(
                    findings,
                    "warn",
                    "DATAURL_JSON",
                    rel,
                    "DataURL returned in JSON",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span(),
                )

        # ---- Binary output without prepareBinaryData ----
        if "prepareBinaryData" not in txt:
            for m in matches_filtered(BINARY_PROP_RE):
                add_finding(
                    findings,
                    "error",
                    "BINARY_PREPARE",
                    rel,
                    "Binary output w/o prepareBinaryData",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span(),
                )

        # ---- Credential declarations ----
        for m in finditer_nocomment(CRED_DECL_RE, txt, comment_spans):
            add_finding(
                findings,
                "info",
                "CRED_DECL",
                rel,
                f"Credential declared: {m.group(1)}",
                pkg=npm_name_for_pkg,
                text=txt,
                span=m.span(),
                matched_text=m.group(0),
            )


        for m in UI_VALUE_QUOTED_RE.finditer(txt):
            if is_in_spans(m.start(), comment_spans):
                continue
            val = m.group("val")
            if NON_ASCII_RE.search(val or ""):
                add_finding(
                    findings,
                    "error",
                    "I18N_NON_EN",
                    rel,
                    "Non-English chars found in UI text (quoted)",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span("val"),
                    matched_text=val,
                )
        for m in UI_VALUE_TPL_RE.finditer(txt):
            if is_in_spans(m.start(), comment_spans):
                continue
            val = m.group("val")
            if NON_ASCII_RE.search(val or ""):
                add_finding(
                    findings,
                    "error",
                    "I18N_NON_EN",
                    rel,
                    "Non-English chars found in UI text (template)",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span("val"),
                    matched_text=val,
                )

        imported = iter_imported_modules(txt, comment_spans)
        for base in imported:
            if is_tooling_module(base):
                continue
            networky, why = is_networky_module_name(base)
            if networky:
                add_finding(
                    findings,
                    "error",
                    "EXT_HTTP_IMPORT",
                    rel,
                    f"External NET-capable lib import: {base} ({why})",
                    pkg=npm_name_for_pkg,
                    matched_text=base,
                )
            for fam, cfg in SUS_FAMILIES.items():
                if base in cfg["modules"]:
                    if fam == "tunnel_proxy":
                        add_finding(
                            findings,
                            "warn",
                            "PROXY_TUNNEL",
                            rel,
                            f"proxy/tunnel import: {base}",
                            pkg=npm_name_for_pkg,
                            matched_text=base,
                        )
                    elif fam == "remote_shell":
                        add_finding(
                            findings,
                            "error",
                            "REMOTE_SHELL_CALL",
                            rel,
                            f"remote shell import: {base}",
                            pkg=npm_name_for_pkg,
                            matched_text=base,
                        )
                    elif fam == "exfil_sdk":
                        add_finding(
                            findings,
                            "warn",
                            "EXFIL_SDK_CALL",
                            rel,
                            f"telemetry/exfil SDK import: {base}",
                            pkg=npm_name_for_pkg,
                            matched_text=base,
                        )
                    else:  # stealth / captcha
                        add_finding(
                            findings,
                            "error",
                            "EXT_SUS_IMPORT",
                            rel,
                            f"suspicious import: {base}",
                            pkg=npm_name_for_pkg,
                            matched_text=base,
                        )

        if ("puppeteer" in txt) and ("puppeteer-extra-plugin-stealth" in txt):
            m = re.search(
                r"puppeteer\.use\s*\(\s*require\(\s*['\"]puppeteer-extra-plugin-stealth['\"]\s*\)\s*\(\s*\)\s*\)",
                txt,
            )
            if m:
                add_finding(
                    findings,
                    "error",
                    "BROWSER_STEALTH",
                    rel,
                    "Puppeteer stealth plugin enabled",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span(),
                )

        LOG_LINE_RE = re.compile(
            r"\b(console\.(log|error|warn)|this\.logger\.(info|debug|warn|error)|logger\.(info|debug|warn|error))\s*\(",
            re.I,
        )
        SENSITIVE_HINT_RE = re.compile(
            r"(cookie|authorization|bearer|token|api[_-]?key|secret|client[_-]?secret|private[_-]?key|passwd|password)",
            re.I,
        )
        for m in matches_filtered(LOG_LINE_RE):
            end = min(len(txt), m.end() + 300)
            window = txt[m.start() : end]
            if SENSITIVE_HINT_RE.search(window):
                add_finding(
                    findings,
                    "error",
                    "LOG_SENSITIVE",
                    rel,
                    "Sensitive data printed in logs",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=(m.start(), end),
                )

        saw_binary_semantics = bool(BINARY_PROP_NAME_RE.search(txt))
        saw_hand_roll = bool(
            next(finditer_nocomment(BINARY_HAND_ROLL_RE, txt, comment_spans), None)
        )
        if saw_binary_semantics and saw_hand_roll:
            mh = BINARY_HAND_ROLL_RE.search(txt)
            add_finding(
                findings,
                "warn",
                "BINARY_PREPARE_WEAK",
                rel,
                "Manual base64/dataURL for binary; prefer prepareBinaryData()",
                pkg=npm_name_for_pkg,
                text=txt,
                span=mh.span() if mh else (0, 1),
            )

        # ---- DELETE_RET_BOOL ----
        if OP_DELETE_HINT_RE.search(txt):
            m_del = next(
                finditer_nocomment(RET_BOOL_DELETED_ARR_RE, txt, comment_spans), None
            )
            if m_del:
                add_finding(
                    findings,
                    "warn",
                    "DELETE_RET_BOOL",
                    rel,
                    "Delete returns [{deleted:true}] — return structured summary instead",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m_del.span(),
                )

        for m in SECRET_FIELD_NAME_RE.finditer(txt):
            if is_in_spans(m.start(), comment_spans):
                continue
            start_pos = m.start()
            window = txt[start_pos : start_pos + 2000]
            depth = 0
            end_rel: Optional[int] = None
            for i, ch in enumerate(window):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth <= 0 and i > 0:
                        end_rel = i + 1
                        break
            if end_rel is None:
                end_rel = min(len(window), 800)
            block_text = window[:end_rel]
            if TYPEOPTIONS_PASSWORD_TRUE_RE.search(block_text) or ALT_MASK_HINT_RE.search(
                block_text
            ):
                continue
            span = (start_pos, min(start_pos + end_rel, len(txt)))
            add_finding(
                findings,
                "error",
                "INPUT_SECRET_UNMASKED",
                rel,
                "Sensitive input without masking: add typeOptions:{password:true} or use Credentials.",
                pkg=npm_name_for_pkg,
                text=txt,
                span=span,
                matched_text=m.group("key"),
            )

        lower_txt = txt.lower()
        sanitizer_seen = any(ind.lower() in lower_txt for ind in HTML_SANITIZER_INDICATORS)
        if not sanitizer_seen:
            for rx in HTML_RENDER_PATTERNS:
                for m in finditer_nocomment(rx, txt, comment_spans):
                    matched = txt[m.start() : m.end()]
                    add_finding(
                        findings,
                        "error",
                        "HTML_UNSANITIZED",
                        rel,
                        f"HTML rendered with no sanitizer (need one of: {', '.join(HTML_SANITIZER_INDICATORS)})",
                        pkg=npm_name_for_pkg,
                        text=txt,
                        span=m.span(),
                        matched_text=matched,
                    )

        if EXFIL_CALL_HINT_RE.search(txt):
            h = EXFIL_CALL_HINT_RE.search(txt)
            add_finding(
                findings,
                "warn",
                "EXFIL_SDK_CALL",
                rel,
                "Telemetry/exfil-like call",
                pkg=npm_name_for_pkg,
                text=txt,
                span=h.span(),
            )
        if REMOTE_SHELL_HINT_RE.search(txt):
            h = REMOTE_SHELL_HINT_RE.search(txt)
            add_finding(
                findings,
                "error",
                "REMOTE_SHELL_CALL",
                rel,
                "Potential remote shell execution",
                pkg=npm_name_for_pkg,
                text=txt,
                span=h.span(),
            )

        # N9: prompt-injection surface — LLM/chat API use + getNodeParameter keys that plausibly feed user/model text
        if list(finditer_nocomment(LLM_API_SURFACE_RE, txt, comment_spans)):
            for m in finditer_nocomment(GET_NODE_PARAMETER_KEY_RE, txt, comment_spans):
                key = m.group("key")
                if not _node_parameter_key_suggests_llm_prompt(key):
                    continue
                add_finding(
                    findings,
                    "warn",
                    "PROMPT_INJECTION_CANDIDATE",
                    rel,
                    "LLM/chat API with getNodeParameter for prompt-like key (static N9: user-controlled text may reach the model).",
                    pkg=npm_name_for_pkg,
                    text=txt,
                    span=m.span(),
                    matched_text=key,
                )

    findings = dedupe_findings(findings)
    return {
        "findings": findings,
        "meta": {
            "files_scanned": files_scanned,
            "pkg": {"name": pkg_name, "version": pkg_version},
            "deps_collected": dep_items,
        },
    }


def fetch_npm_metadata(name: str, version: Optional[str]) -> Dict[str, Any]:
    import urllib.parse

    need_ver = (version or "latest").strip() or "latest"
    name_enc = urllib.parse.quote(name)
    r = http_get(f"https://registry.npmjs.org/{name_enc}", timeout=30)
    if r.status_code == 404:
        raise RuntimeError(f"npm_not_found: {name}")
    if r.status_code != 200:
        raise RuntimeError(f"npm_meta_http_{r.status_code}: {name}")
    meta_all = r.json()
    versions = meta_all.get("versions") or {}
    if need_ver == "latest":
        need_ver = (meta_all.get("dist-tags") or {}).get("latest")
        if not need_ver:
            if not versions:
                raise RuntimeError(f"npm_no_versions: {name}")

            def _sem_key(v):
                parts = re.split(r"[^\d]+", v)
                nums = [int(p) for p in parts if p.isdigit()]
                while len(nums) < 3:
                    nums.append(0)
                return tuple(nums[:3])

            need_ver = sorted(versions.keys(), key=_sem_key, reverse=True)[0]
    if need_ver not in versions:
        raise RuntimeError(f"npm_version_absent: {name}@{need_ver}")
    vmeta = versions[need_ver]
    tarball = (vmeta.get("dist") or {}).get("tarball")
    if not tarball:
        raise RuntimeError(f"npm_no_tarball: {name}@{need_ver}")
    return {
        "name": vmeta.get("name") or name,
        "version": need_ver,
        "tarball": tarball,
        "pkg_json": vmeta,
    }


def download_npm_tarball(tarball_url: str) -> bytes:
    r = http_get(tarball_url, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"download tarball failed {r.status_code}")
    return r.content

def main():
    ap = argparse.ArgumentParser(
        description="Scan n8n community node packages from npm (node_layer scanner).",
    )
    ap.add_argument(
        "--packages-txt",
        type=str,
        default=None,
        help="Text file: one npm package per line (empty lines and # comments skipped).",
    )
    ap.add_argument(
        "--input-csv",
        type=str,
        default=None,
        help="CSV with name, repository_url (default: built-in INPUT_CSV).",
    )
    ap.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON path (default depends on --packages-txt vs CSV mode).",
    )
    args = ap.parse_args()

    if args.packages_txt and args.input_csv:
        ap.error("Use only one of --packages-txt or --input-csv.")

    if args.packages_txt:
        pt = resolve_scan_path(args.packages_txt)
        rows = load_rows_from_package_txt(str(pt))
        input_csv_for_header: Optional[str] = None
        input_packages_txt_for_header = str(pt)
        if args.output:
            out = resolve_scan_path(args.output)
        else:
            out = resolve_scan_path(DEFAULT_PACKAGES_TXT_OUTPUT)
    else:
        csv_p = (
            resolve_scan_path(args.input_csv)
            if args.input_csv
            else resolve_scan_path(INPUT_CSV)
        )
        rows = load_rows_from_csv(str(csv_p))
        input_csv_for_header = str(csv_p)
        input_packages_txt_for_header: Optional[str] = None
        if args.output:
            out = resolve_scan_path(args.output)
        else:
            out = resolve_scan_path(OUTPUT_FILE)

    work = Path(tempfile.mkdtemp(prefix="scan-npm-only-"))
    print(f"[+] workdir: {work}")

    total_pkgs = len(rows)
    print(f"[i] total packages: {total_pkgs}")

    counters = {
        "scanned_npm": 0,
        "npm_failed": 0,
        "repo_ok": 0,
        "repo_not_set": 0,
        "repo_unreachable": 0,
        "repo_impersonation": 0,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    first_item = True
    _node_layer_catalog = node_layer_rule_catalog()

    with out.open("w", encoding="utf-8") as fout:
        # JSON header
        fout.write("{\n")
        fout.write(f'  "source": "npm_only",\n')
        fout.write('  "finding_taxonomy": "node_layer_table3",\n')
        fout.write(
            f'  "node_layer_rule_catalog": {json.dumps(_node_layer_catalog, ensure_ascii=False)},\n'
        )
        fout.write(
            f'  "input_csv": {json.dumps(input_csv_for_header, ensure_ascii=False)},\n'
        )
        fout.write(
            f'  "input_packages_txt": {json.dumps(input_packages_txt_for_header, ensure_ascii=False)},\n'
        )
        fout.write(f'  "output": {json.dumps(str(out), ensure_ascii=False)},\n')
        fout.write(f'  "generated_at": {json.dumps(now_ts())},\n')
        fout.write('  "packages": [\n')

        for idx, row in enumerate(rows, 1):
            name = row["name"]
            repo_url_csv = (row.get("repository_url") or "").strip()
            if repo_url_csv.lower() == "nan":
                repo_url_csv = ""

            print(f"[=] {idx}/{total_pkgs} scanning {name} …")

            item: Dict[str, Any] = {
                "index": idx,
                "npm_name": name,
                "csv_repository_url": repo_url_csv,
            }


            repo_info: Dict[str, Any] = {}
            fraud: Optional[Dict[str, Any]] = None

            if not repo_url_csv:
                repo_info = {
                    "url": None,
                    "reachable": False,
                    "status": "no_repository_url_in_csv",
                    "is_official_repo": False,
                }
                counters["repo_not_set"] += 1
            else:
                is_official = (
                    repo_url_csv.rstrip("/").lower()
                    == OFFICIAL_N8N_REPO.rstrip("/").lower()
                )
                repo_info["url"] = repo_url_csv
                repo_info["is_official_repo"] = is_official
                try:

                    try:
                        r = http_get(repo_url_csv, method="HEAD", timeout=15)
                    except Exception:
                        r = http_get(repo_url_csv, method="GET", timeout=15)
                    repo_info["status_code"] = r.status_code
                    repo_info["reachable"] = 200 <= r.status_code < 400
                    if repo_info["reachable"]:
                        counters["repo_ok"] += 1
                    else:
                        counters["repo_unreachable"] += 1
                except Exception as e:
                    repo_info["reachable"] = False
                    repo_info["status"] = f"error:{e}"
                    counters["repo_unreachable"] += 1

                if is_official:
                    fraud = {
                        "severity": "error",
                        "rule": "OFFICIAL_REPO_IMPERSONATION",
                        "message": f"repository_url points to official {OFFICIAL_N8N_REPO}",
                    }
                    attach_paper_n_to_finding(
                        fraud, "OFFICIAL_REPO_IMPERSONATION"
                    )
                    attach_node_layer_table3_to_finding(
                        fraud, "OFFICIAL_REPO_IMPERSONATION"
                    )
                    counters["repo_impersonation"] += 1

            item["github_repo"] = repo_info
            if fraud is not None:
                item["fraud"] = fraud


            scans_obj: Dict[str, Any] = {}
            npm_version: Optional[str] = None
            npm_error_reason: Optional[str] = None

            try:
                meta = fetch_npm_metadata(name, None)
                npm_version = meta["version"]
                tgz = download_npm_tarball(meta["tarball"])
                pkg_dir = work / f"npm_{name.replace('/', '_')}@{npm_version}"
                npm_root = extract_tgz_to_dir(tgz, pkg_dir)
                npm_scan_res = scan_tree(str(npm_root), name)
                scans_obj["npm"] = npm_scan_res
                item["npm_version"] = npm_version
                counters["scanned_npm"] += 1
            except Exception as e:
                npm_error_reason = str(e)
                counters["npm_failed"] += 1

            item["scan"] = scans_obj
            item["source_used"] = "npm" if scans_obj else "none"
            if npm_error_reason:
                item["npm_error"] = npm_error_reason


            item["consistency"] = {
                "status": "npm_only",
                "details": "scanned from npm tarball only",
                "npm_version": npm_version,
                "github_version": None,
            }

            item["error"] = item.get("npm_error")

            if not first_item:
                fout.write(",\n")
            encoded = json.dumps(item, ensure_ascii=False, indent=2)

            indented = "\n".join("    " + line for line in encoded.splitlines())
            fout.write(indented)
            first_item = False


            del item, scans_obj


            if idx % 50 == 0:
                gc.collect()


        fout.write("\n  ],\n")
        fout.write('  "counters": ')
        fout.write(json.dumps(counters, ensure_ascii=False, indent=2).replace("\n", "\n  "))
        fout.write("\n}\n")

    print(f"[OK] report -> {out}")

    if not KEEP_WORKDIR:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"[i] workdir kept at: {work}")


if __name__ == "__main__":
    main()
