#!/usr/bin/env python3

import io
import os
import re
import json
import tarfile
import zipfile
import shutil
import tempfile
import gc
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterable, Pattern, Match
from datetime import datetime

INPUT_CSV    = "../data/node_fetch_result/n8n_nodes_final_2025-11-15_11-36-26.csv"
OUTPUT_FILE  = "../data/scan_result/scan_report.json"
KEEP_WORKDIR = False
OFFICIAL_N8N_REPO = "https://github.com/n8n-io/n8n"
USER_AGENT   = "n8n-node-audit/4.0-npm-only-filtered"

try:
    import requests
except Exception:
    print("Please install: pip install requests pandas")
    raise

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
    "LOG_SENSITIVE": "DATA_PRIVACY",
    "DATAURL_JSON": "DATA_PRIVACY",
    "BINARY_PREPARE": "DATA_PRIVACY",
    "BINARY_PREPARE_WEAK": "DATA_PRIVACY",
    "DELETE_RET_BOOL": "DATA_PRIVACY",
    "CRED_DECL": "DATA_PRIVACY",
    "INPUT_SECRET_UNMASKED": "DATA_PRIVACY",
    "HTML_UNSANITIZED": "HTML_XSS",
    "NODE_ENGINE": "CONFIG",
    "LICENSE": "CONFIG",
    "PKG_JSON_INVALID": "CONFIG",
    "PKG_JSON_MISSING": "CONFIG",
    "I18N_NON_EN": "CONFIG",

    "OFFICIAL_REPO_IMPERSONATION": "SUPPLYCHAIN",
}

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

ENGINES_NODE_RE = re.compile(r"^\s*>=\s*20")
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
        engines = (pkg_json.get("engines") or {}).get("node")
        if not engines or not ENGINES_NODE_RE.search(str(engines)):
            add_finding(
                findings,
                "error",
                "NODE_ENGINE",
                "package.json",
                "package.json engines.node should be '>=20'",
                pkg=npm_name_for_pkg,
            )
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
                "ENV_FS",
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
                "ENV_FS",
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
    work = Path(tempfile.mkdtemp(prefix="scan-npm-only-"))
    print(f"[+] workdir: {work}")

    rows = load_rows_from_csv(INPUT_CSV)
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

    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    first_item = True

    with Path(OUTPUT_FILE).open("w", encoding="utf-8") as fout:
        # JSON header
        fout.write("{\n")
        fout.write(f'  "source": "npm_only",\n')
        fout.write(f'  "input_csv": {json.dumps(INPUT_CSV, ensure_ascii=False)},\n')
        fout.write(f'  "output": {json.dumps(OUTPUT_FILE, ensure_ascii=False)},\n')
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

    print(f"[OK] report -> {OUTPUT_FILE}")

    if not KEEP_WORKDIR:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"[i] workdir kept at: {work}")


if __name__ == "__main__":
    main()
