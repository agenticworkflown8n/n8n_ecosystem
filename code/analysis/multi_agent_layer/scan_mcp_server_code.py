#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

_PIPELINE_DIR = Path(__file__).resolve().parent.parent
if str(_PIPELINE_DIR) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_DIR))

# Repo `code/` tree: this file is code/pipeline/mcp/scan_mcp_server_code.py
BASE_DIR = Path(__file__).resolve().parent.parent.parent
REGISTRY_DIR = BASE_DIR / "data" / "MCP" / "registry"
REGISTRY_SERVERS_FILE = REGISTRY_DIR / "mcp_registry_servers.json"
OUTPUT_DIR = BASE_DIR / "data" / "MCP" / "code_analysis"
CODE_CACHE_DIR = OUTPUT_DIR / "code_cache"
RESULTS_FILE = OUTPUT_DIR / "mcp_code_scan_results.json"
REPORT_FILE = OUTPUT_DIR / "mcp_code_scan_report.md"
SUMMARY_FILE = OUTPUT_DIR / "mcp_code_scan_summary.json"


def _ensure_scan_dirs() -> None:
    """Directories needed for registry read + scan outputs (not the full pipeline artifact tree)."""
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CODE_CACHE_DIR.mkdir(parents=True, exist_ok=True)


# Paper Table: M1–M9 → base tier (Sv/Md) for MCP server-layer findings (canonical; scan_n8n_nodes imports from here).
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


def tier_from_paper_m(paper_m: str) -> Optional[str]:
    return BASE_TIER_BY_PAPER_M.get(paper_m)


def _label_non_empty(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return len(v.strip()) > 0
    if isinstance(v, (list, dict)):
        return len(v) > 0
    return True


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


def mcp_risk_finding_for_evidence(
    rule_id: str,
    family: str,
    rel: str,
    line_no: int,
    match: str,
    context: str,
) -> Dict[str, Any]:
    """Shape one MCP risk row like scan_n8n_nodes findings for static_evidence_score."""
    ctx = (context or "").strip()
    mlines: Optional[List[str]] = None
    if ctx:
        parts = [ln for ln in ctx.split("\n") if ln.strip()][:5]
        if parts:
            mlines = parts
    return {
        "file": rel,
        "line_start": line_no,
        "line_end": line_no,
        "match_lines": mlines,
        "matched_text": match,
        "code_snippet": ctx[:2000] if ctx else None,
        "message": f"{family}/{rule_id}",
        "rule": rule_id,
    }


SAVE_EVERY_N = 25


def deduplicate_registry_rows(servers: List[Dict]) -> List[Dict]:
    """
    One row per logical registry server (full_name), preferring is_latest then newest updated_at.
    Matches the denominator used for |MCP registry| in the paper (e.g., ~6,470).
    """
    best: Dict[str, Dict] = {}
    for s in servers:
        k = (s.get("full_name") or "").strip() or f"__unnamed__{id(s)}"
        c = best.get(k)
        if c is None:
            best[k] = s
            continue
        sl, cl = bool(s.get("is_latest")), bool(c.get("is_latest"))
        if sl and not cl:
            best[k] = s
        elif cl and not sl:
            pass
        elif (s.get("updated_at") or "") >= (c.get("updated_at") or ""):
            best[k] = s
    return list(best.values())


# Append Table~\ref{tab:app_mcp_static_rules} rule row ids; keep in sync with MCPServerCodeScanner._load_risk_rules
EXPECTED_RULE_IDS: Tuple[str, ...] = (
    "cmd_exec",
    "dynamic_code",
    "unsafe_deserialization",
    "path_traversal",
    "outbound_http",
    "tls_relaxed",
    "broad_permission",
    "secret_literal",
    "secret_env_source",
)
EXPECTED_FAMILIES: Tuple[str, ...] = (
    "command_injection",
    "dynamic_code_execution",
    "unsafe_parsing",
    "file_path_traversal",
    "unauthorized_network_access",
    "insecure_transport_verification",
    "overbroad_permission_scope",
    "sensitive_data_exposure",
)


def aggregate_scan_results(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Count servers with any finding and per-rule / per-family hit totals."""
    by_rule: Dict[str, int] = defaultdict(int)
    by_family: Dict[str, int] = defaultdict(int)
    servers_hitting_rule: Dict[str, set] = {rid: set() for rid in EXPECTED_RULE_IDS}
    servers_hitting_family: Dict[str, set] = {fam: set() for fam in EXPECTED_FAMILIES}
    servers_with_findings = 0
    total_findings = 0
    ev_conf_agg: Dict[str, int] = defaultdict(int)
    chain_conf_agg: Dict[str, int] = defaultdict(int)
    for sname, payload in scan_results.items():
        if not isinstance(payload, dict):
            continue
        n = int(payload.get("total_findings") or 0)
        if n > 0:
            servers_with_findings += 1
            total_findings += n
        evc = payload.get("findings_by_evidence_confidence") or {}
        if isinstance(evc, dict):
            for k, v in evc.items():
                try:
                    ev_conf_agg[str(k)] += int(v)
                except (TypeError, ValueError):
                    pass
        cbc = payload.get("findings_by_confidence") or {}
        if isinstance(cbc, dict):
            for k, v in cbc.items():
                try:
                    chain_conf_agg[str(k)] += int(v)
                except (TypeError, ValueError):
                    pass
        risks = payload.get("risks") or {}
        if not isinstance(risks, dict):
            continue
        for fam, issues in risks.items():
            if not issues:
                continue
            by_family[str(fam)] += len(issues)
            for iss in issues:
                rid = (iss or {}).get("rule_id")
                if rid:
                    by_rule[str(rid)] += 1
                    servers_hitting_rule.setdefault(str(rid), set()).add(sname)
                servers_hitting_family.setdefault(str(fam), set()).add(sname)
    for rid in EXPECTED_RULE_IDS:
        by_rule.setdefault(rid, 0)
    for fam in EXPECTED_FAMILIES:
        by_family.setdefault(fam, 0)
    return {
        "servers_in_results": len(scan_results),
        "servers_with_at_least_one_finding": servers_with_findings,
        "total_findings": total_findings,
        "findings_by_rule_id": {k: by_rule[k] for k in EXPECTED_RULE_IDS},
        "findings_by_family": {k: by_family[k] for k in EXPECTED_FAMILIES},
        "unique_servers_with_hit_by_rule_id": {k: len(servers_hitting_rule.get(k, set())) for k in EXPECTED_RULE_IDS},
        "unique_servers_with_hit_by_family": {k: len(servers_hitting_family.get(k, set())) for k in EXPECTED_FAMILIES},
        "findings_by_evidence_confidence": {
            "1": ev_conf_agg.get("1", 0),
            "2": ev_conf_agg.get("2", 0),
        },
        "findings_by_chain_confidence": {
            "weak": chain_conf_agg.get("weak", 0),
            "strong": chain_conf_agg.get("strong", 0),
        },
    }


class MCPServerCodeScanner:
    """
    Static MCP scanner: risk-rule matching with deduplication, guard-aware
    weak/strong tiers, and optional source--sink context. Capability buckets
    (file/system/network/memory) are aggregated for reporting and surface
    labeling; they do not replace behavior rule hits.
    """

    def __init__(self):
        self.scan_results = defaultdict(dict)
        self.capability_patterns = self._load_capability_patterns()
        self.risk_rules = self._load_risk_rules()
        self.guard_patterns = self._load_guard_patterns()
        self.source_patterns = self._load_source_patterns()
        self.sink_patterns = self._load_sink_patterns()
        self.vendor_dirs = {
            ".git",
            "node_modules",
            "dist",
            "build",
            "vendor",
            "venv",
            ".venv",
            "target",
            "__pycache__",
            ".next",
            ".cache",
        }

    def _load_capability_patterns(self) -> Dict[str, List[re.Pattern]]:
        return {
            "file_resource": [
                re.compile(r"\bfs\.(read|write|append|unlink|rename|mkdir|rmdir|createReadStream|createWriteStream)\b", re.IGNORECASE),
                re.compile(r"\b(open|read|write|chmod|chown|remove|copyfile)\s*\(", re.IGNORECASE),
            ],
            "system_resource": [
                re.compile(r"\b(child_process|subprocess|os\.system|execv|fork|spawn)\b", re.IGNORECASE),
                re.compile(r"\b(exec|execSync|spawn|spawnSync|popen|subprocess\.run)\s*\(", re.IGNORECASE),
            ],
            "network_resource": [
                re.compile(r"\b(fetch|axios|get|post|put|delete|request)\s*\(", re.IGNORECASE),
                re.compile(r"\b(http|https|socket|urllib|requests)\b", re.IGNORECASE),
                re.compile(r"https?://", re.IGNORECASE),
            ],
            "memory_resource": [
                re.compile(r"\b(ctypes\.CDLL|dlopen|unsafe|malloc|free|memcpy|create_string_buffer)\b", re.IGNORECASE),
            ],
        }

    def _load_risk_rules(self) -> List[Dict]:
        return [
            {
                "id": "cmd_exec",
                "family": "command_injection",
                "pattern": re.compile(r"\b(exec|execSync|spawn|spawnSync|popen|subprocess\.run|os\.system)\s*\(", re.IGNORECASE),
            },
            {
                "id": "dynamic_code",
                "family": "dynamic_code_execution",
                "pattern": re.compile(r"\b(eval|new\s+Function|vm\.Script|compile|exec)\s*\(", re.IGNORECASE),
            },
            {
                "id": "unsafe_deserialization",
                "family": "unsafe_parsing",
                "pattern": re.compile(r"\b(yaml\.load|pickle\.loads|marshal\.loads|JSON\.parse)\s*\(", re.IGNORECASE),
            },
            {
                "id": "path_traversal",
                "family": "file_path_traversal",
                "pattern": re.compile(r"(\.\./|%2e%2e|path\.join\s*\(|path\.resolve\s*\()", re.IGNORECASE),
            },
            {
                "id": "outbound_http",
                "family": "unauthorized_network_access",
                "pattern": re.compile(r"\b(fetch|axios|requests\.(get|post)|http\.(get|request)|https\.(get|request)|urllib\.request)\b", re.IGNORECASE),
            },
            {
                "id": "tls_relaxed",
                "family": "insecure_transport_verification",
                "pattern": re.compile(r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED)", re.IGNORECASE),
            },
            {
                "id": "broad_permission",
                "family": "overbroad_permission_scope",
                "pattern": re.compile(r"(allowAll|permissions?\s*[:=]\s*['\"]?\*|read.*write.*execute)", re.IGNORECASE),
            },
            {
                "id": "secret_literal",
                "family": "sensitive_data_exposure",
                "pattern": re.compile(r"((api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"])", re.IGNORECASE),
            },
            {
                "id": "secret_env_source",
                "family": "sensitive_data_exposure",
                "pattern": re.compile(r"(process\.env\.[A-Z0-9_]+|os\.environ|getenv\s*\()", re.IGNORECASE),
            },
        ]

    def _load_guard_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r"\b(allowlist|whitelist|denylist|blocklist|sanitize|validator|validate|escape)\b", re.IGNORECASE),
            re.compile(r"\b(auth|authentication|authorization|bearer|token check|apikey)\b", re.IGNORECASE),
            re.compile(r"\b(timeout|rate.?limit|retry|backoff)\b", re.IGNORECASE),
            re.compile(r"\b(verify\s*=\s*True|rejectUnauthorized\s*:\s*true)\b", re.IGNORECASE),
        ]

    def _load_source_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r"(process\.env\.[A-Z0-9_]+|os\.environ|getenv\s*\()", re.IGNORECASE),
            re.compile(r"(request\.(body|query|params)|ctx\.(request|params)|input\(|argv)", re.IGNORECASE),
        ]

    def _load_sink_patterns(self) -> List[re.Pattern]:
        return [
            re.compile(r"\b(fetch|axios|requests\.(get|post)|http\.(get|request)|https\.(get|request)|urllib\.request)\b", re.IGNORECASE),
            re.compile(r"\b(exec|execSync|spawn|subprocess\.run|os\.system|eval|new\s+Function)\b", re.IGNORECASE),
            re.compile(r"\b(fs\.(write|append|createWriteStream)|writeFile|open\s*\()", re.IGNORECASE),
        ]

    def fetch_anthropic_registry_servers(self) -> List[Dict]:
        print("Fetching MCP servers from Anthropic Registry...")
        servers = []
        if REGISTRY_SERVERS_FILE.exists():
            try:
                with open(REGISTRY_SERVERS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    servers = data.get("servers", [])
                    print(f"  Loaded {len(servers)} servers from cached registry data")
                    return servers
            except Exception as e:
                print(f"  Error reading cached registry: {e}")
        try:
            github_org = "modelcontextprotocol"
            github_api = f"https://api.github.com/orgs/{github_org}/repos"
            response = requests.get(github_api, timeout=10)
            if response.status_code == 200:
                repos = response.json()
                for repo in repos:
                    if "mcp" in repo["name"].lower() or "server" in repo["name"].lower():
                        servers.append(
                            {
                                "name": repo["name"],
                                "full_name": repo["full_name"],
                                "description": repo.get("description", ""),
                                "url": repo["html_url"],
                                "clone_url": repo["clone_url"],
                                "source": "anthropic_github",
                                "stars": repo.get("stargazers_count", 0),
                                "updated_at": repo.get("updated_at", ""),
                            }
                        )
                print(f"  Found {len(servers)} servers from Anthropic GitHub org")
        except Exception as e:
            print(f"  Error fetching from Anthropic registry: {e}")
        return servers

    def get_repository_url(self, server: Dict) -> Optional[str]:
        if server.get("clone_url"):
            return server["clone_url"]
        if server.get("url"):
            url = server["url"]
            if "github.com" in url:
                return url if url.endswith(".git") else f"{url}.git"
        repo = server.get("repository")
        if isinstance(repo, str) and "github.com" in repo:
            return repo if repo.endswith(".git") else f"{repo}.git"
        if isinstance(repo, dict) and repo.get("url"):
            return repo["url"]
        return None

    def clone_or_download_code(self, repo_url: str, server_name: str) -> Optional[Path]:
        cache_key = hashlib.md5(f"{repo_url}{server_name}".encode()).hexdigest()
        cache_path = CODE_CACHE_DIR / cache_key
        if cache_path.exists():
            print(f"  Using cached code: {cache_path}")
            return cache_path
        if "github.com" in repo_url:
            try:
                print(f"  Cloning {repo_url}...")
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(cache_path)],
                    check=True,
                    capture_output=True,
                    timeout=60,
                    text=True,
                )
                if cache_path.exists():
                    return cache_path
            except subprocess.TimeoutExpired:
                print(f"  Timeout cloning {repo_url}")
            except subprocess.CalledProcessError as e:
                stderr = e.stderr if hasattr(e, "stderr") else str(e)
                print(f"  Failed to clone {repo_url}: {stderr}")
            except Exception as e:
                print(f"  Error cloning {repo_url}: {e}")
        return None

    def _should_scan_file(self, file_path: Path) -> bool:
        if not file_path.is_file():
            return False
        if any(part in self.vendor_dirs for part in file_path.parts):
            return False
        low = file_path.name.lower()
        if any(tok in low for tok in ("test", "spec", "fixture", "example", "sample", "demo")):
            return False
        code_ext = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".cpp", ".c", ".mjs"}
        config_files = {"server.json", "mcp.json", "manifest.json", "config.json"}
        return file_path.suffix.lower() in code_ext or low in config_files

    def _line_number(self, content: str, idx: int) -> int:
        return content[:idx].count("\n") + 1

    def _get_context(self, content: str, start: int, end: int, context_lines: int = 2) -> str:
        lines = content.split("\n")
        start_line = content[:start].count("\n")
        end_line = content[:end].count("\n")
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        return "\n".join(lines[context_start:context_end])

    def _is_comment_line(self, line_text: str) -> bool:
        s = line_text.strip()
        return s.startswith("//") or s.startswith("#") or s.startswith("*") or s.startswith("/*")

    def _nearby_text(self, lines: List[str], line_no: int, window: int = 4) -> str:
        start = max(0, line_no - 1 - window)
        end = min(len(lines), line_no - 1 + window + 1)
        return "\n".join(lines[start:end])

    def _has_guard_nearby(self, lines: List[str], line_no: int) -> bool:
        nearby = self._nearby_text(lines, line_no, window=6)
        return any(p.search(nearby) for p in self.guard_patterns)

    def _has_source_sink_chain(self, lines: List[str], line_no: int) -> bool:
        nearby = self._nearby_text(lines, line_no, window=8)
        has_source = any(p.search(nearby) for p in self.source_patterns)
        has_sink = any(p.search(nearby) for p in self.sink_patterns)
        return has_source and has_sink

    def _rule_specific_filter(self, rule_id: str, nearby_text: str) -> bool:
        """
        Return True when the candidate should be skipped due to missing context.
        """
        if rule_id == "path_traversal":
            needs_fs_op = re.search(r"\b(fs\.(read|write|open)|readFile|writeFile|open\s*\()", nearby_text, re.IGNORECASE)
            needs_user_path = re.search(r"(req\.(body|query|params)|input|argv|user|path)", nearby_text, re.IGNORECASE)
            return not (needs_fs_op and needs_user_path)
        if rule_id == "secret_env_source":
            # Environment access alone is too broad unless combined with sink nearby.
            has_sink = any(p.search(nearby_text) for p in self.sink_patterns)
            return not has_sink
        return False

    def _confidence(self, has_guard: bool, has_chain: bool) -> str:
        """
        Two tiers (replacing numeric 1/2/3):
        - strong: nearby window has both source-like and sink-like patterns and no guard nearby.
        - weak: guarded hit, or no complete source→sink chain in the window (ambiguous/static-only).
        """
        if has_chain and not has_guard:
            return "strong"
        return "weak"

    def _severity(self, family: str, has_guard: bool) -> str:
        """Matches prior behavior: guarded findings → low; unguarded → high/medium by family."""
        high = {
            "command_injection",
            "dynamic_code_execution",
            "sensitive_data_exposure",
            "unauthorized_network_access",
        }
        if has_guard:
            return "low"
        if family in high:
            return "high"
        return "medium"

    def _platform_hint(self, file_text: str) -> List[str]:
        hints = set()
        t = file_text.lower()
        if "powershell" in t or "win32" in t:
            hints.add("windows")
        if "darwin" in t or "launchctl" in t:
            hints.add("macos")
        if "linux" in t or "systemd" in t:
            hints.add("linux")
        if "docker" in t or "container" in t:
            hints.add("container")
        return sorted(hints)

    def scan_code_directory(self, code_path: Path, server_name: str) -> Dict:
        results = {
            "server": server_name,
            "code_path": str(code_path),
            "capabilities": defaultdict(int),
            "risks": defaultdict(list),
            "files_scanned": 0,
            "total_findings": 0,
            "findings_by_confidence": {"weak": 0, "strong": 0},
            "findings_by_evidence_confidence": {"1": 0, "2": 0},
        }
        if not code_path.exists():
            return results

        dedupe = set()
        for file_path in code_path.rglob("*"):
            if not self._should_scan_file(file_path):
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"    Error scanning {file_path}: {e}")
                continue

            lines = content.split("\n")
            rel = str(file_path.relative_to(code_path))
            results["files_scanned"] += 1

            # Optional surface aggregation for reporting (not a substitute for risk hits)
            for capability, patterns in self.capability_patterns.items():
                if any(p.search(content) for p in patterns):
                    results["capabilities"][capability] += 1

            # Risk rules + guard-aware weak/strong tier
            for rule in self.risk_rules:
                for m in rule["pattern"].finditer(content):
                    line_no = self._line_number(content, m.start())
                    if line_no <= len(lines) and self._is_comment_line(lines[line_no - 1]):
                        continue
                    nearby = self._nearby_text(lines, line_no, window=6)
                    if self._rule_specific_filter(rule["id"], nearby):
                        continue
                    key = (rule["id"], rel, line_no)
                    if key in dedupe:
                        continue
                    dedupe.add(key)

                    has_guard = self._has_guard_nearby(lines, line_no)
                    has_chain = self._has_source_sink_chain(lines, line_no)
                    chain_confidence = self._confidence(has_guard, has_chain)
                    severity = self._severity(rule["family"], has_guard)
                    results["findings_by_confidence"][chain_confidence] += 1

                    context = self._get_context(content, m.start(), m.end())
                    ev_finding = mcp_risk_finding_for_evidence(
                        rule["id"],
                        rule["family"],
                        rel,
                        line_no,
                        m.group()[:120],
                        context,
                    )
                    evidence_score = static_evidence_score(ev_finding)
                    confidence = confidence_from_evidence(evidence_score)
                    confidence_label = "Probable" if confidence == 2 else "Uncertain"
                    results["findings_by_evidence_confidence"][str(confidence)] += 1

                    results["risks"][rule["family"]].append(
                        {
                            "rule_id": rule["id"],
                            "file": rel,
                            "line": line_no,
                            "match": m.group()[:120],
                            "chain_confidence": chain_confidence,
                            "confidence": confidence,
                            "confidence_label": confidence_label,
                            "evidence_score": evidence_score,
                            "severity": severity,
                            "guarded": has_guard,
                            "source_sink_chain": has_chain,
                            "platform_hints": self._platform_hint(nearby),
                            "context": context,
                        }
                    )
                    results["total_findings"] += 1

        return results

    def analyze_dependencies(self, code_path: Path) -> Dict:
        dependencies = {
            "package.json": None,
            "requirements.txt": None,
            "go.mod": None,
            "Cargo.toml": None,
            "pom.xml": None,
        }
        for dep_file in dependencies:
            dep_path = code_path / dep_file
            if dep_path.exists():
                try:
                    with open(dep_path, "r", encoding="utf-8", errors="ignore") as f:
                        dependencies[dep_file] = f.read()
                except Exception as e:
                    print(f"    Error reading {dep_file}: {e}")
        return dependencies

    def _summarize_totals(self) -> Tuple[int, int]:
        total_servers = len(self.scan_results)
        total_findings = sum(r.get("total_findings", 0) for r in self.scan_results.values())
        return total_servers, total_findings

    def generate_report(
        self,
        results_path: Optional[Path] = None,
        report_path: Optional[Path] = None,
        summary_path: Optional[Path] = None,
        run_meta: Optional[Dict[str, Any]] = None,
    ):
        results_path = results_path or RESULTS_FILE
        report_path = report_path or REPORT_FILE
        summary_path = summary_path or SUMMARY_FILE
        print("\nGenerating report...")
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)

        agg = aggregate_scan_results(self.scan_results)
        summary_out = {
            "generated_at": datetime.now().isoformat(),
            "aggregate_over_scanned_servers": agg,
        }
        if run_meta:
            summary_out["run"] = run_meta
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_out, f, indent=2, ensure_ascii=False)
        print(f"Summary saved to: {summary_path}")
        print(
            f"  Servers with ≥1 finding: {agg['servers_with_at_least_one_finding']} / {agg['servers_in_results']} in results file"
        )
        print(f"  Total findings: {agg['total_findings']}")
        for rid, cnt in sorted(agg["findings_by_rule_id"].items(), key=lambda x: (-x[1], x[0])):
            if cnt:
                print(f"    {rid}: {cnt}")
        print(f"    (9 rule ids; zero-hit rules omitted in console)")

        if report_path is None:
            print("Markdown report skipped (use --write-markdown for a full mcp_code_scan_report.md).")
        else:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("# MCP Server Code Security Scan Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("---\n\n")

                total_servers, total_findings = self._summarize_totals()
                f.write("## Summary\n\n")
                f.write(f"- **Total servers scanned:** {total_servers}\n")
                f.write(f"- **Total findings (deduplicated):** {total_findings}\n")
                f.write("- **Method:** Risk rules with dedup and guard-aware weak/strong tiers; capability buckets for surface reporting\n\n")

                f.write("## Detailed Results\n\n")
                for server_name, results in self.scan_results.items():
                    server_info = results.get("server_info", {})
                    f.write(f"### {server_name}\n\n")
                    if server_info.get("description"):
                        f.write(f"- **Description:** {server_info['description']}\n")
                    if server_info.get("url"):
                        f.write(f"- **Repository:** {server_info['url']}\n")
                    if server_info.get("stars", 0) > 0:
                        f.write(f"- **Stars:** {server_info['stars']}\n")
                    f.write(f"- **Code path:** `{results.get('code_path', 'N/A')}`\n")
                    f.write(f"- **Files scanned:** {results.get('files_scanned', 0)}\n")
                    f.write(f"- **Total findings:** {results.get('total_findings', 0)}\n")
                    conf = results.get("findings_by_confidence", {})
                    evc = results.get("findings_by_evidence_confidence", {})
                    f.write(
                        f"- **Chain tier (guard/source–sink):** Weak={conf.get('weak', 0)}, "
                        f"Strong={conf.get('strong', 0)}\n"
                    )
                    f.write(
                        f"- **Evidence confidence (1=Uncertain, 2=Probable):** "
                        f"1={evc.get('1', 0)}, 2={evc.get('2', 0)}\n\n"
                    )

                    caps = results.get("capabilities", {})
                    if caps:
                        f.write("#### Capability Surface\n\n")
                        for cap_name, cap_count in sorted(caps.items(), key=lambda x: (-x[1], x[0])):
                            f.write(f"- {cap_name.replace('_', ' ').title()}: {cap_count} files\n")
                        f.write("\n")

                    if results.get("risks"):
                        f.write("#### Risk Findings\n\n")
                        for family, issues in sorted(results["risks"].items(), key=lambda x: (-len(x[1]), x[0])):
                            if not issues:
                                continue
                            f.write(f"**{family.replace('_', ' ').title()}:** {len(issues)} findings\n\n")
                            for issue in issues[:5]:
                                f.write(
                                    f"- `{issue['file']}:{issue['line']}` "
                                    f"[{issue['rule_id']}] "
                                    f"evidence={issue.get('confidence_label', '?')}({issue.get('confidence', '?')}) "
                                    f"chain={issue.get('chain_confidence', issue.get('confidence', '?'))} "
                                    f"sev={issue['severity']} guarded={issue['guarded']} match=`{issue['match']}`\n"
                                )
                            if len(issues) > 5:
                                f.write(f"- ... and {len(issues) - 5} more findings\n")
                            f.write("\n")
                    f.write("---\n\n")
        print(f"Results saved to: {results_path}")
        if report_path is not None:
            print(f"Report saved to: {report_path}")


_thread_local = threading.local()


def _thread_scanner() -> MCPServerCodeScanner:
    if not hasattr(_thread_local, "scanner"):
        _thread_local.scanner = MCPServerCodeScanner()
    return _thread_local.scanner


def _process_one_server(server: Dict) -> Tuple[str, str, Optional[Dict]]:
    """
    Returns: (status, server_name, scan_results_or_none)
    status in: ok, no_repo, clone_failed
    """
    scanner = _thread_scanner()
    server_name = server.get("full_name") or server.get("name", "Unknown")
    repo_url = scanner.get_repository_url(server)
    if not repo_url:
        return ("no_repo", server_name, None)
    code_path = scanner.clone_or_download_code(repo_url, server_name)
    if not code_path:
        return ("clone_failed", server_name, None)
    scan_results = scanner.scan_code_directory(code_path, server_name)
    scan_results["dependencies"] = scanner.analyze_dependencies(code_path)
    scan_results["server_info"] = {
        "name": server.get("name"),
        "full_name": server.get("full_name"),
        "description": server.get("description"),
        "url": server.get("url"),
        "source": server.get("source"),
        "stars": server.get("stars", 0),
    }
    return ("ok", server_name, scan_results)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP server code scanner with weak/strong static tiers")
    parser.add_argument(
        "--max-servers",
        type=int,
        default=50,
        help="After dedupe, cap how many servers to process. 0 = all deduplicated rows.",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Use raw registry rows (may exceed logical server count due to version duplicates).",
    )
    parser.add_argument("--workers", type=int, default=4, help="Parallel clone+scan threads")
    parser.add_argument("--resume", action="store_true", help="Skip servers already present in the results JSON")
    parser.add_argument(
        "--results-json",
        type=str,
        default="",
        help="Override path for mcp_code_scan_results.json",
    )
    parser.add_argument("--server-filter", type=str, default="", help="Only scan servers whose name/url contains this text")
    parser.add_argument(
        "--write-markdown",
        action="store_true",
        help="Write mcp_code_scan_report.md (can be very large for full registry runs).",
    )
    parser.add_argument(
        "--rebuild-summary-only",
        type=str,
        default="",
        metavar="RESULTS.json",
        help="Load an existing mcp_code_scan_results.json, rewrite mcp_code_scan_summary.json, and exit (no clone/scan).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.rebuild_summary_only:
        _ensure_scan_dirs()
    if args.rebuild_summary_only:
        p = Path(args.rebuild_summary_only)
        out = p.with_name("mcp_code_scan_summary.json")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        agg = aggregate_scan_results(data)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(
                {"generated_at": datetime.now().isoformat(), "aggregate_over_scanned_servers": agg, "source_results": str(p)},
                f,
                indent=2,
                ensure_ascii=False,
            )
        print(f"Wrote {out} (servers in file: {agg['servers_in_results']})")
        return

    print("=" * 60)
    print("MCP Server Code Security Scanner (risk rules + weak/strong tiers; capability surface reporting)")
    print("=" * 60)

    results_path = Path(args.results_json) if args.results_json else RESULTS_FILE
    report_path: Optional[Path] = results_path.with_name("mcp_code_scan_report.md")
    if args.results_json == "":
        report_path = REPORT_FILE
    summary_path = results_path.with_name("mcp_code_scan_summary.json")

    scanner = MCPServerCodeScanner()
    raw = scanner.fetch_anthropic_registry_servers()
    servers = raw if args.no_dedupe else deduplicate_registry_rows(raw)
    if args.server_filter:
        needle = args.server_filter.lower()
        servers = [
            s
            for s in servers
            if needle in str(s.get("name", "")).lower()
            or needle in str(s.get("full_name", "")).lower()
            or needle in str(s.get("url", "")).lower()
        ]

    if not servers:
        print("No MCP servers found in registry.")
        print("You may need to run fetch_mcp_registry_servers.py first.")
        return

    cap = len(servers) if args.max_servers == 0 else min(args.max_servers, len(servers))
    batch = servers[:cap]
    print(f"\nRegistry rows: {len(raw)}; using {len(servers)} after filter; processing {len(batch)} servers (cap={args.max_servers})")

    if args.resume and results_path.exists():
        try:
            with open(results_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                scanner.scan_results.update(existing)
                done = set(existing.keys())
                batch = [s for s in batch if (s.get("full_name") or s.get("name", "Unknown")) not in done]
                print(f"Resume: loaded {len(existing)} results; {len(batch)} servers left to scan")
        except Exception as e:
            print(f"Resume: could not read {results_path}: {e}")

    stats = {"no_repo": 0, "clone_failed": 0, "ok": 0}
    lock = threading.Lock()
    completed = 0
    max_workers = max(1, int(args.workers))

    def save_partial():
        with lock:
            snap = dict(scanner.scan_results)
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, ensure_ascii=False)
        agg = aggregate_scan_results(snap)
        partial = {
            "generated_at": datetime.now().isoformat(),
            "partial": True,
            "aggregate_over_scanned_servers": agg,
            "counters": dict(stats),
            "pending_remaining": len(batch) - completed,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(partial, f, indent=2, ensure_ascii=False)

    report_for_md: Optional[Path] = report_path if (cap <= 200 or args.write_markdown) else None

    if not batch:
        print("Nothing to scan.")
        scanner.generate_report(
            results_path, report_for_md, summary_path, run_meta={"note": "resume only"}
        )
        return

    if max_workers == 1:
        for server in batch:
            status, server_name, scan_results = _process_one_server(server)
            stats[status] = stats.get(status, 0) + 1
            if status == "ok" and scan_results:
                scanner.scan_results[server_name] = scan_results
            completed += 1
            if completed % SAVE_EVERY_N == 0:
                save_partial()
                print(f"  Progress: {completed}/{len(batch)}  stats={stats}")
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_process_one_server, s) for s in batch]
            for fut in as_completed(futs):
                try:
                    status, server_name, scan_results = fut.result()
                except Exception as e:
                    with lock:
                        stats["clone_failed"] = stats.get("clone_failed", 0) + 1
                    print(f"  Worker error: {e}")
                    completed += 1
                    continue
                with lock:
                    stats[status] = stats.get(status, 0) + 1
                    if status == "ok" and scan_results:
                        scanner.scan_results[server_name] = scan_results
                completed += 1
                if completed % SAVE_EVERY_N == 0:
                    save_partial()
                    print(f"  Progress: {completed}/{len(batch)}  stats={stats}")

    run_meta = {
        "registry_raw_rows": len(raw),
        "deduplicated_rows": len(servers) if not args.no_dedupe else None,
        "processed_cap": cap,
        "workers": max_workers,
        "counters": stats,
        "note": "Per-server JSON entries are successful clone+scan only; aggregate 'servers with findings' is over that set. no_repo/clone_failed counts are in counters, not as per-server rows.",
    }
    scanner.generate_report(results_path, report_for_md, summary_path, run_meta=run_meta)
    print("\n" + "=" * 60)
    print("Scan completed!")
    print(f"  ok={stats.get('ok',0)} no_repo={stats.get('no_repo',0)} clone_failed={stats.get('clone_failed',0)}")
    print(f"Results: {results_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
