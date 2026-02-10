#!/usr/bin/env python3
"""
Summarize scan report (streaming) and/or rule violation summary from package-level stats.
Modes: scan-report (default), rule-violation.
"""

import argparse
import json
import re
import codecs
from tempfile import NamedTemporaryFile
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, List

try:
    import ijson
    HAS_IJSON = True
except ImportError:
    HAS_IJSON = False
    print("[WARN] ijson not available. Install with: pip install ijson")
    print("[WARN] Will attempt to use regular JSON loading (may use more memory)")


CONTROL_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
INPUT_FILE = "../data/scan_result/scan_report_20260115_npm_only.json"
OUTPUT_FILE = "../data/summary_result/summary_20260115_npm_only.json"
TOPN = 100
ASYM_EXAMPLE_LIMIT = 100
I18N_EXAMPLE_LIMIT = 200
MIT_EXAMPLE_LIMIT = 200
DEP_EXAMPLE_LIMIT = 150
I18N_RULE = "I18N_NON_EN"
LICENSE_RULE = "LICENSE"

RULE_CATEGORY: Dict[str, str] = {
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
    "EXT_FAKE_NPM": "SUPPLYCHAIN",
    "VERSION_MISMATCH": "SUPPLYCHAIN",
}

ALL_RULES = sorted(set(RULE_CATEGORY.keys()))
ALL_CATEGORIES = sorted(set(RULE_CATEGORY.values()))

PKG_LEVEL_STATS_INPUT = "../data/summary_result/package_level_stats_20260115.json"
RULE_VIOLATION_OUTPUT = "../data/summary_result/summary_20260115.json"

HTML_RULES = {"HTML_UNSANITIZED"}

EXEC_RULES = {
    "COMMAND_EXEC",
    "VM_DYNAMIC",
    "EVAL_DYNAMIC",
    "DYNAMIC_REQUIRE",
    "DYNAMIC_IMPORT",
    "DYNAMIC_REGEX",
    "DESERIALIZE",
}

DYNAMIC_LOAD_RULES = {"DYNAMIC_REQUIRE", "DYNAMIC_IMPORT"}

NETWORK_RULES = {
    "EXT_HTTP_CALL",
    "EXT_HTTP_IMPORT",
    "EXT_HTTP_DEP",
    "RAW_NET",
    "HTTP_PROTO",
    "SSRF_HOST",
    "PROXY_TUNNEL",
    "EXFIL_SDK_CALL",
    "REMOTE_SHELL_CALL",
}

DESERIALIZE_RULES = {"DESERIALIZE"}

EXCLUDED_FOR_TOPN = {I18N_RULE}

EMOJI_RE = re.compile(r"[\U0001F300-\U0001FAFF\U00002700-\U000027BF]")
CJK_RE = re.compile(r"[\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]")
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")
UI_KEY_NAME_RE = re.compile(
    r"\b(displayName|description|placeholder|hint|help|tooltip|sample|examples?)\b",
    re.I,
)


def _safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


def _norm_ver(v: Any) -> str:
    if not isinstance(v, str):
        return ""
    s = v.strip()
    if not s:
        return ""
    if s[:1] in ("v", "V"):
        s = s[1:]
    for sep in ("+", "-"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def _parse_semver_triplet(v: str):
    if not v:
        return (0, 0, 0, False)
    parts = v.split(".")
    if len(parts) < 3:
        parts += ["0"] * (3 - len(parts))
    nums = []
    ok = False
    for p in parts[:3]:
        try:
            n = int(p)
            nums.append(n)
            ok = True or ok
        except Exception:
            nums.append(0)
    return (nums[0], nums[1], nums[2], ok)


def _compare_versions(npm_v: Any, gh_v: Any):
    npm_raw, gh_raw = npm_v, gh_v
    if not npm_raw and not gh_raw:
        return "unparsable", "both versions missing"
    if not npm_raw:
        return "missing_npm_version", "npm version missing"
    if not gh_raw:
        return "missing_github_version", "github version missing"

    npm_norm = _norm_ver(npm_raw)
    gh_norm = _norm_ver(gh_raw)
    nM, nm, np, ok_npm = _parse_semver_triplet(npm_norm)
    gM, gm, gp, ok_gh = _parse_semver_triplet(gh_norm)

    if not ok_npm and not ok_gh:
        return "unparsable", f"unparsable semver: npm='{npm_raw}', github='{gh_raw}'"
    if not ok_npm:
        return "unparsable", f"unparsable npm semver: '{npm_raw}'"
    if not ok_gh:
        return "unparsable", f"unparsable github semver: '{gh_raw}'"

    if (nM, nm, np) == (gM, gm, gp):
        return "equal", "same normalized semver"
    if (nM, nm, np) > (gM, gm, gp):
        return "npm_newer", f"{npm_norm} > {gh_norm}"
    else:
        return "github_newer", f"{gh_norm} > {npm_norm}"


def _clean_file_to_temp(src_path: Path, chunk_size: int = 8 * 1024 * 1024) -> Path | None:
    """Read source in chunks, strip control chars to a temp file; return path or None."""
    try:
        tmp_file = NamedTemporaryFile(delete=False, suffix=".cleaned.json", mode="w", encoding="utf-8")
        tmp_path = Path(tmp_file.name)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="ignore")
        with src_path.open("rb") as fin, tmp_file as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                text = CONTROL_REGEX.sub("", text)
                fout.write(text)
            tail = decoder.decode(b"", final=True)
            if tail:
                fout.write(CONTROL_REGEX.sub("", tail))
        return tmp_path
    except Exception as exc:
        print(f"[ERROR] Failed to clean file: {exc}")
        return None


def _clean_package_dict(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively strip control chars from dict (mainly in string fields)."""
    if isinstance(pkg, dict):
        cleaned = {}
        for k, v in pkg.items():
            cleaned[k] = _clean_package_dict(v)
        return cleaned
    elif isinstance(pkg, list):
        return [_clean_package_dict(item) for item in pkg]
    elif isinstance(pkg, str):
        return CONTROL_REGEX.sub("", pkg)
    else:
        return pkg


def _process_package(item: Dict[str, Any], stats: Dict[str, Any]):
    """Process one package and update stats."""
    name = item.get("npm_name") or "<unknown>"
    source_used = item.get("source_used")
    stats["source_used_dist"][source_used or "none"] += 1

    any_error = False
    scanned_npm = False

    # fraud
    fraud = item.get("fraud")
    if fraud and fraud.get("rule") == "OFFICIAL_REPO_IMPERSONATION":
        stats["fraud_count"] += 1
        stats["fraud_list"].append({
            "npm_name": name,
            "message": fraud.get("message", ""),
            "repo_url": (item.get("github_repo") or {}).get("url"),
        })

    scan = item.get("scan") or {}
    npm = scan.get("npm")
    if npm:
        scanned_npm = True
        stats["scanned_npm_pkgs"] += 1
        stats["files_scanned_npm_sum"] += _safe_int((npm.get("meta") or {}).get("files_scanned"))
    if npm:
        findings = npm.get("findings") or []

        for f in findings:
            rule = (f.get("rule") or "").strip() or "UNKNOWN"
            sev = (f.get("severity") or "").lower() or "error"

            stats["by_rule"][rule] += 1
            stats["by_rule_src"]["npm"][rule] += 1

            cat = RULE_CATEGORY.get(rule)
            if cat:
                stats["by_category"][cat] += 1
                stats["by_category_src"]["npm"][cat] += 1

            if sev == "error" and rule not in EXCLUDED_FOR_TOPN:
                stats["by_pkg_total_errors"][name] += 1
                stats["by_pkg_rule_breakdown"][name][rule] += 1
                stats["by_pkg_source_breakdown"][name]["npm"] += 1
                any_error = True

            stats["harvest_panels"]("npm", f)
            stats["harvest_i18n"](name, "npm", f)
            stats["harvest_mit"](name, "npm", f)

        deps = (npm.get("meta") or {}).get("deps_collected") or []
        for d in deps:
            stats["deps_total"] += 1
            if (d.get("is_network_suspect") == "yes") and (d.get("is_tooling") != "yes"):
                stats["deps_network_total"] += 1
                dep_name = d.get("module") or d.get("full_spec") or "<unknown>"
                stats["deps_network_counter"][dep_name] += 1
                stats["deps_network_by_kind"][d.get("dep_kind") or "unknown"] += 1
                if len(stats["deps_network_examples"]) < DEP_EXAMPLE_LIMIT:
                    stats["deps_network_examples"].append({
                        "npm_name": name,
                        "source": "npm",
                        "dep_kind": d.get("dep_kind"),
                        "module": dep_name,
                        "reason": d.get("reason", ""),
                        "version_spec": d.get("version_spec", ""),
                    })

    cons = item.get("consistency") or {}
    status = (cons.get("status") or "unknown").lower()
    if status not in ("match", "mismatch", "unknown", "npm_only"):
        status = "unknown"
    stats["consistency_dist"][status] += 1

    npm_ver = cons.get("npm_version") or item.get("npm_version")
    gh_ver = cons.get("github_version")
    asym_status, asym_reason = _compare_versions(npm_ver, gh_ver)
    stats["asym_counts"][asym_status] += 1
    if asym_status != "equal" and len(stats["asym_examples"]) < ASYM_EXAMPLE_LIMIT:
        stats["asym_examples"].append({
            "npm_name": name,
            "npm_version": npm_ver,
            "github_version": gh_ver,
            "status": asym_status,
            "reason": asym_reason,
            "consistency_status": status,
            "consistency_details": cons.get("details", ""),
        })

    if not any_error:
        stats["zero_error_pkgs"] += 1
    if scanned_npm and not any_error:
        stats["zero_error_pkgs_strict"] += 1


def run_rule_violation_summary(input_file: str, output_file: str) -> None:
    """From package_level_stats JSON, compute per-rule and per-category violation counts and percentages; write summary JSON."""
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_file}")
        return
    print(f"[INFO] Reading {input_file}...")
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    packages = data.get("packages", [])
    total_packages = len(packages)
    if total_packages == 0:
        print("[ERROR] No packages found in input file")
        return
    print(f"[INFO] Processing {total_packages} packages...")
    rule_violations = {
        "error": defaultdict(int),
        "warn": defaultdict(int),
        "info": defaultdict(int),
        "total": defaultdict(int),
    }
    category_violations = {
        "error": defaultdict(int),
        "warn": defaultdict(int),
        "info": defaultdict(int),
        "total": defaultdict(int),
    }
    for pkg in packages:
        for rule in ALL_RULES:
            rule_total = pkg.get(f"{rule}_T", 0) or 0
            rule_error = pkg.get(f"{rule}_E", 0) or 0
            rule_warn = pkg.get(f"{rule}_W", 0) or 0
            rule_info = pkg.get(f"{rule}_I", 0) or 0
            if rule_total > 0:
                rule_violations["total"][rule] += 1
            if rule_error > 0:
                rule_violations["error"][rule] += 1
            if rule_warn > 0:
                rule_violations["warn"][rule] += 1
            if rule_info > 0:
                rule_violations["info"][rule] += 1
        for category in ALL_CATEGORIES:
            cat_total = pkg.get(f"{category}_T", 0) or 0
            cat_error = pkg.get(f"{category}_E", 0) or 0
            cat_warn = pkg.get(f"{category}_W", 0) or 0
            cat_info = pkg.get(f"{category}_I", 0) or 0
            if cat_total > 0:
                category_violations["total"][category] += 1
            if cat_error > 0:
                category_violations["error"][category] += 1
            if cat_warn > 0:
                category_violations["warn"][category] += 1
            if cat_info > 0:
                category_violations["info"][category] += 1
    rule_stats = {}
    for rule in ALL_RULES:
        rule_stats[rule] = {
            "violations_error": rule_violations["error"][rule],
            "violations_warn": rule_violations["warn"][rule],
            "violations_info": rule_violations["info"][rule],
            "violations_total": rule_violations["total"][rule],
            "percentage_error": round(100.0 * rule_violations["error"][rule] / total_packages, 2),
            "percentage_warn": round(100.0 * rule_violations["warn"][rule] / total_packages, 2),
            "percentage_info": round(100.0 * rule_violations["info"][rule] / total_packages, 2),
            "percentage_total": round(100.0 * rule_violations["total"][rule] / total_packages, 2),
            "category": RULE_CATEGORY.get(rule, "UNKNOWN"),
        }
    category_stats = {}
    for category in ALL_CATEGORIES:
        category_stats[category] = {
            "violations_error": category_violations["error"][category],
            "violations_warn": category_violations["warn"][category],
            "violations_info": category_violations["info"][category],
            "violations_total": category_violations["total"][category],
            "percentage_error": round(100.0 * category_violations["error"][category] / total_packages, 2),
            "percentage_warn": round(100.0 * category_violations["warn"][category] / total_packages, 2),
            "percentage_info": round(100.0 * category_violations["info"][category] / total_packages, 2),
            "percentage_total": round(100.0 * category_violations["total"][category] / total_packages, 2),
        }
    output = {
        "meta": {
            "input_file": input_file,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "total_packages": total_packages,
            "note": "violations = number of packages that violate this rule; percentage = violations / total_packages * 100",
        },
        "by_rule": rule_stats,
        "by_category": category_stats,
        "top_violations_by_rule": {
            "error": sorted(
                [(r, rule_stats[r]["violations_error"], rule_stats[r]["percentage_error"]) for r in ALL_RULES if rule_stats[r]["violations_error"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
            "warn": sorted(
                [(r, rule_stats[r]["violations_warn"], rule_stats[r]["percentage_warn"]) for r in ALL_RULES if rule_stats[r]["violations_warn"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
            "total": sorted(
                [(r, rule_stats[r]["violations_total"], rule_stats[r]["percentage_total"]) for r in ALL_RULES if rule_stats[r]["violations_total"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
        },
        "top_violations_by_category": {
            "error": sorted(
                [(c, category_stats[c]["violations_error"], category_stats[c]["percentage_error"]) for c in ALL_CATEGORIES if category_stats[c]["violations_error"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
            "warn": sorted(
                [(c, category_stats[c]["violations_warn"], category_stats[c]["percentage_warn"]) for c in ALL_CATEGORIES if category_stats[c]["violations_warn"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
            "total": sorted(
                [(c, category_stats[c]["violations_total"], category_stats[c]["percentage_total"]) for c in ALL_CATEGORIES if category_stats[c]["violations_total"] > 0],
                key=lambda x: x[1], reverse=True,
            ),
        },
    }
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(output_file).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Summary saved -> {output_file}")
    print(f"[+] Total packages: {total_packages}")
    print(f"[+] Rules with violations: {sum(1 for r in ALL_RULES if rule_stats[r]['violations_total'] > 0)}")
    print(f"[+] Categories with violations: {sum(1 for c in ALL_CATEGORIES if category_stats[c]['violations_total'] > 0)}")
    top_errors = output["top_violations_by_rule"]["error"][:10]
    print("\n[Top 10 rules by error violations]:")
    for i, (rule, count, pct) in enumerate(top_errors, 1):
        print(f"  {i}. {rule}: {count} packages ({pct}%)")


def main_scan_report(input_file: str, output_file: str) -> None:
    input_path = Path(input_file)
    cleaned_path = _clean_file_to_temp(input_path)
    if cleaned_path is None:
        print("[ERROR] Cleaning input file failed; aborting.")
        return

    print(f"[INFO] Cleaned input written to: {cleaned_path}")
    stats = {
        "by_rule": Counter(),
        "by_rule_src": {"npm": Counter()},
        "by_category": Counter(),
        "by_category_src": {"npm": Counter()},
        "by_pkg_total_errors": Counter(),
        "by_pkg_rule_breakdown": defaultdict(Counter),
        "by_pkg_source_breakdown": defaultdict(Counter),
        "scanned_npm_pkgs": 0,
        "files_scanned_npm_sum": 0,
        "consistency_dist": Counter(),
        "source_used_dist": Counter(),
        "fraud_count": 0,
        "fraud_list": [],
        "asym_counts": Counter(),
        "asym_examples": [],
        "zero_error_pkgs": 0,
        "zero_error_pkgs_strict": 0,
        "packages_with_i18n_error": set(),
        "i18n_error_sum": 0,
        "i18n_by_source": Counter(),
        "i18n_examples": [],
        "ui_key_breakdown": Counter(),
        "emoji_hits": 0,
        "cjk_hits": 0,
        "other_unicode_hits": 0,
        "packages_with_mit_issue": set(),
        "mit_issue_sum": 0,
        "mit_by_source": Counter(),
        "mit_examples": [],
        "html_unsanitized_cnt": Counter(),
        "exec_cnt": Counter(),
        "dynload_cnt": Counter(),
        "network_cnt": Counter(),
        "deserialize_cnt": Counter(),
        "deps_network_counter": Counter(),
        "deps_network_examples": [],
        "deps_network_by_kind": Counter(),
        "deps_total": 0,
        "deps_network_total": 0,
    }
    def harvest_i18n(npm_name: str, source: str, f: Dict[str, Any]):
        if f.get("rule") != I18N_RULE:
            return
        stats["i18n_error_sum"] += 1
        stats["packages_with_i18n_error"].add(npm_name)
        stats["i18n_by_source"][source] += 1
        code_snip = f.get("code_snippet") or ""
        key_match = UI_KEY_NAME_RE.search(code_snip)
        key_name = (key_match.group(1).lower() if key_match else "unknown")
        stats["ui_key_breakdown"][key_name] += 1
        txt = f.get("matched_text") or code_snip
        if txt:
            if EMOJI_RE.search(txt):
                stats["emoji_hits"] += 1
            if CJK_RE.search(txt):
                stats["cjk_hits"] += 1
            elif NON_ASCII_RE.search(txt):
                stats["other_unicode_hits"] += 1
        if len(stats["i18n_examples"]) < I18N_EXAMPLE_LIMIT:
            stats["i18n_examples"].append({
                "npm_name": npm_name,
                "source": source,
                "file": f.get("file"),
                "matched_text": (f.get("matched_text") or "")[:200],
                "snippet": (code_snip or "")[:300]
            })
    
    def harvest_mit(npm_name: str, source: str, f: Dict[str, Any]):
        if f.get("rule") != LICENSE_RULE:
            return
        stats["mit_issue_sum"] += 1
        stats["packages_with_mit_issue"].add(npm_name)
        stats["mit_by_source"][source] += 1
        if len(stats["mit_examples"]) < MIT_EXAMPLE_LIMIT:
            stats["mit_examples"].append({
                "npm_name": npm_name,
                "source": source,
                "file": f.get("file"),
                "severity": f.get("severity"),
                "message": f.get("message"),
                "snippet": (f.get("code_snippet") or "")[:300]
            })
    
    def harvest_panels(source: str, f: Dict[str, Any]):
        rule = (f.get("rule") or "").strip()
        if rule in HTML_RULES:
            stats["html_unsanitized_cnt"][source] += 1
        if rule in EXEC_RULES:
            stats["exec_cnt"][source] += 1
        if rule in DYNAMIC_LOAD_RULES:
            stats["dynload_cnt"][source] += 1
        if rule in NETWORK_RULES:
            stats["network_cnt"][source] += 1
        if rule in DESERIALIZE_RULES:
            stats["deserialize_cnt"][source] += 1
    
    stats["harvest_i18n"] = harvest_i18n
    stats["harvest_mit"] = harvest_mit
    stats["harvest_panels"] = harvest_panels
    total_pkgs = 0
    counters_from_scan = {}
    if HAS_IJSON:
        print("[INFO] Using streaming JSON parser (ijson)...")
        try:
            with open(cleaned_path, "rb") as f:
                packages_parser = ijson.items(f, "packages.item")
                skipped = 0
                for pkg in packages_parser:
                    total_pkgs += 1
                    if total_pkgs % 1000 == 0:
                        print(f"[INFO] Processed {total_pkgs} packages...")
                    try:
                        pkg_cleaned = _clean_package_dict(pkg)
                        _process_package(pkg_cleaned, stats)
                    except Exception as e:
                        skipped += 1
                        if skipped <= 5:
                            print(f"[WARN] Skipped package {pkg.get('npm_name', 'unknown')}: {e}")
                if skipped > 0:
                    print(f"[WARN] Skipped {skipped} packages due to errors")
                try:
                    f.seek(0)
                    parser = ijson.parse(f)
                    current_key = None
                    counters_dict = {}
                    for prefix, event, value in parser:
                        if prefix == "counters" and event == "map_key":
                            current_key = value
                        elif prefix.startswith("counters.") and event in ("number", "string"):
                            key = prefix.split(".", 1)[1]
                            counters_dict[key] = value
                    if counters_dict:
                        counters_from_scan = counters_dict
                except Exception as e:
                    print(f"[WARN] Could not read counters from stream: {e}, will try to read from full parse if needed")
        except Exception as e:
            print(f"[WARN] Streaming parse failed: {e}, falling back to regular parse")
            total_pkgs = 0
    if total_pkgs > 0 and not counters_from_scan:
        print("[INFO] Streaming parse succeeded but counters not found, attempting to read counters separately...")
        try:
            with open(cleaned_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                counters_from_scan = data.get("counters", {})
                if counters_from_scan:
                    print("[INFO] Successfully read counters from full parse")
        except Exception as e:
            print(f"[WARN] Could not read counters separately: {e}")
    if total_pkgs == 0:
        print("[INFO] Using regular JSON loading (may use more memory)...")
        try:
            with open(cleaned_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[WARN] strict JSON load failed at pos {e.pos}, retrying with strict=False and extra cleaning...")
            text = Path(cleaned_path).read_text(encoding="utf-8", errors="ignore")
            text = CONTROL_REGEX.sub("", text)
            data = json.loads(text, strict=False)

        pkgs = data.get("packages", [])
        total_pkgs = len(pkgs)
        for item in pkgs:
            item_cleaned = _clean_package_dict(item)
            _process_package(item_cleaned, stats)
        counters_from_scan = data.get("counters", {})

    topn = []
    for pkg_name, cnt in stats["by_pkg_total_errors"].most_common(TOPN):
        topn.append({
            "npm_name": pkg_name,
            "error_count": cnt,
            "rule_breakdown": dict(stats["by_pkg_rule_breakdown"][pkg_name]),
            "source_breakdown": dict(stats["by_pkg_source_breakdown"][pkg_name]),
        })

    deps_top = [{"module": m, "count": c} for m, c in stats["deps_network_counter"].most_common(50)]

    out = {
        "meta": {
            "input_file": input_file,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "note": "by_repo_topN excludes I18N_NON_EN and counts only severity=='error'; by_rule includes all severities.",
            "excluded_for_topn": sorted(list(EXCLUDED_FOR_TOPN)),
        },
        "totals": {
            "packages": total_pkgs,
            "findings_sum_all_severities": int(sum(stats["by_rule"].values())),
            "scanned_npm_pkgs": stats["scanned_npm_pkgs"],
            "files_scanned_sum": {
                "npm": stats["files_scanned_npm_sum"],
            },
            "packages_zero_error": stats["zero_error_pkgs"],
            "packages_zero_error_strict": stats["zero_error_pkgs_strict"],
            "pass_rate": round(100.0 * stats["zero_error_pkgs"] / total_pkgs, 2) if total_pkgs else 0.0,
            "pass_rate_strict": round(100.0 * stats["zero_error_pkgs_strict"] / total_pkgs, 2) if total_pkgs else 0.0,
        },
        "by_rule": dict(stats["by_rule"]),
        "by_rule_source": {
            "npm": dict(stats["by_rule_src"]["npm"]),
        },
        "by_category": dict(stats["by_category"]),
        "by_category_source": {
            "npm": dict(stats["by_category_src"]["npm"]),
        },
        "by_repo_topN": topn,
        "consistency": {
            "distribution": dict(stats["consistency_dist"]),
        },
        "version_asymmetry": {
            "counts": dict(stats["asym_counts"]),
            "examples": stats["asym_examples"],
        },
        "source_used": dict(stats["source_used_dist"]),
        "fraud": {
            "count": stats["fraud_count"],
            "items": stats["fraud_list"],
        },
        "html_sanitization_overview": {
            "rules": sorted(list(HTML_RULES)),
            "counts_by_source": dict(stats["html_unsanitized_cnt"]),
        },
        "code_execution_overview": {
            "rules": sorted(list(EXEC_RULES)),
            "counts_by_source": dict(stats["exec_cnt"]),
        },
        "dynamic_loading_overview": {
            "rules": sorted(list(DYNAMIC_LOAD_RULES)),
            "counts_by_source": dict(stats["dynload_cnt"]),
        },
        "network_risk_overview": {
            "rules": sorted(list(NETWORK_RULES)),
            "counts_by_source": dict(stats["network_cnt"]),
        },
        "deserialization_overview": {
            "rules": sorted(list(DESERIALIZE_RULES)),
            "counts_by_source": dict(stats["deserialize_cnt"]),
        },
        "deps_network_summary": {
            "deps_total": stats["deps_total"],
            "network_suspect_total": stats["deps_network_total"],
            "by_dep_kind": dict(stats["deps_network_by_kind"]),
            "top_network_suspect_deps": deps_top,
            "examples": stats["deps_network_examples"],
            "note": "Network-suspect deps = is_network_suspect=='yes' and is_tooling!='yes'.",
        },
        "english_compliance": {
            "packages_with_i18n_error": len(stats["packages_with_i18n_error"]),
            "i18n_error_sum": stats["i18n_error_sum"],
            "pass_rate_english_only": round(
                100.0 * (total_pkgs - len(stats["packages_with_i18n_error"])) / total_pkgs, 2
            ) if total_pkgs else 0.0,
            "i18n_by_source": dict(stats["i18n_by_source"]),
            "packages_with_i18n_error_examples": sorted(list(stats["packages_with_i18n_error"]))[:50],
        },
        "i18n_examples": stats["i18n_examples"],
        "i18n_breakdown": {
            "ui_key": dict(stats["ui_key_breakdown"]),
            "unicode_categories": {
                "emoji_hits": stats["emoji_hits"],
                "cjk_hits": stats["cjk_hits"],
                "other_unicode_hits": stats["other_unicode_hits"],
            },
        },
        "mit_license_compliance": {
            "packages_with_mit_issue": len(stats["packages_with_mit_issue"]),
            "mit_issue_sum": stats["mit_issue_sum"],
            "pass_rate_mit": round(
                100.0 * (total_pkgs - len(stats["packages_with_mit_issue"])) / total_pkgs, 2
            ) if total_pkgs else 0.0,
            "mit_by_source": dict(stats["mit_by_source"]),
            "packages_with_mit_issue_examples": sorted(list(stats["packages_with_mit_issue"]))[:50],
        },
        "mit_examples": stats["mit_examples"],
        "package_availability": {
            "npm_packages": {
                "scanned_successfully": counters_from_scan.get("scanned_npm", 0),
                "failed_to_download": counters_from_scan.get("npm_failed", 0),
                "total_attempted": counters_from_scan.get("scanned_npm", 0) + counters_from_scan.get("npm_failed", 0),
                "success_rate": round(
                    100.0 * counters_from_scan.get("scanned_npm", 0) / 
                    (counters_from_scan.get("scanned_npm", 0) + counters_from_scan.get("npm_failed", 0) or 1), 2
                ) if (counters_from_scan.get("scanned_npm", 0) + counters_from_scan.get("npm_failed", 0)) > 0 else 0.0,
            },
            "github_repositories": {
                "reachable": counters_from_scan.get("repo_ok", 0),
                "not_set": counters_from_scan.get("repo_not_set", 0),
                "unreachable": counters_from_scan.get("repo_unreachable", 0),
                "total_with_repo_url": counters_from_scan.get("repo_ok", 0) + counters_from_scan.get("repo_unreachable", 0),
                "reachability_rate": round(
                    100.0 * counters_from_scan.get("repo_ok", 0) / 
                    (counters_from_scan.get("repo_ok", 0) + counters_from_scan.get("repo_unreachable", 0) or 1), 2
                ) if (counters_from_scan.get("repo_ok", 0) + counters_from_scan.get("repo_unreachable", 0)) > 0 else 0.0,
            },
            "official_repo_impersonation": {
                "count": counters_from_scan.get("repo_impersonation", 0),
                "note": "Packages that claim to use the official n8n repository URL",
            },
            "note": "Statistics from scan counters. npm_failed includes packages that could not be downloaded from npm registry. repo_unreachable includes repositories that returned non-2xx/3xx status codes or connection errors.",
        },
    }

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(output_file).write_text(
        json.dumps(out, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[+] summary saved -> {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Summarize scan report and/or rule violation summary.")
    sub = parser.add_subparsers(dest="mode", help="Mode to run")
    p_scan = sub.add_parser("scan-report", help="Summarize raw scan report (streaming)")
    p_scan.add_argument("--input", "-i", default=INPUT_FILE, help="Scan report JSON path")
    p_scan.add_argument("--output", "-o", default=OUTPUT_FILE, help="Output summary JSON path")
    p_rule = sub.add_parser("rule-violation", help="Rule violation summary from package_level_stats")
    p_rule.add_argument("--input", "-i", default=PKG_LEVEL_STATS_INPUT, help="Package-level stats JSON path")
    p_rule.add_argument("--output", "-o", default=RULE_VIOLATION_OUTPUT, help="Output summary JSON path")
    args = parser.parse_args()
    if args.mode == "rule-violation":
        run_rule_violation_summary(args.input, args.output)
    else:
        if args.mode is None:
            main_scan_report(INPUT_FILE, OUTPUT_FILE)
        else:
            main_scan_report(args.input, args.output)


if __name__ == "__main__":
    main()
