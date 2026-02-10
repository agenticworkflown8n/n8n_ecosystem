#!/usr/bin/env python3
"""
Analyze MCP templates for presence of risky nodes.
Inputs: MCP template list, node risk analysis (mcp_nodes_risk_analysis.json), template files.
Outputs: count of templates with risky nodes, risk type distribution, high-risk template list.
"""

import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any, Set
from datetime import datetime


MCP_TEMPLATES_LIST = "../data/MULTI-AGENT/mcp_templates_list.txt"
NODE_RISK_ANALYSIS = "../data/scan_result/mcp_nodes_risk_analysis.json"
TEMPLATES_DIR = "../data/n8n_templates_dump/workflows"
OUTPUT_FILE = "../data/MULTI-AGENT/mcp_templates_risk_nodes_analysis.json"

HIGH_RISK_RULES = {
    "COMMAND_EXEC",
    "EVAL_DYNAMIC",
    "VM_DYNAMIC",
    "SSRF_HOST",
    "RAW_NET",
    "EXT_HTTP_CALL",
    "EXT_HTTP_IMPORT",
    "ENV_FS",
    "LOG_SENSITIVE",
    "REMOTE_SHELL_CALL",
    "INPUT_SECRET_UNMASKED",
    "HTML_UNSANITIZED",
    "BINARY_PREPARE",
}


MEDIUM_RISK_RULES = {
    "DYNAMIC_REQUIRE",
    "DYNAMIC_IMPORT",
    "DYNAMIC_REGEX",
    "DESERIALIZE",
    "EXT_HTTP_DEP",
    "PROXY_TUNNEL",
    "EXFIL_SDK_CALL",
    "BINARY_PREPARE_WEAK",
    "DELETE_RET_BOOL",
    "DATAURL_JSON",
}


def load_mcp_template_ids() -> Set[str]:
    """Load MCP template ID list from file."""
    template_ids = set()
    list_path = Path(MCP_TEMPLATES_LIST)
    
    if not list_path.exists():
        print(f"[WARN] MCP templates list not found: {list_path}")
        return template_ids
    
    with list_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if "ID" in line:

                import re
                match = re.search(r'ID\s+(\d+)', line)
                if match:
                    template_ids.add(match.group(1))

            elif line and line.isdigit():
                template_ids.add(line)
    
    print(f"[INFO] Loaded {len(template_ids)} MCP template IDs")
    return template_ids


def load_node_risks() -> Dict[str, Dict[str, Any]]:
    """Load node risk analysis results from JSON."""
    risk_path = Path(NODE_RISK_ANALYSIS)
    
    if not risk_path.exists():
        print(f"[WARN] Node risk analysis not found: {risk_path}")
        return {}
    
    with risk_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    

    risk_map = {}
    

    for pkg in data.get("top_risky_packages", []):
        npm_name = pkg.get("npm_name", "")
        if npm_name:
            risk_map[npm_name] = {
                "total_findings": pkg.get("findings_count", 0),
                "error_count": pkg.get("error_count", 0),
                "warn_count": pkg.get("warn_count", 0),
                "info_count": pkg.get("info_count", 0),
                "has_errors": pkg.get("has_errors", False),
                "has_warnings": pkg.get("has_warnings", False),
            }
    
    print(f"[INFO] Loaded risk info for {len(risk_map)} packages")
    return risk_map


def extract_nodes_from_template(template: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all nodes from template (handles multiple template formats)."""

    wf = template.get("workflow") or {}
    if "workflow" in wf and isinstance(wf["workflow"], dict):
        inner_nodes = wf["workflow"].get("nodes")
        if isinstance(inner_nodes, list) and inner_nodes:
            return inner_nodes

    nodes = wf.get("nodes")
    if isinstance(nodes, list):
        return nodes

    nodes = template.get("nodes")
    if isinstance(nodes, list):
        return nodes
    return []


def extract_node_types_from_template(template: Dict[str, Any]) -> List[str]:
    """Extract all node types from template."""
    node_types = []
    nodes = extract_nodes_from_template(template)
    
    for node in nodes:
        node_type = node.get("type", "")
        if not node_type:

            node_type = node.get("name", "")
        if node_type:
            node_types.append(node_type)
    
    return node_types


def normalize_package_name(node_type: str) -> str:
    """Normalize package name for matching risk analysis results."""
    return node_type.split(".")[0]


def analyze_template_risks(template: Dict[str, Any], node_risks: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze risks for a single template."""
    template_id, template_name = template_meta(template)
    
    node_types = extract_node_types_from_template(template)
    
    risky_nodes = []
    high_risk_nodes = []
    medium_risk_nodes = []
    all_node_packages = set()
    
    for node_type in node_types:
        pkg_name = normalize_package_name(node_type)
        all_node_packages.add(pkg_name)
        
        if pkg_name in node_risks:
            risk_info = node_risks[pkg_name]
            risky_nodes.append({
                "node_type": node_type,
                "package": pkg_name,
                "error_count": risk_info.get("error_count", 0),
                "warn_count": risk_info.get("warn_count", 0),
                "total_findings": risk_info.get("total_findings", 0),
            })
            
            if risk_info.get("has_errors", False):
                high_risk_nodes.append(pkg_name)
            if risk_info.get("has_warnings", False):
                medium_risk_nodes.append(pkg_name)
    
    return {
        "template_id": template_id,
        "template_name": template_name,
        "total_nodes": len(node_types),
        "unique_packages": len(all_node_packages),
        "risky_nodes": risky_nodes,
        "risky_node_count": len(risky_nodes),
        "high_risk_node_count": len(high_risk_nodes),
        "medium_risk_node_count": len(medium_risk_nodes),
        "has_high_risk": len(high_risk_nodes) > 0,
        "has_medium_risk": len(medium_risk_nodes) > 0,
        "has_any_risk": len(risky_nodes) > 0,
        "high_risk_packages": sorted(list(set(high_risk_nodes))),
        "medium_risk_packages": sorted(list(set(medium_risk_nodes))),
        "all_packages": sorted(list(all_node_packages)),
    }


def load_template(template_id: str, templates_dir: Path) -> Dict[str, Any] | None:
    """Load a single template file by ID."""
    possible_files = [
        templates_dir / f"{template_id}.json",
        templates_dir / f"workflow_{template_id}.json",
    ]
    
    for file_path in possible_files:
        if file_path.exists():
            try:
                with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load template {template_id} from {file_path}: {e}")
    
    return None


def template_meta(template: Dict[str, Any]) -> tuple:
    """Get template id and name."""

    tid = template.get("id") or template.get("_id")
    name = template.get("name") or template.get("title")
    

    wf = template.get("workflow") or {}
    if not tid:
        tid = wf.get("id")
    if not name:
        name = wf.get("name") or wf.get("title")
    
    return str(tid or "unknown"), str(name or "Unknown")


def main():
    print("[INFO] Starting MCP templates risk nodes analysis...")
    

    mcp_template_ids = load_mcp_template_ids()
    if not mcp_template_ids:
        print("[ERROR] No MCP template IDs found")
        return
    

    node_risks = load_node_risks()
    if not node_risks:
        print("[WARN] No node risk data found, analysis will be limited")
    

    templates_dir = Path(TEMPLATES_DIR)
    if not templates_dir.exists():
        print(f"[ERROR] Templates directory not found: {templates_dir}")
        return
    
    print(f"[INFO] Scanning templates in: {templates_dir}")
    

    results = []
    stats = {
        "total_mcp_templates": len(mcp_template_ids),
        "templates_loaded": 0,
        "templates_with_risky_nodes": 0,
        "templates_with_high_risk": 0,
        "templates_with_medium_risk": 0,
        "templates_without_risks": 0,
    }
    
    risk_package_counter = Counter()
    high_risk_package_counter = Counter()
    
    for template_id in mcp_template_ids:
        template = load_template(template_id, templates_dir)
        if not template:
            continue
        
        stats["templates_loaded"] += 1
        analysis = analyze_template_risks(template, node_risks)
        results.append(analysis)
        
        if analysis["has_any_risk"]:
            stats["templates_with_risky_nodes"] += 1

            unique_risky_packages = set(pkg["package"] for pkg in analysis["risky_nodes"])
            for pkg in unique_risky_packages:
                risk_package_counter[pkg] += 1
        
        if analysis["has_high_risk"]:
            stats["templates_with_high_risk"] += 1

            unique_high_risk_packages = set(analysis["high_risk_packages"])
            for pkg in unique_high_risk_packages:
                high_risk_package_counter[pkg] += 1
        
        if analysis["has_medium_risk"]:
            stats["templates_with_medium_risk"] += 1
        
        if not analysis["has_any_risk"]:
            stats["templates_without_risks"] += 1
        
        if stats["templates_loaded"] % 50 == 0:
            print(f"[PROGRESS] Processed {stats['templates_loaded']}/{len(mcp_template_ids)} templates...")
    

    output = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "mcp_templates_list": str(MCP_TEMPLATES_LIST),
            "node_risk_analysis": str(NODE_RISK_ANALYSIS),
            "templates_dir": str(TEMPLATES_DIR),
        },
        "statistics": stats,
        "risk_package_distribution": dict(risk_package_counter.most_common(20)),
        "high_risk_package_distribution": dict(high_risk_package_counter.most_common(20)),
        "templates_with_risks": [
            {
                "template_id": r["template_id"],
                "template_name": r["template_name"],
                "high_risk_count": r["high_risk_node_count"],
                "medium_risk_count": r["medium_risk_node_count"],
                "high_risk_packages": r["high_risk_packages"],
            }
            for r in results
            if r["has_any_risk"]
        ],
        "templates_with_high_risk": [
            {
                "template_id": r["template_id"],
                "template_name": r["template_name"],
                "high_risk_packages": r["high_risk_packages"],
            }
            for r in results
            if r["has_high_risk"]
        ],
        "all_results": results,
    }
    

    output_path = Path(OUTPUT_FILE)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    
    print(f"\n[+] Analysis complete!")
    print(f"[+] Results saved to: {OUTPUT_FILE}")
    print(f"\n=== Summary ===")
    print(f"Total MCP templates: {stats['total_mcp_templates']}")
    print(f"Templates loaded: {stats['templates_loaded']}")
    print(f"Templates with risky nodes: {stats['templates_with_risky_nodes']} ({100.0 * stats['templates_with_risky_nodes'] / stats['templates_loaded']:.1f}%)")
    print(f"Templates with HIGH risk: {stats['templates_with_high_risk']} ({100.0 * stats['templates_with_high_risk'] / stats['templates_loaded']:.1f}%)")
    print(f"Templates with MEDIUM risk: {stats['templates_with_medium_risk']} ({100.0 * stats['templates_with_medium_risk'] / stats['templates_loaded']:.1f}%)")
    print(f"Templates without risks: {stats['templates_without_risks']} ({100.0 * stats['templates_without_risks'] / stats['templates_loaded']:.1f}%)")


if __name__ == "__main__":
    main()
