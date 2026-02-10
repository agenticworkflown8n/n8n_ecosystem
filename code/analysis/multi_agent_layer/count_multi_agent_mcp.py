#!/usr/bin/env python3
"""
Count multi-agent and MCP templates from n8n workflow dump; write stats JSON and list TXT.
"""

import json
from pathlib import Path
from collections import defaultdict

BASE = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = BASE / "data" / "n8n_templates_dump" / "workflows"
OUTPUT_DIR = BASE / "data" / "MULTI-AGENT"
STATS_FILE = OUTPUT_DIR / "multi_agent_mcp_stats.json"
LIST_FILE = OUTPUT_DIR / "multi_agent_templates_list.txt"

AGENT_NODE_TYPE = "@n8n/n8n-nodes-langchain.agent"
MCP_NODE_PREFIXES = ("langchain.mcp", "base.mcp", "base.mcpTrigger", "base.mcpClient", "base.mcpServer")
MCP_KEYWORDS = ("mcp", "model context protocol")


def _is_agent_node(node):
    return (node.get("type") or "").strip() == AGENT_NODE_TYPE


def _is_mcp_node(node):
    t = (node.get("type") or "").lower()
    n = (node.get("name") or "").lower()
    if any(p.lower() in t for p in MCP_NODE_PREFIXES):
        return True
    return any(k in n for k in MCP_KEYWORDS)


def _analyze_template(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error {path}: {e}")
        return None
    workflow = data.get("workflow", {})
    inner = workflow.get("workflow", workflow)
    nodes = inner.get("nodes", [])
    desc = (workflow.get("description") or "").lower()
    has_mcp_desc = any(k in desc for k in MCP_KEYWORDS)
    agent_nodes = [n for n in nodes if _is_agent_node(n)]
    mcp_nodes = [n for n in nodes if _is_mcp_node(n)]
    tid = workflow.get("id", "unknown")
    tname = workflow.get("name", "unknown")
    return {
        "id": tid,
        "name": tname,
        "agent_count": len(agent_nodes),
        "mcp_node_count": len(mcp_nodes),
        "has_mcp_in_description": has_mcp_desc,
        "is_multi_agent": len(agent_nodes) > 1,
        "has_mcp": len(mcp_nodes) > 0 or has_mcp_desc,
        "agent_nodes": [n.get("type", "") for n in agent_nodes],
        "mcp_nodes": [n.get("type", "") for n in mcp_nodes],
    }


def _write_list_file(results, list_path):
    both = [r for r in results if r["is_multi_agent"] and r["has_mcp"]]
    multi_only = [r for r in results if r["is_multi_agent"] and not r["has_mcp"]]
    mcp_only = [r for r in results if not r["is_multi_agent"] and r["has_mcp"]]
    for group in (both, multi_only, mcp_only):
        group.sort(key=lambda x: x["id"])
    total = len(both) + len(multi_only) + len(mcp_only)
    lines = [
        "=" * 80,
        f"MULTI-AGENT AND MCP INTEGRATION TEMPLATES ({total} templates)",
        "=" * 80,
        f"Both (multi-agent + MCP): {len(both)}",
        f"Multi-agent only: {len(multi_only)}",
        f"MCP integration only: {len(mcp_only)}",
        "=" * 80,
        "",
    ]
    if both:
        lines.extend(["=" * 80, f"MULTI-AGENT + MCP INTEGRATION ({len(both)} templates)", "=" * 80, ""])
        for i, t in enumerate(both, 1):
            parts = [f"{t['agent_count']} agent{'s' if t['agent_count'] > 1 else ''}"]
            if t["mcp_node_count"] > 0:
                parts.append(f"{t['mcp_node_count']} MCP node{'s' if t['mcp_node_count'] > 1 else ''}")
            if t["has_mcp_in_description"]:
                parts.append("MCP in description")
            lines.append(f"{i}. ID {t['id']}: {t['name']} ({', '.join(parts)})")
        lines.append("")
    if multi_only:
        lines.extend(["=" * 80, f"MULTI-AGENT ONLY ({len(multi_only)} templates)", "=" * 80, ""])
        for i, t in enumerate(multi_only, 1):
            lines.append(f"{i}. ID {t['id']}: {t['name']} ({t['agent_count']} agent{'s' if t['agent_count'] > 1 else ''})")
        lines.append("")
    if mcp_only:
        lines.extend(["=" * 80, f"MCP INTEGRATION ONLY ({len(mcp_only)} templates)", "=" * 80, ""])
        for i, t in enumerate(mcp_only, 1):
            parts = []
            if t["mcp_node_count"] > 0:
                parts.append(f"{t['mcp_node_count']} MCP node{'s' if t['mcp_node_count'] > 1 else ''}")
            if t["has_mcp_in_description"]:
                parts.append("MCP in description")
            lines.append(f"{i}. ID {t['id']}: {t['name']} ({', '.join(parts) or 'MCP integration'})")
    list_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    if not TEMPLATES_DIR.exists():
        print(f"Templates dir not found: {TEMPLATES_DIR}")
        return
    paths = list(TEMPLATES_DIR.glob("*.json"))
    print(f"Found {len(paths)} templates")
    results = []
    for p in paths:
        r = _analyze_template(p)
        if r:
            results.append(r)
    multi = sum(1 for r in results if r["is_multi_agent"])
    mcp = sum(1 for r in results if r["has_mcp"])
    both = sum(1 for r in results if r["is_multi_agent"] and r["has_mcp"])

    print("STATISTICS")
    print("Total:", len(results))
    print("Multi-agent (2+ agents):", multi)
    print("MCP integration:", mcp)
    print("Both:", both)

    agent_types = defaultdict(int)
    for r in results:
        for t in r["agent_nodes"]:
            agent_types[t] += 1
    print("Agent node types:", dict(sorted(agent_types.items(), key=lambda x: -x[1])))

    mcp_types = defaultdict(int)
    mcp_desc_only = sum(1 for r in results if r["has_mcp"] and r["mcp_node_count"] == 0 and r["has_mcp_in_description"])
    for r in results:
        for t in r["mcp_nodes"]:
            mcp_types[t] += 1
    print("MCP node types:", dict(sorted(mcp_types.items(), key=lambda x: -x[1])))
    if mcp_desc_only:
        print("MCP in description only (no MCP nodes):", mcp_desc_only)

    agent_dist = defaultdict(int)
    for r in results:
        agent_dist[r["agent_count"]] += 1
    print("Agent count distribution:", dict(sorted(agent_dist.items())))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STATS_FILE.write_text(
        json.dumps(
            {
                "summary": {"total_templates": len(results), "multi_agent_count": multi, "mcp_integration_count": mcp, "both_count": both},
                "details": results,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"Stats saved: {STATS_FILE}")

    _write_list_file(results, LIST_FILE)
    print(f"List saved: {LIST_FILE}")


if __name__ == "__main__":
    main()
