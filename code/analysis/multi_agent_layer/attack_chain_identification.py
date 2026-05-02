#!/usr/bin/env python3
"""
Identify attack-chain stage hits (A1–A5) from merged N-star counts per template.

Primary criterion (OR rule, matches
`data/MCP/community_templates_problematic_nodes_agentic_attack_chain_OR_summary.md`):
  - A1: N8 > 0 or N9 > 0
  - A2: N6 > 0 or N7 > 0
  - A3: N1 > 0
  - A4: N5 > 0 or N3 > 0
  - A5: N2 > 0 or N4 > 0

Extended criterion (from `community_templates_problematic_nodes_N_star.md`), optional:
  same as above but additionally ANY of M1–M9 positive for the corresponding stage,
  if `--m-hits-json` provides per-template M counts.

Defaults (paths relative to **current working directory**, not this file’s location):
  - Input: `data/MCP/community_templates_problematic_nodes_N_star_ai_agent.tsv`
  - Output dir: `data/EUAI/`

Override with `--tsv` / `--out-dir` as needed.
  - attack_chain_per_template.json
  - attack_chain_summary.json
  - attack_chain_per_template.csv (optional via --csv)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


N_STAR_RE = re.compile(r"N(\d+)\s*=\s*(\d+)")
M_STAR_RE = re.compile(r"M(\d+)\s*=\s*(\d+)")

# Extended mapping: which M indices (1–9) contribute to each stage (disjunctive within stage).
EXTENDED_STAGE_TO_M: dict[str, tuple[int, ...]] = {
    "A1": (3,),
    "A2": (7,),
    "A3": (1, 2),
    "A4": (4, 8),
    "A5": (5, 6),
}


def _merge_star_maps(target: dict[int, int], src: dict[int, int]) -> None:
    for k, v in src.items():
        target[k] = target.get(k, 0) + v


@dataclass
class TemplateAgg:
    template_id: str
    template_name: str = ""
    n_counts: dict[int, int] = field(default_factory=dict)
    m_counts: dict[int, int] = field(default_factory=dict)
    packages: set[str] = field(default_factory=set)
    has_mcp_node_package: bool = False


def _or_rule_hits(n: dict[int, int]) -> dict[str, bool]:
    return {
        "A1": (n.get(8, 0) > 0) or (n.get(9, 0) > 0),
        "A2": (n.get(6, 0) > 0) or (n.get(7, 0) > 0),
        "A3": (n.get(1, 0) > 0),
        "A4": (n.get(5, 0) > 0) or (n.get(3, 0) > 0),
        "A5": (n.get(2, 0) > 0) or (n.get(4, 0) > 0),
    }


def _extended_hits(n: dict[int, int], m: dict[int, int]) -> dict[str, bool]:
    base = _or_rule_hits(n)
    out = dict(base)
    for stage, m_idxs in EXTENDED_STAGE_TO_M.items():
        if any(m.get(i, 0) > 0 for i in m_idxs):
            out[stage] = True
    return out


def load_tsv_rows(tsv_path: Path) -> dict[str, TemplateAgg]:
    """template_id -> aggregated counts across all node rows."""
    by_id: dict[str, TemplateAgg] = {}

    with tsv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            tid = str(row.get("template_id", "")).strip()
            if not tid:
                continue
            name = str(row.get("template_name", "") or "")
            pkg = str(row.get("package", "") or "").strip().lower()
            nz = str(row.get("nonzero_n_star", "") or "")

            entry = by_id.get(tid)
            if entry is None:
                entry = TemplateAgg(template_id=tid, template_name=name)
                by_id[tid] = entry
            # Prefer longest seen title if repeated
            if name and len(name) > len(entry.template_name):
                entry.template_name = name

            n_only: dict[int, int] = {}
            m_only: dict[int, int] = {}
            for part in nz.split(";"):
                part = part.strip()
                if not part:
                    continue
                mn = N_STAR_RE.match(part)
                mm = M_STAR_RE.match(part)
                if mn:
                    k = int(mn.group(1))
                    n_only[k] = n_only.get(k, 0) + int(mn.group(2))
                if mm:
                    k = int(mm.group(1))
                    m_only[k] = m_only.get(k, 0) + int(mm.group(2))

            _merge_star_maps(entry.n_counts, n_only)
            _merge_star_maps(entry.m_counts, m_only)

            if pkg:
                entry.packages.add(pkg)
            if pkg == "n8n-nodes-mcp":
                entry.has_mcp_node_package = True

    return by_id


def load_m_hits_json(path: Path) -> dict[str, dict[int, int]]:
    """
    Expected shape: { "5339": {"M1": 0, "M3": 1, ...}, ... }
    or { "5339": [ {"M": 3, "count": 1}, ... ] } — we accept flexible dicts.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[int, int]] = {}
    if not isinstance(raw, dict):
        return out
    for tid, payload in raw.items():
        key = str(tid).strip()
        counts: dict[int, int] = {}
        if isinstance(payload, dict):
            for k, v in payload.items():
                ks = str(k).upper()
                if ks.startswith("M") and ks[1:].isdigit():
                    counts[int(ks[1:])] = int(v)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and "M" in item:
                    counts[int(item["M"])] = int(item.get("count", 1))
        if counts:
            out[key] = counts
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Attack chain A1–A5 from N-star TSV")
    ap.add_argument(
        "--tsv",
        type=Path,
        default=Path("data/MCP/community_templates_problematic_nodes_N_star_ai_agent.tsv"),
        help="Input TSV (default: ./data/MCP/... relative to cwd)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/EUAI"),
        help="Output directory (default: ./data/EUAI relative to cwd)",
    )
    ap.add_argument("--m-hits-json", type=Path, default=None, help="Optional per-template M* counts JSON")
    ap.add_argument("--extended", action="store_true", help="Use N OR rule plus M from --m-hits-json (and any M in TSV)")
    ap.add_argument("--csv", action="store_true", help="Also write attack_chain_per_template.csv")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    aggs = load_tsv_rows(args.tsv)
    m_extra = load_m_hits_json(args.m_hits_json) if args.m_hits_json else {}

    per_template: list[dict[str, Any]] = []
    combo_counter: Counter[str] = Counter()

    for tid in sorted(aggs.keys(), key=lambda x: int(x) if x.isdigit() else x):
        agg = aggs[tid]
        m_merged = dict(agg.m_counts)
        if tid in m_extra:
            _merge_star_maps(m_merged, m_extra[tid])

        if args.extended:
            stages = _extended_hits(agg.n_counts, m_merged)
        else:
            stages = _or_rule_hits(agg.n_counts)

        active = sorted([s for s, hit in stages.items() if hit])
        combo_key = ",".join(active) if active else "(none)"
        combo_counter[combo_key] += 1

        stage_count = sum(1 for v in stages.values() if v)
        per_template.append(
            {
                "template_id": tid,
                "template_name": agg.template_name,
                "n_counts": {f"N{k}": v for k, v in sorted(agg.n_counts.items())},
                "m_counts": {f"M{k}": v for k, v in sorted(m_merged.items())},
                "has_mcp_node_package": agg.has_mcp_node_package,
                "packages_distinct": len(agg.packages),
                "stages_or_rule": stages,
                "stages_satisfied": active,
                "stage_hit_count": stage_count,
                "meets_ge_2_stages": stage_count >= 2,
            }
        )

    n_templates = len(per_template)
    stage_totals = {f"A{i}": sum(1 for r in per_template if r["stages_or_rule"].get(f"A{i}")) for i in range(1, 6)}
    ge2 = sum(1 for r in per_template if r["meets_ge_2_stages"])

    dist = Counter(r["stage_hit_count"] for r in per_template)

    summary = {
        "inputs": {
            "tsv": str(args.tsv.resolve()),
            "m_hits_json": str(args.m_hits_json.resolve()) if args.m_hits_json else None,
        },
        "method": {
            "mode": "extended_N_plus_M" if args.extended else "or_rule_N_only",
            "or_rule": {
                "A1": "N8>0 or N9>0",
                "A2": "N6>0 or N7>0",
                "A3": "N1>0",
                "A4": "N5>0 or N3>0",
                "A5": "N2>0 or N4>0",
            },
            "extended_m_mapping": EXTENDED_STAGE_TO_M if args.extended else None,
        },
        "denominators": {
            "templates_in_tsv": n_templates,
            "templates_ge_2_stages": ge2,
            "pct_ge_2": round(100.0 * ge2 / n_templates, 2) if n_templates else 0.0,
        },
        "stage_hit_template_counts": stage_totals,
        "stage_hit_count_distribution": {str(k): dist[k] for k in sorted(dist.keys())},
        "combo_counts_top": dict(combo_counter.most_common(50)),
    }

    out_json = args.out_dir / "attack_chain_per_template.json"
    out_summary = args.out_dir / "attack_chain_summary.json"
    out_json.write_text(json.dumps(per_template, ensure_ascii=False, indent=2), encoding="utf-8")
    out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.csv:
        out_csv = args.out_dir / "attack_chain_per_template.csv"
        fieldnames = [
            "template_id",
            "template_name",
            "stage_hit_count",
            "meets_ge_2_stages",
            "A1",
            "A2",
            "A3",
            "A4",
            "A5",
            "has_mcp_node_package",
            "stages_satisfied",
            "n_counts_json",
        ]
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in per_template:
                st = r["stages_or_rule"]
                w.writerow(
                    {
                        "template_id": r["template_id"],
                        "template_name": r["template_name"],
                        "stage_hit_count": r["stage_hit_count"],
                        "meets_ge_2_stages": r["meets_ge_2_stages"],
                        "A1": st["A1"],
                        "A2": st["A2"],
                        "A3": st["A3"],
                        "A4": st["A4"],
                        "A5": st["A5"],
                        "has_mcp_node_package": r["has_mcp_node_package"],
                        "stages_satisfied": ";".join(r["stages_satisfied"]),
                        "n_counts_json": json.dumps(r["n_counts"], ensure_ascii=False),
                    }
                )

    print(f"[OK] templates={n_templates} ge2={ge2} -> {out_json}")
    print(f"[OK] summary -> {out_summary}")


if __name__ == "__main__":
    main()
