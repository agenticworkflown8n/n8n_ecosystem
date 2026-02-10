#!/usr/bin/env python3

import os, json, csv, glob, sys, pathlib, argparse, datetime
from typing import Dict, Any, List, Tuple, Set, Iterable
from collections import defaultdict, Counter

# ================== CONFIG ==================
OFFICIAL_PREFIXES = (
    "n8n-nodes-base",
    "@n8n/n8n-nodes-langchain",
)

OFFLINE_DIR = "../data/n8n_templates_dump/workflows"
RISK_FILE   = "./risky_nodes.txt"
OUT_DIR     = pathlib.Path("../data/scan_out_risknodes_template")
# ============================================

def _nz(s): 
    return (s or "").strip()

def load_risky_packages(path: str) -> List[str]:
    pkgs: List[str] = []
    if not os.path.isfile(path):
        return pkgs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = _nz(line)
            if not s or s.startswith("#"):
                continue
            pkgs.append(s)
    pkgs = sorted(set(pkgs), key=lambda x: x.lower())
    return pkgs

def is_official_package(name: str) -> bool:
    if not name: 
        return False
    n = name.strip().lower()
    return any(n == p.lower() or n.startswith(p.lower() + "@") for p in OFFICIAL_PREFIXES)

def iter_templates(directory: str) -> Iterable[Dict[str, Any]]:
    for fp in sorted(glob.glob(os.path.join(directory, "*.json"))):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                yield json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to load {fp}: {e}", file=sys.stderr)

def extract_nodes(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    wf = doc.get("workflow") or {}
    if "workflow" in wf and isinstance(wf["workflow"], dict):
        inner_nodes = wf["workflow"].get("nodes")
        if isinstance(inner_nodes, list) and inner_nodes:
            return inner_nodes
    nodes = wf.get("nodes")
    if isinstance(nodes, list):
        return nodes
    nodes = doc.get("nodes")
    if isinstance(nodes, list):
        return nodes
    return []

def template_meta(doc: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    tid = doc.get("id") or doc.get("_id")
    slug = doc.get("slug")
    title = doc.get("title") or doc.get("name")

    wf = doc.get("workflow") or {}
    if not tid:
        tid = wf.get("id")
    if not slug:
        slug = wf.get("slug")
    if not title:
        title = wf.get("name") or wf.get("title")

    return tid, slug, title

def collect_node_types(doc: Dict[str, Any]) -> List[str]:
    types = []
    for n in extract_nodes(doc):
        t = _nz(n.get("type"))
        if not t:
            t = _nz(n.get("name"))
        if t:
            types.append(t)
    return types

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--include-official", action="store_true",
                        help="Include official packages (default: exclude)")
    parser.add_argument("--by-package", action="store_true",
                        help="Also emit per-package CSV (default: off)")
    parser.add_argument("--raw", action="store_true",
                        help="Also emit raw JSONL hits (default: off)")
    args, _ = parser.parse_known_args()
    include_official = args.include_official or os.environ.get("INCLUDE_OFFICIAL") in ("1","true","yes")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    risky_pkgs = load_risky_packages(RISK_FILE)
    if not risky_pkgs:
        print(f"[!] No risky packages found in {RISK_FILE}. Nothing to do.")
        return

    if not include_official:
        risky_pkgs = [p for p in risky_pkgs if not is_official_package(p)]
    if not risky_pkgs:
        print("[!] Risk list becomes empty after excluding official packages.")
        return

    pkg_prefixes = [(p, p + ".") for p in risky_pkgs]

    hits_raw: List[Dict[str, Any]] = []
    per_tmpl_counts: Dict[Tuple[str,str,str,str], int] = Counter()
    per_tmpl_types: Dict[Tuple[str,str,str,str], Set[str]] = defaultdict(set)
    per_pkg_counts: Counter = Counter()
    per_pkg_templates: Dict[str, Set[Tuple[str,str]]] = defaultdict(set)

    scanned = 0
    for doc in iter_templates(OFFLINE_DIR):
        scanned += 1
        tid, slug, title = template_meta(doc)
        node_types = collect_node_types(doc)

        for t in node_types:
            for pkg, pref in pkg_prefixes:
                if t.startswith(pref):
                    key = (pkg, str(tid), str(slug or ""), str(title or ""))
                    per_tmpl_counts[key] += 1
                    per_tmpl_types[key].add(t)
                    per_pkg_counts[pkg] += 1
                    per_pkg_templates[pkg].add((str(tid), str(slug or "")))

                    hits_raw.append({
                        "package": pkg,
                        "template_id": tid,
                        "slug": slug,
                        "title": title,
                        "node_type": t,
                    })

        if scanned % 1000 == 0:
            print(f"[PROG] scanned={scanned} templates…", file=sys.stderr)

    total_hits = sum(per_tmpl_counts.values())
    print("======== SUMMARY ========")
    print(f"Templates scanned      : {scanned}")
    print(f"Total matches (nodes)  : {total_hits}")
    print(f"Affected packages      : {len([p for p,c in per_pkg_counts.items() if c>0])}")

    if total_hits == 0:
        print("[INFO] No risky packages found in templates. No files were saved.")
        print("=========================")
        return

    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    bytpl_csv  = OUT_DIR / f"hits_by_template_{ts}.csv"
    bypkg_csv  = OUT_DIR / f"hits_by_package_{ts}.csv"
    jsonl_path = OUT_DIR / f"hits_raw_{ts}.jsonl"

    with open(bytpl_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["package","template_id","slug","title","count","unique_node_types"])
        for key, cnt in sorted(per_tmpl_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            pkg, tid, slug, title = key
            uniq_types = sorted(per_tmpl_types[key])
            w.writerow([pkg, tid, slug, title, cnt, " | ".join(uniq_types)])
    print(f"Saved per-template CSV : {bytpl_csv}")

    if args.by_package:
        with open(bypkg_csv, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["package","total_occurrences","affected_templates","example_templates"])
            for pkg, cnt in sorted(per_pkg_counts.items(), key=lambda kv: (-kv[1], kv[0])):
                tmpls = sorted(per_pkg_templates[pkg])
                w.writerow([pkg, cnt, len(tmpls), " ; ".join(f"{tid}:{slug}" for tid,slug in tmpls[:10])])
        print(f"Saved per-package CSV  : {bypkg_csv}")

    if args.raw:
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for r in hits_raw:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"Saved raw hits         : {jsonl_path}")

    print("=========================")

if __name__ == "__main__":
    main()
