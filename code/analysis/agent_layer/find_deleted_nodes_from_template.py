
import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Set, Tuple

OLD_CSV = "../data/fetch_result/n8n_nodes_final_2025-10-01_14-53-53.csv"
NEW_CSV = "../data/fetch_result/n8n_nodes_final_2025-11-07_10-52-09.csv"
TEMPLATES_PATH = "../data/n8n_templates_dump/workflows"
OUTPUT_DIR = "../data/deleted_nodes_out"
ID_COL = "\ufeffname"


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def load_ids_from_csv(path: Path, id_col: str) -> Set[str]:
    if not path.is_file():
        raise FileNotFoundError(f"CSV not found: {path}")

    ids: Set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if id_col not in reader.fieldnames:
            raise ValueError(
                f"Column '{id_col}' not found in CSV {path}.\n"
                f"Available columns: {reader.fieldnames}"
            )
        for row in reader:
            value = (row.get(id_col) or "").strip()
            if value:
                ids.add(value)
    return ids


def load_templates_from_file(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(text)
        templates: List[Dict[str, Any]] = []
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict):
                    obj.setdefault("__source_file", str(path))
                    templates.append(obj)
        elif isinstance(data, dict):
            data.setdefault("__source_file", str(path))
            templates.append(data)
        if templates:
            return templates
    except Exception:
        pass

    templates: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                obj.setdefault("__source_file", str(path))
                templates.append(obj)
            elif isinstance(obj, list):
                for it in obj:
                    if isinstance(it, dict):
                        it.setdefault("__source_file", str(path))
                        templates.append(it)
    return templates


def load_templates(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Templates path not found: {path}")

    templates: List[Dict[str, Any]] = []

    if path.is_file():
        print(f"[INFO] Template path is a file: {path}")
        templates.extend(load_templates_from_file(path))
    else:
        print(f"[INFO] Template path is a directory, will recursively scan: {path}")
        json_files = sorted(path.rglob("*.json*"))
        print(f"[INFO] Found template files: {len(json_files)}")
        for fp in json_files:
            try:
                tpls = load_templates_from_file(fp)
                templates.extend(tpls)
            except Exception as e:
                print(f"[WARN] Failed to parse template file, skipped: {fp} ({e})")

    return templates


def _pick_from_dict(d: Dict[str, Any], keys: List[str]) -> str:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            v = d[k]
            return str(v)
    return ""


def extract_template_meta(tpl: Dict[str, Any]) -> Tuple[str, str, str]:
    id_candidates = ["id", "_id", "templateId", "workflowId", "workflow_id"]
    name_candidates = ["name", "title", "workflowName", "workflow_name"]
    desc_candidates = ["description", "summary", "workflowDescription", "workflow_description"]

    tpl_id = _pick_from_dict(tpl, id_candidates)
    tpl_name = _pick_from_dict(tpl, name_candidates)
    tpl_desc = _pick_from_dict(tpl, desc_candidates)

    if tpl_id or tpl_name or tpl_desc:
        return tpl_id, tpl_name, tpl_desc
    for nested_key in ("workflow", "meta", "data"):
        nested = tpl.get(nested_key)
        if isinstance(nested, dict):
            nid = _pick_from_dict(nested, id_candidates)
            nname = _pick_from_dict(nested, name_candidates)
            ndesc = _pick_from_dict(nested, desc_candidates)
            if nid or nname or ndesc:
                tpl_id = tpl_id or nid
                tpl_name = tpl_name or nname
                tpl_desc = tpl_desc or ndesc
                break

    if not tpl_id:
        src = tpl.get("__source_file") or ""
        if src:
            tpl_id = src

    return tpl_id, tpl_name, tpl_desc


def find_affected_templates(templates: List[Dict[str, Any]], deleted_ids: List[str]):
    affected = []
    deleted_tuple = tuple(deleted_ids)

    for tpl in templates:
        tpl_id, tpl_name, tpl_desc = extract_template_meta(tpl)

        serialized = json.dumps(tpl, ensure_ascii=False)
        matched = [nid for nid in deleted_tuple if nid in serialized]

        if matched:
            affected.append({
                "template_id": tpl_id,
                "template_name": tpl_name,
                "template_description": tpl_desc,
                "matched_nodes": "|".join(matched),
            })

    return affected


def write_txt(path: Path, items: List[str], old_csv: Path, new_csv: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(f"# Deleted nodes between:\n")
        f.write(f"#   OLD_CSV: {old_csv}\n")
        f.write(f"#   NEW_CSV: {new_csv}\n")
        f.write("\n")
        for it in items:
            f.write(f"{it}\n")
    return path


def write_csv(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["template_id", "template_name", "template_description", "matched_nodes"]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return path


def main():
    old_path = Path(OLD_CSV)
    new_path = Path(NEW_CSV)
    tpl_path = Path(TEMPLATES_PATH)
    out_dir = Path(OUTPUT_DIR)

    print(f"[INFO] Loading old CSV: {old_path}")
    old_ids = load_ids_from_csv(old_path, ID_COL)
    print(f"[INFO] Old CSV nodes: {len(old_ids)}")

    print(f"[INFO] Loading new CSV: {new_path}")
    new_ids = load_ids_from_csv(new_path, ID_COL)
    print(f"[INFO] New CSV nodes: {len(new_ids)}")

    deleted_ids = sorted(old_ids - new_ids)
    print(f"[INFO] Deleted nodes: {len(deleted_ids)}")

    if not deleted_ids:
        print("[INFO] No deleted nodes detected, exiting.")
        return

    deleted_txt = out_dir / f"deleted_nodes_{ts()}.txt"
    write_txt(deleted_txt, deleted_ids, old_path, new_path)
    print(f"[INFO] Deleted node list written to: {deleted_txt}")

    print(f"[INFO] Loading templates from: {tpl_path}")
    templates = load_templates(tpl_path)
    print(f"[INFO] Templates loaded: {len(templates)}")

    print("[INFO] Searching templates...")
    affected = find_affected_templates(templates, deleted_ids)
    print(f"[INFO] Affected templates: {len(affected)}")

    if affected:
        affected_csv = out_dir / f"affected_templates_{ts()}.csv"
        write_csv(affected_csv, affected)
        print(f"[INFO] Affected templates written to: {affected_csv}")
    else:
        print("[INFO] No templates reference deleted nodes, skipping affected_templates CSV generation.")


if __name__ == "__main__":
    main()
