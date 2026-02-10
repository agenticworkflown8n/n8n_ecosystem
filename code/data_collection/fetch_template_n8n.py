#!/usr/bin/env python3

import json, os, time, pathlib, requests
from datetime import datetime
from typing import Set, Dict, Any, Optional, List

BASE = "https://api.n8n.io/templates"
ROWS = 100

OUTPUT_BASE_DIR = pathlib.Path("../data/n8n_templates_dump")
SCAN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT = OUTPUT_BASE_DIR / SCAN_TIMESTAMP
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "workflows").mkdir(exist_ok=True)
(OUT / "deleted_templates").mkdir(exist_ok=True)

DELETED_TEMPLATES_FILE = OUT / "deleted_templates_report.json"
COMPARISON_FILE = OUT / "comparison_with_previous.json"
METADATA_FILE = OUT / "fetch_metadata.json"

LIST_SLEEP   = 0.5
DETAIL_SLEEP = 0.5
TIMEOUT      = 20
RETRY        = 3

session = requests.Session()

def get_with_retry(url, *, params=None, timeout=TIMEOUT, retry=RETRY):
    backoff = 1.0
    for i in range(retry):
        try:
            r = session.get(url, params=params, timeout=timeout)
            if r.status_code == 404:
                return r
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(backoff); backoff = min(backoff * 2, 8)
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if i == retry - 1:
                raise
            time.sleep(backoff); backoff = min(backoff * 2, 8)

def fmt_time(seconds: int) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h{m}m{s}s"
    if m: return f"{m}m{s}s"
    return f"{s}s"

def find_previous_fetch() -> Optional[pathlib.Path]:
    if not OUTPUT_BASE_DIR.exists():
        return None
    
    fetch_dirs = sorted([d for d in OUTPUT_BASE_DIR.iterdir() if d.is_dir()], reverse=True)
    if len(fetch_dirs) > 1:
        return fetch_dirs[1]
    elif len(fetch_dirs) == 1:
        if fetch_dirs[0].name != SCAN_TIMESTAMP:
            return fetch_dirs[0]
    return None

def get_previous_template_ids(previous_dir: Optional[pathlib.Path]) -> Set[str]:
    if not previous_dir:
        return set()
    
    workflows_dir = previous_dir / "workflows"
    if not workflows_dir.exists():
        return set()
    
    template_ids = set()
    for f in workflows_dir.glob("*.json"):
        if f.stem.isdigit():
            template_ids.add(f.stem)
    
    return template_ids

def analyze_deleted_templates(previous_ids: Set[str], current_ids: Set[str], previous_dir: Optional[pathlib.Path]) -> Dict[str, Any]:
    deleted_ids = previous_ids - current_ids
    
    if not deleted_ids:
        return {
            "deleted_count": 0,
            "deleted_templates": [],
            "analysis": {},
        }
    
    deleted_templates = []
    if previous_dir:
        workflows_dir = previous_dir / "workflows"
        for tid in deleted_ids:
            try:
                tf = workflows_dir / f"{tid}.json"
                if not tf.exists():
                    deleted_templates.append({
                        "template_id": tid,
                        "error": "file_not_found",
                    })
                    continue
                
                with tf.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                workflow = data.get("workflow", {})
                if "workflow" in workflow:
                    workflow = workflow["workflow"]
                
                deleted_templates.append({
                    "template_id": tid,
                    "name": workflow.get("name", "unknown"),
                    "total_views": workflow.get("totalViews", 0),
                    "recent_views": workflow.get("recentViews", 0),
                    "created_at": workflow.get("createdAt", "unknown"),
                    "nodes_count": len(workflow.get("nodes", [])),
                    "file_path": str(tf),
                })
            except Exception as e:
                deleted_templates.append({
                    "template_id": tid,
                    "error": str(e),
                })
    else:
        for tid in deleted_ids:
            deleted_templates.append({
                "template_id": tid,
                "note": "previous_fetch_dir_not_found",
            })
    
    analysis = {
        "total_deleted": len(deleted_templates),
        "avg_views": 0,
        "low_views_count": 0,
        "zero_views_count": 0,
        "oldest_created": None,
        "newest_created": None,
    }
    
    if deleted_templates:
        views = [t.get("total_views", 0) for t in deleted_templates 
                if isinstance(t.get("total_views"), (int, float)) and "error" not in t]
        if views:
            analysis["avg_views"] = sum(views) / len(views)
            analysis["low_views_count"] = len([v for v in views if v < 10])
            analysis["zero_views_count"] = len([v for v in views if v == 0])
        
        dates = []
        for t in deleted_templates:
            created = t.get("created_at")
            if created and created != "unknown" and "error" not in t:
                try:
                    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    dates.append(dt)
                except:
                    pass
        if dates:
            analysis["oldest_created"] = min(dates).isoformat()
            analysis["newest_created"] = max(dates).isoformat()
    
    return {
        "deleted_count": len(deleted_templates),
        "deleted_templates": deleted_templates,
        "analysis": analysis,
    }

def create_comparison_report(previous_ids: Set[str], current_ids: Set[str], previous_dir: Optional[pathlib.Path]) -> Dict[str, Any]:
    new_templates = current_ids - previous_ids
    deleted_templates = previous_ids - current_ids
    
    return {
        "previous_fetch": str(previous_dir) if previous_dir else None,
        "previous_fetch_timestamp": previous_dir.name if previous_dir else None,
        "current_fetch_timestamp": SCAN_TIMESTAMP,
        "generated_at": datetime.now().isoformat(),
        "comparison": {
            "new_templates": sorted(list(new_templates)),
            "deleted_templates": sorted(list(deleted_templates)),
            "new_count": len(new_templates),
            "deleted_count": len(deleted_templates),
            "total_change": len(new_templates) - len(deleted_templates),
            "previous_total": len(previous_ids),
            "current_total": len(current_ids),
        },
    }

print(f"[INFO] Starting template fetch...")
print(f"[INFO] Fetch timestamp: {SCAN_TIMESTAMP}")
print(f"[INFO] Output directory: {OUT}")

previous_dir = find_previous_fetch()
if previous_dir:
    print(f"[INFO] Found previous fetch: {previous_dir.name}")
    previous_ids = get_previous_template_ids(previous_dir)
    print(f"[INFO] Previous fetch had {len(previous_ids)} templates")
else:
    print(f"[INFO] No previous fetch found (first run)")
    previous_ids = set()

page = 1
total_saved = 0
current_template_ids = set()
t_start = time.monotonic()

print(f"[INFO] Start fetching templates… rows/page={ROWS}")
while True:
    t_page_start = time.monotonic()
    try:
        r = get_with_retry(f"{BASE}/search", params={"page": page, "rows": ROWS})
    except Exception as e:
        print(f"[WARN] fetch list page={page} failed: {e}")
        break

    data = r.json()
    items = data.get("items") or data.get("workflows") or []
    if not items:
        print(f"[INFO] page={page} is empty. Stop.")
        break

    (OUT / f"list_page_{page}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2))

    page_saved = 0
    page_skipped = 0
    page_failed = 0
    for it in items:
        wid = it.get("id")
        if not wid:
            continue
        
        wid_str = str(wid)
        wf_path = OUT / "workflows" / f"{wid_str}.json"
        if wf_path.exists():
            page_skipped += 1
            continue

        time.sleep(DETAIL_SLEEP)
        try:
            wr = get_with_retry(f"{BASE}/workflows/{wid_str}")
        except requests.HTTPError as e:
            if e.response and e.response.status_code == 404:
                page_failed += 1
                continue
            print(f"[WARN] fetch detail id={wid_str} failed: {e}")
            page_failed += 1
            continue
        except Exception as e:
            print(f"[WARN] fetch detail id={wid_str} failed: {e}")
            page_failed += 1
            continue

        if wr.status_code == 200:
            try:
                wf_data = wr.json()
                wf_path.write_text(json.dumps(wf_data, ensure_ascii=False, indent=2))
                page_saved += 1
                total_saved += 1
                current_template_ids.add(wid_str)
            except json.JSONDecodeError as e:
                print(f"[WARN] Invalid JSON for id={wid_str}: {e}")
                page_failed += 1
        elif wr.status_code == 404:
            page_failed += 1
            continue
        else:
            print(f"[WARN] Unexpected status {wr.status_code} for id={wid_str}")
            page_failed += 1

    elapsed_page = fmt_time(time.monotonic() - t_page_start)
    elapsed_total = fmt_time(time.monotonic() - t_start)
    print(
        f"[PAGE {page}] items={len(items)}, saved_new={page_saved}, skipped_exist={page_skipped}, failed={page_failed} | "
        f"page_time={elapsed_page}, total_saved={total_saved}, total_time={elapsed_total}"
    )

    page += 1
    time.sleep(LIST_SLEEP)

print(f"[DONE] Saved workflows (new this run): {total_saved} | elapsed={fmt_time(time.monotonic() - t_start)}")
print(f"[INFO] Total templates in current fetch: {len(current_template_ids)}")

print(f"[INFO] Analyzing deleted templates...")
deleted_report = analyze_deleted_templates(previous_ids, current_template_ids, previous_dir)

print(f"[INFO] Creating comparison report...")
comparison_report = create_comparison_report(previous_ids, current_template_ids, previous_dir)

if deleted_report.get("deleted_count", 0) > 0:
    deleted_report["generated_at"] = datetime.now().isoformat()
    deleted_report["fetch_timestamp"] = SCAN_TIMESTAMP
    try:
        with DELETED_TEMPLATES_FILE.open("w", encoding="utf-8") as f:
            json.dump(deleted_report, f, ensure_ascii=False, indent=2)
        print(f"[OK] Deleted templates report saved: {DELETED_TEMPLATES_FILE.name}")
        print(f"[INFO] Deleted templates: {deleted_report['deleted_count']}")
        analysis = deleted_report.get("analysis", {})
        if analysis:
            print(f"  Average views: {analysis.get('avg_views', 0):.1f}")
            print(f"  Zero views: {analysis.get('zero_views_count', 0)}")
            print(f"  Low views (<10): {analysis.get('low_views_count', 0)}")
    except Exception as e:
        print(f"[ERROR] Failed to save deleted templates report: {e}")
else:
    print(f"[INFO] No deleted templates found")

try:
    with COMPARISON_FILE.open("w", encoding="utf-8") as f:
        json.dump(comparison_report, f, ensure_ascii=False, indent=2)
    print(f"[OK] Comparison report saved: {COMPARISON_FILE.name}")
    comp = comparison_report.get("comparison", {})
    if comp:
        print(f"[INFO] Comparison results:")
        print(f"  New templates: {comp.get('new_count', 0)}")
        print(f"  Deleted templates: {comp.get('deleted_count', 0)}")
        print(f"  Net change: {comp.get('total_change', 0)}")
except Exception as e:
    print(f"[ERROR] Failed to save comparison report: {e}")

try:
    metadata = {
        "generated_at": datetime.now().isoformat(),
        "fetch_timestamp": SCAN_TIMESTAMP,
        "total_templates": len(current_template_ids),
        "new_templates_this_run": total_saved,
        "deleted_templates_count": deleted_report.get("deleted_count", 0),
        "previous_fetch": str(previous_dir) if previous_dir else None,
    }
    with METADATA_FILE.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    print(f"[OK] Metadata saved: {METADATA_FILE.name}")
except Exception as e:
    print(f"[ERROR] Failed to save metadata: {e}")

try:
    latest_link = OUTPUT_BASE_DIR / "latest"
    if latest_link.exists() or latest_link.is_symlink():
        latest_link.unlink()
    latest_link.symlink_to(SCAN_TIMESTAMP)
    print(f"[OK] Created symlink: latest -> {SCAN_TIMESTAMP}")
except Exception as e:
    print(f"[WARN] Failed to create symlink: {e}")

print(f"\n[INFO] All files saved in: {OUT}")
