#!/usr/bin/env python3

import argparse, csv, random, re, time, sys, json
from datetime import datetime
from pathlib import Path
from urllib.parse import quote
import requests

SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
REGISTRY_PKG_URL = "https://registry.npmjs.org/{name}"
DOWNLOADS_POINT = "https://api.npmjs.org/downloads/point/last-week/{names}"
KEY = "n8n-nodes"
CACHE_PATH = Path(".npm_downloads_cache.json")

class Logger:
    def __init__(self, verbose: bool = False, color: bool = True, stream=sys.stdout):
        self.verbose = verbose
        self.color = color
        self.stream = stream
        self._colors = {
            "INFO": "\033[36m",
            "OK": "\033[32m",
            "WARN": "\033[33m",
            "ERR": "\033[31m",
            "DBG": "\033[35m",
            "RESET": "\033[0m",
        }

    def _ts(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _fmt(self, lvl, msg):
        if self.color:
            return f"[{self._ts()}] {self._colors.get(lvl,'')}{lvl:<4}{self._colors['RESET']} | {msg}"
        return f"[{self._ts()}] {lvl:<4} | {msg}"

    def info(self, msg):  print(self._fmt("INFO", msg), file=self.stream, flush=True)
    def ok(self, msg):    print(self._fmt("OK",   msg), file=self.stream, flush=True)
    def warn(self, msg):  print(self._fmt("WARN", msg), file=self.stream, flush=True)
    def err(self, msg):   print(self._fmt("ERR",  msg), file=self.stream, flush=True)
    def dbg(self, msg):
        if self.verbose:
            print(self._fmt("DBG", msg), file=self.stream, flush=True)

def ts():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def backoff_sleep(attempt, retry_after=None, logger: Logger=None, ctx=""):
    if retry_after:
        try: wait = float(retry_after)
        except: wait = min(60, 2 ** attempt)
    else:
        wait = min(60, 2 ** attempt)
    jitter = random.uniform(0, 0.4)
    if logger:
        logger.warn(f"{ctx}Retry attempt {attempt+1}, sleeping {wait + jitter:.1f}s (Retry-After={retry_after})")
    time.sleep(wait + jitter)

def get_json(session, url, params=None, attempt=0, max_attempts=8, headers=None, logger: Logger=None, ctx=""):
    try:
        if logger: logger.dbg(f"{ctx}GET {url} params={params}")
        r = session.get(url, params=params, headers=headers or {}, timeout=30)
    except requests.RequestException as e:
        if attempt >= max_attempts:
            if logger: logger.err(f"{ctx}Request exception limit reached: {e}")
            raise
        backoff_sleep(attempt, logger=logger, ctx=ctx)
        return get_json(session, url, params, attempt+1, max_attempts, headers, logger, ctx)
    if r.status_code == 429:
        if logger: logger.warn(f"{ctx}HTTP 429 Too Many Requests")
        if attempt >= max_attempts:
            raise RuntimeError("HTTP 429 too many retries")
        backoff_sleep(attempt, r.headers.get("Retry-After"), logger, ctx)
        return get_json(session, url, params, attempt+1, max_attempts, headers, logger, ctx)
    if r.status_code >= 500:
        if logger: logger.warn(f"{ctx}HTTP {r.status_code} server error")
        if attempt >= max_attempts:
            r.raise_for_status()
        backoff_sleep(attempt, logger=logger, ctx=ctx)
        return get_json(session, url, params, attempt+1, max_attempts, headers, logger, ctx)
    r.raise_for_status()
    return r.json()

def search_page(session, q, size, offset, logger: Logger):
    headers = {"User-Agent": "n8n-node-research/2.0", "Accept": "application/json"}
    params = {"text": q, "size": size, "from": offset}
    return get_json(session, SEARCH_URL, params=params, headers=headers, logger=logger, ctx="[search] ")

def normalize_repo(u: str) -> str:
    if not u: return ""
    u = u.strip()
    u = re.sub(r'^git\+', '', u)
    u = re.sub(r'\.git$', '', u)
    m = re.match(r'^git@github\.com:(.+)$', u)
    if m:
        return f"https://github.com/{m.group(1)}"
    return u

def safe_pkg(name: str) -> str:
    return quote(name, safe='')

def get_repo_home_from_registry(session, name, logger: Logger):
    ctx = f"[hydrate:{name}] "
    try:
        j = get_json(session, REGISTRY_PKG_URL.format(name=safe_pkg(name)), logger=logger, ctx=ctx)
    except Exception as e:
        logger.warn(f"{ctx}Failed to read registry: {e}")
        return "", ""
    dist_tags = j.get("dist-tags", {})
    latest = dist_tags.get("latest")
    if not latest:
        logger.warn(f"{ctx}No dist-tags.latest")
    meta = j.get("versions", {}).get(latest, {}) if latest else {}
    repo = meta.get("repository", {})
    repo_url = repo.get("url") if isinstance(repo, dict) else (repo or "")
    homepage = meta.get("homepage") or ""
    repo_url = normalize_repo(repo_url)
    if not repo_url and not homepage:
        logger.dbg(f"{ctx}No repository/homepage")
    return repo_url, homepage

def load_cache():
    if CACHE_PATH.exists():
        try: return json.loads(CACHE_PATH.read_text("utf-8"))
        except: return {}
    return {}

def save_cache(cache):
    try: CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except: pass

def cache_is_fresh(ts_iso, hours=24):
    try:
        ts = datetime.fromisoformat(ts_iso)
        return (datetime.now() - ts).total_seconds() < hours * 3600
    except: return False

def get_weekly_downloads_bulk(session, names, logger: Logger, chunk_size=80, max_attempts=6):
    from urllib.parse import quote as q
    out = {n: 0 for n in names}
    if not names: return out

    chunks = [names[i:i+chunk_size] for i in range(0, len(names), chunk_size)]
    for ci, chunk in enumerate(chunks, 1):
        attempt = 0
        while True:
            enc = ",".join(q(n, safe="") for n in chunk)
            url = DOWNLOADS_POINT.format(names=enc)
            try:
                r = session.get(url, timeout=30)
                if r.status_code == 429:
                    ra = r.headers.get("Retry-After")
                    base = min(120, 10 * (2 ** attempt))
                    wait = float(ra) if (ra and ra.isdigit()) else base
                    jitter = random.uniform(0, 0.3)
                    logger.warn(f"[bulk:{ci}/{len(chunks)}] 429, sleeping {wait + jitter:.1f}s (Retry-After={ra})")
                    time.sleep(wait + jitter)
                    attempt += 1
                    if attempt > max_attempts:
                        logger.warn(f"[bulk:{ci}] Exceeded retry limit, setting all in chunk to 0")
                        break
                    continue

                r.raise_for_status()
                data = r.json()

                if isinstance(data, list):
                    for item in data:
                        name = item.get("package")
                        dl = int(item.get("downloads", 0) or 0)
                        if name in out: out[name] = dl
                elif isinstance(data, dict):
                    if len(chunk) == 1 and data.get("package") in out:
                        out[data["package"]] = int(data.get("downloads", 0) or 0)
                    else:
                        for k, v in data.items():
                            try:
                                out[k] = int((v or {}).get("downloads", 0) or 0)
                            except Exception:
                                pass

                logger.dbg(f"[bulk:{ci}] Filled {sum(1 for k,v in out.items() if v)} / {len(out)}")
                break
            except requests.RequestException as e:
                base = min(120, 5 * (2 ** attempt))
                wait = base + random.uniform(0, 0.3)
                logger.warn(f"[bulk:{ci}] Request failed ({e}), sleeping {wait:.1f}s before retry")
                time.sleep(wait)
                attempt += 1
                if attempt > max_attempts:
                    logger.warn(f"[bulk:{ci}] Exceeded retry limit, setting all in chunk to 0")
                    break

        time.sleep(0.2 + random.uniform(0, 0.2))

    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-q","--query", default="n8n-nodes")
    ap.add_argument("--size", type=int, default=250, help="Page size (<=250)")
    ap.add_argument("--sleep", type=float, default=0.8, help="Sleep seconds between pages")
    ap.add_argument("--out-prefix", default="n8n_nodes_final", help="Output prefix")
    ap.add_argument("--hydrate-missing", action="store_true", help="Fill missing repo/home")
    ap.add_argument("--max-scan", type=int, default=0, help="Max items to scan (0=all)")
    ap.add_argument("--verbose", action="store_true", help="Print detailed debug output")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--downloads", choices=["bulk","none"], default="bulk", help="Downloads mode: bulk or none")
    ap.add_argument("--bulk-size", type=int, default=80, help="Bulk downloads query batch size")
    ap.add_argument("--cache-hours", type=int, default=24, help="Downloads cache validity hours")
    args = ap.parse_args()

    logger = Logger(verbose=args.verbose, color=(not args.no_color))

    out_csv = f"{args.out_prefix}_{ts()}.csv"
    out_csv_path = Path(out_csv)

    seen_this_run = set()
    scanned, kept, offset, total = 0, 0, 0, None
    key_lower = KEY.lower()

    logger.info(f"Query keyword: {args.query} | Page size: {args.size} | Sleep per page: {args.sleep}s")
    logger.info(f"Output file: {out_csv_path.resolve()}")
    if args.max_scan:
        logger.info(f"Max scan limit: {args.max_scan}")
    if args.hydrate_missing:
        logger.info("Will hydrate missing repository/homepage from registry")
    logger.info(f"Downloads mode: {args.downloads}{' (using cache)' if args.downloads=='bulk' else ''}")

    cache = load_cache() if args.downloads == "bulk" else {}

    with requests.Session() as sess, out_csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["name","version","date","description","npm_url","repository_url","homepage_url","weekly_downloads"])

        page = 0
        while True:
            if args.max_scan and scanned >= args.max_scan:
                logger.warn("Reached max-scan limit, stopping early")
                break

            page += 1
            logger.info(f"====== Page {page} (offset={offset}) starting ======")
            j = search_page(sess, args.query, args.size, offset, logger)
            objs = j.get("objects", []) or []
            total = j.get("total", total)
            logger.info(f"Page returned objects={len(objs)} | Total={total}")

            if not objs:
                logger.warn("No more results, ending")
                break

            page_kept = 0
            page_skipped_nonmatch = 0
            page_dedup = 0
            page_names, page_rows = [], []

            for obj in objs:
                pkg = obj.get("package", {}) or {}
                name = pkg.get("name") or ""
                if key_lower not in name.lower():
                    page_skipped_nonmatch += 1
                    logger.dbg(f"[skip] Non-keyword match: {name}")
                    continue

                version = pkg.get("version") or ""
                date = pkg.get("date") or ""
                desc = (pkg.get("description") or "").replace("\n"," ").strip()
                links = pkg.get("links", {}) or {}
                npm_url = links.get("npm") or ""
                repo_url = normalize_repo(links.get("repository") or "")
                home_url = links.get("homepage") or ""

                if args.hydrate_missing and (not repo_url or not home_url):
                    logger.dbg(f"[hydrate] {name} missing fields, attempting to fill...")
                    r2, h2 = get_repo_home_from_registry(sess, name, logger)
                    if not repo_url and r2: repo_url = r2
                    if not home_url and h2: home_url = h2

                row_key = (name, version, npm_url, repo_url, home_url)
                if row_key in seen_this_run:
                    page_dedup += 1
                    logger.dbg(f"[dedup] Skipping duplicate: {name}@{version}")
                    continue
                seen_this_run.add(row_key)

                page_names.append(name)
                page_rows.append((name, version, date, desc, npm_url, repo_url, home_url))

            name_to_downloads = {}
            if args.downloads == "bulk" and page_rows:
                fresh = {}
                need_query = []
                for n in page_names:
                    ent = cache.get(n)
                    if ent and cache_is_fresh(ent.get("ts",""), hours=args.cache_hours):
                        try:
                            fresh[n] = int(ent.get("downloads", 0) or 0)
                        except Exception:
                            need_query.append(n)
                    else:
                        need_query.append(n)
                name_to_downloads.update(fresh)

                if need_query:
                    try:
                        logger.info(f"[bulk] Need to query downloads for {len(need_query)} packages (chunk={args.bulk_size})")
                        fetched = get_weekly_downloads_bulk(sess, need_query, logger, chunk_size=args.bulk_size)
                        name_to_downloads.update(fetched)
                        now_iso = datetime.now().isoformat(timespec="seconds")
                        for n, v in fetched.items():
                            cache[n] = {"downloads": int(v or 0), "ts": now_iso}
                        save_cache(cache)
                    except Exception as e:
                        logger.warn(f"[bulk] Bulk downloads query failed: {e}, setting all to 0")
                        for n in need_query:
                            name_to_downloads[n] = 0
            else:
                for n in page_names:
                    name_to_downloads[n] = 0

            for row in page_rows:
                name = row[0]
                weekly = int(name_to_downloads.get(name, 0) or 0)
                w.writerow([*row, weekly])
                kept += 1
                page_kept += 1
                if args.verbose and (page_kept % 10 == 0):
                    logger.info(f"[progress] Page written {page_kept} rows (total {kept})")

            scanned += len(objs)
            logger.ok(f"====== Page {page} completed: wrote {page_kept} rows, dedup {page_dedup}, non-match {page_skipped_nonmatch} ======")

            if total and offset + len(objs) >= total:
                logger.info("Reached last page, ending")
                break

            offset += len(objs)
            sleep_s = args.sleep + random.uniform(0, 0.3)
            logger.info(f"Page sleep {sleep_s:.1f}s...")
            time.sleep(sleep_s)

    logger.ok(f"Completed: output {out_csv_path} | Scanned={scanned}, Kept={kept}, Total={total}")

if __name__ == "__main__":
    main()
