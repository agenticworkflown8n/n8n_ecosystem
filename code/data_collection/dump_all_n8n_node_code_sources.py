#!/usr/bin/env python3

import io
import os
import re
import json
import tarfile
import zipfile
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

INPUT_CSV     = "../data/fetch_result/n8n_nodes_final_2025-11-07_10-52-09.csv"

OUTPUT_DIR = "../data/code_source_dump"

OFFICIAL_N8N_REPO = "https://github.com/n8n-io/n8n"
KEEP_WORKDIR      = False

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
USER_AGENT   = "n8n-node-source-dump/2.0"

try:
    import requests
except Exception:
    print("Please install required packages: pip install requests pandas")
    raise


def now_ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def http_get(
    url: str,
    *,
    timeout: int = 30,
    headers: Optional[Dict[str, str]] = None,
    max_retry: int = 3,
    backoff: float = 1.5,
) -> requests.Response:
    hs = {"User-Agent": USER_AGENT}
    if GITHUB_TOKEN and "github" in url:
        hs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    if headers:
        hs.update(headers)
    last_exc = None
    for attempt in range(max_retry):
        try:
            r = requests.get(url, headers=hs, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504):
                import time
                sleep_s = (backoff ** attempt) * 0.6 + 0.4
                print(f"[!] http_get {url} status={r.status_code}, retry in {sleep_s:.1f}s")
                time.sleep(sleep_s)
                continue
            return r
        except Exception as e:
            last_exc = e
            import time
            sleep_s = (backoff ** attempt) * 0.6 + 0.4
            print(f"[!] http_get {url} exception {e}, retry in {sleep_s:.1f}s")
            time.sleep(sleep_s)
    if last_exc:
        raise last_exc
    raise RuntimeError(f"GET failed: {url}")


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


def extract_zip_to_dir(zip_bytes: bytes, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest_dir)
    subs = [p for p in dest_dir.iterdir() if p.is_dir()]
    return subs[0] if subs else dest_dir


def try_codeload_zip(owner: str, repo: str, ref: str) -> Optional[bytes]:
    ref = re.sub(r"^refs/(tags|heads)/", "", ref)
    url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
    try:
        print(f"[i]   try GitHub codeload: {url}")
        r = http_get(url, timeout=60)
        if r.status_code == 200:
            return r.content
        print(f"[!]   codeload {url} status={r.status_code}")
        return None
    except Exception as e:
        print(f"[!]   codeload error: {e}")
        return None


def fetch_npm_metadata(name: str, version: Optional[str]) -> Dict[str, Any]:
    import urllib.parse
    need_ver = (version or "latest").strip() or "latest"
    name_enc = urllib.parse.quote(name)
    url = f"https://registry.npmjs.org/{name_enc}"
    print(f"[i]   fetch npm meta: {url}")
    r = http_get(url, timeout=30)
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
        "gitHead": vmeta.get("gitHead"),
    }


def download_npm_tarball(tarball_url: str) -> bytes:
    print(f"[i]   download tarball: {tarball_url}")
    r = http_get(tarball_url, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"download tarball failed {r.status_code}: {tarball_url}")
    return r.content


def _norm_ver(v: Optional[str]) -> str:
    if not v or not isinstance(v, str):
        return ""
    s = v.strip()
    if not s:
        return ""
    if s[:1].lower() == "v":
        s = s[1:]
    for sep in ("+", "-"):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s


def build_version_consistency(npm_version: Optional[str], gh_version: Optional[str]) -> Dict[str, Any]:
    nv = _norm_ver(npm_version)
    gv = _norm_ver(gh_version)
    status = "unknown"
    details = []
    if nv and gv:
        status = "match" if nv == gv else "mismatch"
        details.append(f"npm={nv}, github={gv}")
    elif nv and not gv:
        details.append(f"npm={nv}, github=missing")
    elif gv and not nv:
        details.append(f"npm=missing, github={gv}")
    else:
        details.append("both versions missing")
    return {
        "status": status,
        "details": "; ".join(details),
        "npm_version": npm_version,
        "github_version": gh_version,
    }


def load_rows_from_csv(path: str) -> List[Dict[str, str]]:
    import pandas as pd
    df = pd.read_csv(path)
    if "name" not in df.columns:
        raise ValueError("CSV must contain column 'name'")
    if "repository_url" not in df.columns:
        raise ValueError("CSV must contain column 'repository_url'")
    rows = []
    for _, r in df.iterrows():
        rows.append({
            "name": str(r.get("name", "")).strip(),
            "repository_url": str(r.get("repository_url", "")).strip(),
        })
    return rows


IGNORE_DIRS = {
    "node_modules",
    "dist-tests",
    "build-tests",
    ".git",
    "coverage",
    "__tests__",
    "__mocks__",
}


def iter_source_files(root: Path):
    for p in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def classify_lang(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".ts":
        return "ts"
    if suf == ".js":
        return "js"
    return "other"


def safe_pkg_name(pkg: str) -> str:
    s = pkg.strip()
    s = s.replace("@", "_")
    s = s.replace("/", "_")
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s)
    return s or "pkg"


def dump_source_files_for_pkg(
    pkg_name: str,
    root_dir: Path,
    source_used: str,
    code_file_path: Path,
) -> int:
    count = 0
    code_file_path.parent.mkdir(parents=True, exist_ok=True)
    with code_file_path.open("w", encoding="utf-8") as code_out_f:
        for fpath in iter_source_files(root_dir):
            try:
                txt = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                print(f"[!]   read file error ({fpath}): {e}")
                continue
            if not txt:
                continue

            rel = str(fpath.relative_to(root_dir))
            lang = classify_lang(fpath)
            is_node_file = rel.lower().endswith(".node.ts") or rel.lower().endswith(".node.js")

            rec = {
                "npm_name": pkg_name,
                "source_used": source_used,
                "file_path": rel.replace("\\", "/"),
                "is_node_file": is_node_file,
                "lang": lang,
                "code": txt,
            }
            code_out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    return count


def main():
    ts = now_ts()
    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    files_dir = out_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    output_meta_path = out_dir / f"source_meta_{ts}.json"

    work = Path(tempfile.mkdtemp(prefix="dump-src-"))
    print(f"[+] workdir: {work}")
    print(f"[+] output meta: {output_meta_path}")
    print(f"[+] files dir: {files_dir}")

    rows = load_rows_from_csv(INPUT_CSV)
    print(f"[i] total packages from CSV: {len(rows)}")

    meta: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "source": "github_first_then_npm",
        "input_csv": INPUT_CSV,
        "output_dir": str(out_dir),
        "ts": ts,
        "counters": {
            "used_github": 0,
            "used_npm": 0,
            "fraud": 0,
            "github_failed": 0,
            "npm_failed": 0,
            "no_source": 0,
        },
        "packages": [],
    }

    FORCE_NPM = {
        "@oshankhz/n8n-nodes-bee2bee-indexer",
        "n8n-nodes-nqdev-aio-beta",
        "n8n-nodes-nqdev-aio",
        "n8n-nodes-streamline",
        "n8n-nodes-streamline-connector",
        "@openemm/n8n-nodes-openemm",
    }

    try:
        for idx, row in enumerate(rows, 1):
            name = row["name"]
            repo_url_csv = (row.get("repository_url") or "").strip()
            if repo_url_csv.lower() == "nan":
                repo_url_csv = ""
            if not name:
                continue

            pkg_entry: Dict[str, Any] = {
                "index": idx,
                "npm_name": name,
                "csv_repository_url": repo_url_csv,
                "github": None,
                "npm": None,
                "source_used": None,
                "github_error_reason": None,
                "npm_error": None,
                "files_dumped": 0,
                "code_file": None,
                "consistency": None,
                "error": None,
            }

            print(f"[=] {idx}/{len(rows)} dump sources for {name} …")

            source_used = None
            npm_version = None
            gh_version = None
            fraud = None

            gh_error_reason = None
            gh_root_dir: Optional[Path] = None

            if name in FORCE_NPM:
                gh_url = None
                gh_error_reason = "forced_npm_mode"
            else:
                gh_url = repo_url_csv if repo_url_csv else None
                if not gh_url:
                    gh_error_reason = "no_github_repo_in_csv"

            if gh_url:
                if gh_url.lower().rstrip("/") == OFFICIAL_N8N_REPO.lower().rstrip("/"):
                    fraud = {
                        "severity": "error",
                        "rule": "OFFICIAL_REPO_IMPERSONATION",
                        "message": f"repository_url points to official {OFFICIAL_N8N_REPO}; skipping GitHub.",
                    }
                    meta["counters"]["fraud"] += 1
                    gh_error_reason = "github_official_repo_impersonation"
                else:
                    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", gh_url)
                    if m:
                        owner, repo = m.group(1), m.group(2)
                        gh_zip_bytes = (
                            try_codeload_zip(owner, repo, "refs/heads/main")
                            or try_codeload_zip(owner, repo, "refs/heads/master")
                        )
                        if gh_zip_bytes:
                            gh_dir = work / f"github_{owner}_{repo}"
                            gh_root_dir = extract_zip_to_dir(gh_zip_bytes, gh_dir)
                            source_used = "github"
                            meta["counters"]["used_github"] += 1
                            pkg_entry["github"] = {
                                "repo_url": gh_url,
                                "ref_used": "main/master",
                                "__root": str(gh_root_dir),
                            }
                        else:
                            gh_error_reason = "github_ref_not_found_or_download_failed"
                    else:
                        gh_error_reason = "github_url_invalid"

            npm_error_reason = None
            npm_root_dir: Optional[Path] = None

            if source_used != "github":
                try:
                    meta_npm = fetch_npm_metadata(name, None)
                    npm_version = meta_npm["version"]
                    tgz = download_npm_tarball(meta_npm["tarball"])
                    pkg_dir = work / f"npm_{name.replace('/', '_')}@{npm_version}"
                    npm_root_dir = extract_tgz_to_dir(tgz, pkg_dir)
                    source_used = "npm"
                    meta["counters"]["used_npm"] += 1
                    pkg_entry["npm"] = {
                        "version": npm_version,
                        "tarball": meta_npm["tarball"],
                        "__root": str(npm_root_dir),
                    }
                except Exception as e:
                    npm_error_reason = str(e)
                    meta["counters"]["npm_failed"] += 1
                    print(f"[!]   npm fallback failed for {name}: {npm_error_reason}")

            if source_used == "github":
                try:
                    meta_npm = fetch_npm_metadata(name, None)
                    npm_version = meta_npm["version"]
                except Exception as e:
                    pkg_entry["npm_metadata_error"] = str(e)
                if gh_root_dir:
                    pkg_json_path = gh_root_dir / "package.json"
                    if pkg_json_path.exists():
                        try:
                            pkg_json = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="ignore"))
                            gh_version = pkg_json.get("version")
                        except Exception:
                            pass
                pkg_entry["consistency"] = build_version_consistency(npm_version, gh_version)
            elif source_used == "npm":
                if npm_root_dir:
                    pkg_json_path = npm_root_dir / "package.json"
                    if pkg_json_path.exists():
                        try:
                            pkg_json = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="ignore"))
                            gh_version = pkg_json.get("version")
                        except Exception:
                            pass
                pkg_entry["consistency"] = build_version_consistency(npm_version, gh_version)
            else:
                pkg_entry["consistency"] = {
                    "status": "unknown",
                    "details": "no source downloaded",
                    "npm_version": None,
                    "github_version": None,
                }

            files_dumped = 0
            code_file_path = None

            if source_used == "github" and gh_root_dir is not None:
                code_file_path = files_dir / f"{safe_pkg_name(name)}.jsonl"
                print(f"[i]   dumping from GitHub tree: {gh_root_dir} -> {code_file_path.name}")
                files_dumped = dump_source_files_for_pkg(name, gh_root_dir, "github", code_file_path)
            elif source_used == "npm" and npm_root_dir is not None:
                code_file_path = files_dir / f"{safe_pkg_name(name)}.jsonl"
                print(f"[i]   dumping from npm tree: {npm_root_dir} -> {code_file_path.name}")
                files_dumped = dump_source_files_for_pkg(name, npm_root_dir, "npm", code_file_path)
            else:
                meta["counters"]["no_source"] += 1

            pkg_entry["files_dumped"] = files_dumped
            pkg_entry["source_used"] = source_used or "none"
            if files_dumped > 0 and code_file_path is not None:
                pkg_entry["code_file"] = str(code_file_path.relative_to(out_dir))

            if gh_error_reason:
                pkg_entry["github_error_reason"] = gh_error_reason
                if source_used != "github":
                    meta["counters"]["github_failed"] += 1
            if npm_error_reason:
                pkg_entry["npm_error"] = npm_error_reason
            if fraud is not None:
                pkg_entry["fraud"] = fraud

            pkg_entry["error"] = (
                pkg_entry.get("npm_error")
                or pkg_entry.get("github_error_reason")
                or (None if source_used else "both_sources_unavailable")
            )

            meta["packages"].append(pkg_entry)

    finally:
        output_meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[OK] meta -> {output_meta_path}")

        if not KEEP_WORKDIR:
            shutil.rmtree(work, ignore_errors=True)
            print(f"[i] workdir removed: {work}")
        else:
            print(f"[i] workdir kept at: {work}")


if __name__ == "__main__":
    main()
