#!/usr/bin/env python3
"""
Code similarity pipeline: build MinHash signatures -> LSH cluster -> filter/sort package pairs.
Subcommands: build-signatures | cluster | filter | all
"""

import argparse
import csv
import gc
import json
import re
import sys
import time
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

FILES_DIR = Path("../data/code_source_dump/files")
OUTPUT_DIR = Path("../data/code_similarity_out_stream")
SIGNATURES_CSV = OUTPUT_DIR / "file_signatures.csv"
FILE_PAIRS_CSV = OUTPUT_DIR / "file_pairs_sim_lsh.csv"
PKG_PAIRS_CSV = OUTPUT_DIR / "pkg_pairs_sim_lsh.csv"
PKG_PAIRS_FILTERED_CSV = OUTPUT_DIR / "pkg_pairs_sim_lsh_filtered_sorted.csv"
SUMMARY_TXT = OUTPUT_DIR / "summary_lsh.txt"

K_GRAM = 5
NUM_HASHES = 80
NUM_BANDS = 20
ROWS_PER_BAND = 4
MIN_SIM_THRESHOLD = 0.9
DEFAULT_FILTER_THRESHOLD = 0.5
SIM_COLUMNS = ("sim_pkg_minhash_jaccard", "sim_pkg_token_jaccard")

JS_KEYWORDS = {
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete",
    "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if",
    "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this", "throw",
    "true", "try", "typeof", "var", "let", "void", "while", "with", "yield", "async", "await",
}
TOKEN_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*|"
    r"==|===|!=|!==|<=|>=|=>|&&|\|\||"
    r"[{}()\[\];,\.<>+\-*/%&|^!~?:=]"
)


# ---------------------------------------------------------------------------
# Step 1: Build MinHash signatures
# ---------------------------------------------------------------------------

def strip_comments_strings_numbers(src: str) -> str:
    src = re.sub(r"//.*", "", src)
    src = re.sub(r"/\*[\s\S]*?\*/", "", src)
    src = re.sub(r"\"[^\"]*\"|'[^']*'|`[^`]*`", " STR ", src)
    src = re.sub(r"\b\d+(\.\d+)?\b", " NUM ", src)
    src = re.sub(r"\s+", " ", src)
    return src.strip()


def tokenize(src: str) -> List[str]:
    return TOKEN_PATTERN.findall(src)


def normalize_identifiers(tokens: List[str]) -> List[str]:
    var_map: Dict[str, str] = {}
    func_map: Dict[str, str] = {}
    var_idx = func_idx = 1
    out: List[str] = []
    prev = None
    for tok in tokens:
        if re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", tok):
            if tok in JS_KEYWORDS:
                out.append(tok)
            else:
                if prev == "function":
                    if tok not in func_map:
                        func_map[tok] = f"FUNC_{func_idx}"
                        func_idx += 1
                    out.append(func_map[tok])
                else:
                    if tok not in var_map:
                        var_map[tok] = f"VAR_{var_idx}"
                        var_idx += 1
                    out.append(var_map[tok])
        else:
            out.append(tok)
        prev = tok
    return out


def normalize_code_with_ids(src: str) -> List[str]:
    cleaned = strip_comments_strings_numbers(src)
    return normalize_identifiers(tokenize(cleaned))


def build_shingles(tokens: List[str], k: int) -> Set[str]:
    if len(tokens) < k:
        return set()
    return {" ".join(tokens[i : i + k]) for i in range(len(tokens) - k + 1)}


def generate_minhash_signature(shingles: Set[str], num_hashes: int) -> List[int]:
    if not shingles:
        return [0] * num_hashes
    shingle_bytes = [s.encode("utf-8") for s in shingles]
    minhash = [2**32 - 1] * num_hashes
    for shingle_b in shingle_bytes:
        base_hash = zlib.crc32(shingle_b) & 0xFFFFFFFF
        for i in range(num_hashes):
            a, b, M = 1103515245 + i * 12345, 12345 + i * 67890, 2**31 - 1
            hash_val = (a * base_hash + b) % M
            if hash_val < minhash[i]:
                minhash[i] = hash_val
    return minhash


def run_build_signatures(files_dir: Path, output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    pkg_files = sorted(p for p in files_dir.glob("*.jsonl") if p.is_file())
    print(f"[INFO] Building MinHash signatures from JSONL in: {files_dir}")
    print(f"[INFO] K-gram: {K_GRAM}, Num hashes: {NUM_HASHES}")
    print(f"[INFO] Found {len(pkg_files)} package JSONL files")
    fieldnames = ["file_id", "npm_name", "file_path", "lang", "num_shingles"] + [f"h{i}" for i in range(NUM_HASHES)]
    file_id = total_files = skipped_files = 0
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for pkg_idx, pkg_file in enumerate(pkg_files):
            if (pkg_idx + 1) % 100 == 0:
                print(f"[PROGRESS] {pkg_idx + 1}/{len(pkg_files)} packages, {total_files} files, {skipped_files} skipped")
            with pkg_file.open("r", encoding="utf-8") as pkg_f:
                for line in pkg_f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    npm_name = obj.get("npm_name") or pkg_file.stem
                    file_path = obj.get("file_path") or ""
                    lang = (obj.get("lang") or "").lower()
                    code = obj.get("code") or ""
                    if not code:
                        skipped_files += 1
                        continue
                    tokens = normalize_code_with_ids(code)
                    shingles = build_shingles(tokens, K_GRAM)
                    if not shingles:
                        skipped_files += 1
                        continue
                    signature = generate_minhash_signature(shingles, NUM_HASHES)
                    row = {"file_id": file_id, "npm_name": npm_name, "file_path": file_path, "lang": lang, "num_shingles": len(shingles)}
                    for i, h_val in enumerate(signature):
                        row[f"h{i}"] = h_val
                    writer.writerow(row)
                    file_id += 1
                    total_files += 1
    print(f"[OK] Total files: {total_files}, skipped: {skipped_files} -> {output_csv}")


# ---------------------------------------------------------------------------
# Step 2: LSH cluster and aggregate to package pairs
# ---------------------------------------------------------------------------

def compute_minhash_jaccard(sig_a: List[int], sig_b: List[int]) -> float:
    if len(sig_a) != len(sig_b) or len(sig_a) == 0:
        return 0.0
    matches = sum(1 for i in range(len(sig_a)) if sig_a[i] == sig_b[i])
    return matches / len(sig_a)


def lsh_cluster_streaming_per_band(
    input_csv_path: Path,
    output_file_pairs_path: Path,
    num_hashes: int,
    num_bands: int,
    rows_per_band: int,
    min_sim: float,
) -> int:
    assert num_bands * rows_per_band == num_hashes
    output_file_pairs_path.parent.mkdir(parents=True, exist_ok=True)
    f_out = output_file_pairs_path.open("w", encoding="utf-8", newline="")
    writer = csv.DictWriter(f_out, fieldnames=["pkg_a", "file_a", "pkg_b", "file_b", "sim_minhash_jaccard"])
    writer.writeheader()
    MAX_SEEN_PAIRS = 2_000_000
    candidate_pairs_seen: Set[Tuple[int, int]] = set()
    total_written = total_candidates = duplicates_skipped = 0
    try:
        for band_idx in range(num_bands):
            print(f"\n[INFO] Band {band_idx + 1}/{num_bands}...")
            band_buckets: Dict[Tuple[int, ...], Set[int]] = defaultdict(set)
            metadata_dict: Dict[int, Tuple[str, str]] = {}
            file_count = 0
            start_idx = band_idx * rows_per_band
            end_idx = start_idx + rows_per_band
            with input_csv_path.open("r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    file_id = int(row["file_id"])
                    band_hash = tuple(int(row[f"h{i}"]) for i in range(start_idx, end_idx))
                    band_buckets[band_hash].add(file_id)
                    metadata_dict[file_id] = (row["npm_name"], row["file_path"])
                    file_count += 1
                    if file_count % 100000 == 0:
                        print(f"    {file_count} files...")
            print(f"  Built {len(band_buckets)} buckets from {file_count} files")
            MAX_BUCKET_SIZE, MAX_PAIRS_PER_BUCKET = 1000, 100000
            if len(candidate_pairs_seen) > MAX_SEEN_PAIRS:
                items_list = list(candidate_pairs_seen)
                candidate_pairs_seen = set(items_list[len(items_list) // 2 :])
            processed_in_band = skipped_large_buckets = 0
            full_signatures: Dict[int, List[int]] = {}
            for bucket_file_ids in band_buckets.values():
                if len(bucket_file_ids) < 2:
                    continue
                file_list = sorted(bucket_file_ids)[:MAX_BUCKET_SIZE] if len(bucket_file_ids) > MAX_BUCKET_SIZE else sorted(bucket_file_ids)
                if len(bucket_file_ids) > MAX_BUCKET_SIZE:
                    skipped_large_buckets += 1
                bucket_needed_ids = set(file_list)
                missing_ids = [fid for fid in bucket_needed_ids if fid not in full_signatures]
                if missing_ids:
                    with input_csv_path.open("r", encoding="utf-8") as f:
                        for row in csv.DictReader(f):
                            fid = int(row["file_id"])
                            if fid in missing_ids:
                                full_signatures[fid] = [int(row[f"h{i}"]) for i in range(num_hashes)]
                                missing_ids.remove(fid)
                                if not missing_ids:
                                    break
                pairs_in_bucket = 0
                for i in range(len(file_list)):
                    for j in range(i + 1, len(file_list)):
                        if pairs_in_bucket >= MAX_PAIRS_PER_BUCKET:
                            break
                        fa, fb = file_list[i], file_list[j]
                        pair = (fa, fb)
                        if pair in candidate_pairs_seen:
                            duplicates_skipped += 1
                            pairs_in_bucket += 1
                            continue
                        if len(candidate_pairs_seen) < MAX_SEEN_PAIRS:
                            candidate_pairs_seen.add(pair)
                        pairs_in_bucket += 1
                        processed_in_band += 1
                        total_candidates += 1
                        if processed_in_band % 50000 == 0:
                            print(f"    {processed_in_band} pairs, written {total_written}...")
                        sa, sb = full_signatures.get(fa), full_signatures.get(fb)
                        if sa is None or sb is None:
                            continue
                        sim = compute_minhash_jaccard(sa, sb)
                        if sim >= min_sim:
                            npm_a, file_a = metadata_dict[fa]
                            npm_b, file_b = metadata_dict[fb]
                            writer.writerow({"pkg_a": npm_a, "file_a": file_a, "pkg_b": npm_b, "file_b": file_b, "sim_minhash_jaccard": f"{sim:.4f}"})
                            total_written += 1
                            if total_written % 1000 == 0:
                                f_out.flush()
                    if pairs_in_bucket >= MAX_PAIRS_PER_BUCKET:
                        break
                if len(full_signatures) > 50000:
                    items = list(full_signatures.items())
                    full_signatures = dict(items[len(items) // 2 :])
                    gc.collect()
            print(f"  Band done: {processed_in_band} pairs, {skipped_large_buckets} large buckets skipped")
            del band_buckets, metadata_dict
            gc.collect()
        print(f"\n[INFO] Candidate pairs: {total_candidates}, duplicates skipped: {duplicates_skipped}, written: {total_written}")
    finally:
        f_out.close()
    return total_written


def run_cluster(
    input_csv: Path,
    output_dir: Path,
    num_hashes: int,
    num_bands: int,
    rows_per_band: int,
    min_sim: float,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    file_pairs_path = output_dir / "file_pairs_sim_lsh.csv"
    start = time.time()
    num_file_pairs = lsh_cluster_streaming_per_band(
        input_csv, file_pairs_path, num_hashes, num_bands, rows_per_band, min_sim
    )
    print(f"[INFO] Aggregating package-level similarity...")
    pkg_pairs: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    with file_pairs_path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            pkg_a, pkg_b = row["pkg_a"], row["pkg_b"]
            if pkg_a > pkg_b:
                pkg_a, pkg_b = pkg_b, pkg_a
            pkg_pairs[(pkg_a, pkg_b)].append(float(row["sim_minhash_jaccard"]))
    pkg_similarity: Dict[Tuple[str, str], Tuple[float, int]] = {}
    for (pkg_a, pkg_b), sims in pkg_pairs.items():
        avg_sim = sum(sims) / len(sims) if sims else 0.0
        pkg_similarity[(pkg_a, pkg_b)] = (avg_sim, len(sims))
    del pkg_pairs
    gc.collect()
    pkg_pairs_path = output_dir / "pkg_pairs_sim_lsh.csv"
    with pkg_pairs_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["pkg_a", "pkg_b", "sim_pkg_minhash_jaccard", "num_file_pairs"])
        w.writeheader()
        for (pkg_a, pkg_b), (avg_sim, num_pairs) in sorted(pkg_similarity.items()):
            w.writerow({"pkg_a": pkg_a, "pkg_b": pkg_b, "sim_pkg_minhash_jaccard": f"{avg_sim:.4f}", "num_file_pairs": num_pairs})
    total_files = sum(1 for _ in csv.DictReader(input_csv.open("r", encoding="utf-8")))
    elapsed = time.time() - start
    summary_path = output_dir / "summary_lsh.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"Total files: {total_files}\n")
        f.write(f"LSH: bands={num_bands}, rows_per_band={rows_per_band}, hashes={num_hashes}\n")
        f.write(f"Min similarity threshold: {min_sim}\n")
        f.write(f"File pairs (>= threshold): {num_file_pairs}\n")
        f.write(f"Package pairs: {len(pkg_similarity)}\n")
        f.write(f"Time: {elapsed:.2f} sec\n")
    print(f"[OK] {file_pairs_path} | {pkg_pairs_path} | {summary_path}")


# ---------------------------------------------------------------------------
# Step 3: Filter and sort package pairs
# ---------------------------------------------------------------------------

def _detect_sim_column(fieldnames: List[str]) -> Optional[str]:
    for col in SIM_COLUMNS:
        if col in fieldnames:
            return col
    return None


def run_filter(
    input_csv: Path,
    output_csv: Path,
    min_sim_threshold: float,
    top_n: Optional[int] = None,
) -> None:
    if not input_csv.exists():
        raise FileNotFoundError(f"Input not found: {input_csv}")
    rows: List[Dict[str, Any]] = []
    total_rows = filtered_by_threshold = 0
    with input_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        sim_col = _detect_sim_column(fieldnames)
        if not sim_col:
            raise ValueError(f"No similarity column in {input_csv}. Expected one of: {SIM_COLUMNS}")
        for row in reader:
            total_rows += 1
            try:
                sim = float(row[sim_col])
            except (ValueError, KeyError):
                continue
            if sim < min_sim_threshold:
                filtered_by_threshold += 1
                continue
            row[sim_col] = sim
            rows.append(row)
    rows.sort(key=lambda x: x[sim_col], reverse=True)
    if top_n and len(rows) > top_n:
        rows = rows[:top_n]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out = dict(row)
            if isinstance(out.get(sim_col), float):
                out[sim_col] = f"{out[sim_col]:.4f}"
            writer.writerow(out)
    print(f"[INFO] Read {total_rows}, filtered {filtered_by_threshold}, wrote {len(rows)} -> {output_csv}")
    if rows:
        print("Top 10:")
        for i, row in enumerate(rows[:10], 1):
            pa = (row["pkg_a"][:38] + "..") if len(row["pkg_a"]) > 40 else row["pkg_a"]
            pb = (row["pkg_b"][:38] + "..") if len(row["pkg_b"]) > 40 else row["pkg_b"]
            print(f"  {i}. {row[sim_col]}  {pa}  {pb}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Code similarity: build signatures -> LSH cluster -> filter/sort")
    sub = parser.add_subparsers(dest="cmd")
    p_build = sub.add_parser("build-signatures", help="Build MinHash signatures from JSONL")
    p_build.add_argument("--files-dir", type=Path, default=FILES_DIR)
    p_build.add_argument("--output", type=Path, default=SIGNATURES_CSV)
    p_cluster = sub.add_parser("cluster", help="LSH cluster and aggregate to package pairs")
    p_cluster.add_argument("--input", type=Path, default=SIGNATURES_CSV)
    p_cluster.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    p_cluster.add_argument("--min-sim", type=float, default=MIN_SIM_THRESHOLD)
    p_filter = sub.add_parser("filter", help="Filter and sort package pairs by similarity")
    p_filter.add_argument("--input", type=Path, default=PKG_PAIRS_CSV)
    p_filter.add_argument("--output", type=Path, default=PKG_PAIRS_FILTERED_CSV)
    p_filter.add_argument("--threshold", type=float, default=DEFAULT_FILTER_THRESHOLD)
    p_filter.add_argument("--top-n", type=int, default=None)
    p_all = sub.add_parser("all", help="Run build-signatures -> cluster -> filter")
    p_all.add_argument("--files-dir", type=Path, default=FILES_DIR)
    p_all.add_argument("--threshold", type=float, default=DEFAULT_FILTER_THRESHOLD)
    p_all.add_argument("--top-n", type=int, default=None)
    args = parser.parse_args()

    if args.cmd is None:
        args.cmd = "all"
    if args.cmd == "build-signatures":
        run_build_signatures(args.files_dir, args.output)
        return
    if args.cmd == "cluster":
        if not args.input.exists():
            print(f"[ERROR] {args.input} not found. Run build-signatures first.")
            sys.exit(1)
        run_cluster(args.input, args.output_dir, NUM_HASHES, NUM_BANDS, ROWS_PER_BAND, args.min_sim)
        return
    if args.cmd == "filter":
        if not (0.0 <= args.threshold <= 1.0):
            print("[ERROR] --threshold must be in [0, 1]")
            sys.exit(1)
        try:
            run_filter(args.input, args.output, args.threshold, args.top_n)
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERROR] {e}")
            sys.exit(1)
        return
    if args.cmd == "all":
        files_dir = getattr(args, "files_dir", FILES_DIR)
        threshold = getattr(args, "threshold", DEFAULT_FILTER_THRESHOLD)
        top_n = getattr(args, "top_n", None)
        run_build_signatures(files_dir, SIGNATURES_CSV)
        run_cluster(SIGNATURES_CSV, OUTPUT_DIR, NUM_HASHES, NUM_BANDS, ROWS_PER_BAND, MIN_SIM_THRESHOLD)
        try:
            run_filter(PKG_PAIRS_CSV, PKG_PAIRS_FILTERED_CSV, threshold, top_n)
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERROR] filter step: {e}")
            sys.exit(1)
        return
    parser.print_help()


if __name__ == "__main__":
    main()
