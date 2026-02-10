#!/usr/bin/env python3
# Ethics: uses public APIs (Discourse, Reddit); respects rate limits and ToS; no private data.

import os, re, time, json, html, argparse, datetime as dt, random
from typing import List, Dict, Any, Set
from pathlib import Path

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

# ---- optional reddit api
try:
    import praw
except Exception:
    praw = None

# ---- .env auto-load
try:
    from dotenv import load_dotenv
    _ENV_LOADED = load_dotenv(dotenv_path=Path(__file__).with_name(".env"))
    if _ENV_LOADED:
        print("[INIT] .env loaded from", Path(__file__).with_name(".env"))
    else:
        print("[INIT] .env not found or not loaded (will rely on process env)")
except Exception as e:
    print("[INIT] python-dotenv not installed or failed; continuing without .env:", e)

# ========= CONFIG =========
BASE_URL = "https://community.n8n.io"
CATEGORY_ID = 12
OUT_DIR = "../data/community_fullout"
COMM_JSONL = os.path.join(OUT_DIR, "topics_full.jsonl")
REDDIT_JSONL = os.path.join(OUT_DIR, "reddit_full.jsonl")
MERGED_CSV = os.path.join(OUT_DIR, "merged_topics.csv")

# timeouts & rate
TIMEOUT = 20
MAX_RETRY = 4
SLEEP_LIST = 0.5
SLEEP_DETAIL = 0.5

# Reddit public endpoints
REDDIT_PUBLIC_LIMIT = 100
REDDIT_PAGES_DEFAULT = 3
REDDIT_SLEEP = 0.7
REDDIT_LIST_SLEEP = 1.2
REDDIT_LIST_MAX_RETRY = 5

# NLP
NGRAM_RANGE = (1, 3)
TOPK_TERMS = 30
SEED = 42
np.random.seed(SEED)

EN_STOPWORDS = {
    "the","a","an","and","or","but","if","in","on","at","to","for","from","of","by","with","as",
    "is","are","was","were","be","been","being","do","does","did","doing","have","has","had",
    "this","that","these","those","it","its","they","them","their","you","your","i","we","our",
    "can","could","should","would","may","might","must","will","shall","about","into","over",
    "under","again","further","then","once","here","there","when","where","why","how","all",
    "any","both","each","few","more","most","other","some","such","no","nor","not","only","own",
    "same","so","than","too","very","e.g","eg","etc","via","per"
}
CUSTOM_STOPWORDS = {
    "n8n","node","workflow","workflows","issue","help","thanks","hi","hello","please",
    "http","https","www","com","json","api","error","errors","problem","question"
}
STOPWORDS = EN_STOPWORDS | CUSTOM_STOPWORDS

MCP_KEYWORDS = [
    "mcp", "model context protocol", "modelcontextprotocol",
    "@modelcontextprotocol", "mcp server", "mcp client",
    "mcp tool", "mcp resource", "mcp prompt",
    "mcp security", "mcp vulnerability", "mcp risk",
    "mcp privilege", "mcp permission", "mcp access",
    "mcp api", "mcp node", "mcp integration",
]

SECURITY_PATTERNS = {
    "Code Exec / Eval": r"\beval\(|new\s+function\(|setTimeout\(\s*['\"].+\)",
    "ENV / FS Exposure": r"\bprocess\.env\b|\.env|fs\.(read|write|append|mkd)ir|permission denied",
    "SSRF / Outbound":   r"\bssrf\b|unvalidated url|open redirect|http request node",
    "Secrets Leak":      r"(api[_-]?key|secret|token|bearer)\s*(=|:)\s*[\w-]{12,}|hardcoded\s+(secret|credential)",
    "OAuth Misconfig":   r"\boauth(1|2)?\b|refresh token|invalid client|redirect uri|callback url",
    "TLS / Certificates":r"\bssl\b|tls|self[- ]signed|certificate verify failed|insecure",
    "Proxy / Corp Net":  r"\bproxy\b|http_proxy|https_proxy|no_proxy",
    "Binary / Upload":   r"\bbinary\b|multipart|file upload|content[- ]type",
    "HTTP/Webhook":      r"n8n[- ]nodes[- ]base\.httpRequest|webhook node|trigger node",
    "Supply Chain":      r"\b(remote script|untrusted dependency|http import|load script)\b",
    "MCP Security":      r"\bmcp.*?(security|vulnerability|risk|threat|exploit|attack|breach|leak)",
    "MCP Privilege":     r"\bmcp.*?(privilege|permission|access|authorization|unauthorized|escalation)",
    "MCP API Abuse":     r"\bmcp.*?(api|network|system|file|memory).*?(abuse|misuse|unauthorized|unrestricted)",
    "MCP Data Tampering": r"\bmcp.*?(tamper|modify|alter|manipulate|corrupt|inject)",
    "MCP Misinformation": r"\bmcp.*?(misinformation|disinformation|fake|false|manipulate.*?data)",
    "MCP Instability":   r"\bmcp.*?(unstable|crash|error|fail|bug|issue|problem|broken)",
    "MCP Node Issue":    r"\bn8n.*?mcp.*?(node|integration|connector|plugin)",
}

SEC_WEIGHTS = {
    "Code Exec / Eval": 5, "ENV / FS Exposure": 4, "SSRF / Outbound": 4, "Secrets Leak": 5,
    "OAuth Misconfig": 3, "TLS / Certificates": 3, "Proxy / Corp Net": 2, "Binary / Upload": 3,
    "HTTP/Webhook": 3, "Supply Chain": 4,
    "MCP Security": 6, "MCP Privilege": 6, "MCP API Abuse": 5,
    "MCP Data Tampering": 5, "MCP Misinformation": 4, "MCP Instability": 3, "MCP Node Issue": 4,
}

# ========= utils =========
def ensure_outdir(): os.makedirs(OUT_DIR, exist_ok=True)

session = requests.Session()
session.headers.update({
    "User-Agent": os.environ.get("REDDIT_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                                     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "application/json"
})

def safe_get(url, params=None, timeout=TIMEOUT, max_retry=MAX_RETRY):
    backoff = 1.0
    for i in range(max_retry):
        try:
            r = session.get(url, params=params, timeout=timeout)
            if r is None:
                raise RuntimeError("null response")
            if r.status_code in (429, 500, 502, 503, 504):
                sleep = backoff + random.uniform(0, 0.5)
                print(f"[WARN] {r.status_code} {url} -> sleep {sleep:.1f}s retry {i+1}/{max_retry}")
                time.sleep(sleep); backoff = min(backoff*2, 16)
                continue
            r.raise_for_status()
            return r
        except Exception as e:
            if i == max_retry-1:
                print(f"[ERROR] safe_get final fail: {url} ({e})")
                return None
            sleep = backoff + random.uniform(0, 0.5)
            print(f"[WARN] safe_get err: {e} -> sleep {sleep:.1f}s retry {i+1}/{max_retry}")
            time.sleep(sleep); backoff = min(backoff*2, 16)
    return None

def bs_clean_text(raw_html: str) -> str:
    soup = BeautifulSoup(raw_html or "", "html.parser")
    for t in soup.find_all(["pre","code","script","style"]): t.decompose()
    text = soup.get_text(" ")
    text = re.sub(r"(https?://|www\.)\S+", " ", text)                     # urls
    text = re.sub(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", " ", text)               # emails
    text = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff_\-]+", " ", text)            # keep en/cn/_
    text = re.sub(r"\s+", " ", text).strip()
    return html.unescape(text.lower())

def remove_stopwords_and_noise(text: str) -> str:
    toks = [t for t in text.split() if len(t) > 1 and not t.isdigit()]
    toks = [t for t in toks if t not in STOPWORDS]
    return " ".join(toks)

def append_jsonl(path, rows):
    with open(path, "a", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")

def load_ids(path) -> Set[str]:
    if not os.path.exists(path): return set()
    ids=set()
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            try: ids.add(str(json.loads(line)["id"]))
            except: pass
    return ids

# ========= community (public) =========
def fetch_comm_page(page: int):
    r = safe_get(f"{BASE_URL}/c/questions/{CATEGORY_ID}.json?page={page}")
    if r is None: return None
    try: return r.json()
    except: return None

def fetch_comm_topic(tid: str):
    r = safe_get(f"{BASE_URL}/t/{tid}.json")
    if r is None: return None
    try: return r.json()
    except: return None

def crawl_community_public(max_pages=None):
    ensure_outdir()
    seen = load_ids(COMM_JSONL)
    print(f"[COMM] cached topics: {len(seen)}")
    total_new=0; page=0
    acc=[]
    while True:
        if max_pages and page>=max_pages: break
        data = fetch_comm_page(page)
        topics = (data or {}).get("topic_list",{}).get("topics",[])
        if not topics:
            print(f"[COMM][PAGE {page}] no new/empty -> stop")
            break
        page_new=[]
        for t in tqdm(topics, desc=f"Community Page {page}", unit="topic"):
            tid = str(t.get("id"))
            if tid in seen: continue
            d = fetch_comm_topic(tid)
            if not d: continue
            posts = d.get("post_stream",{}).get("posts",[])
            texts = [bs_clean_text(p.get("cooked","")) for p in posts]
            doc = remove_stopwords_and_noise(" ".join([t.get("title","")] + texts))
            item = {
                "platform":"community","id":tid,"title":t.get("title",""),
                "url":f"{BASE_URL}/t/{t.get('slug','')}/{tid}",
                "created_at":t.get("created_at"),
                "views":t.get("views",0),"posts_count":t.get("posts_count",0),
                "like_count":t.get("like_count",0),"doc_text":doc
            }
            page_new.append(item); seen.add(tid); total_new += 1
            time.sleep(SLEEP_DETAIL)
        if page_new:
            append_jsonl(COMM_JSONL,page_new)
            print(f"[COMM][PAGE {page}] new={len(page_new)}, total_new={total_new}")
            acc.extend(page_new)
        else:
            print(f"[COMM][PAGE {page}] no new")
        page += 1; time.sleep(SLEEP_LIST)
    all_rows=[]
    if os.path.exists(COMM_JSONL):
        with open(COMM_JSONL,"r",encoding="utf-8") as f:
            for line in f:
                try: all_rows.append(json.loads(line))
                except: pass
    return all_rows

# ========= reddit: public =========
def reddit_public_list_url(after=None, subreddit=None):
    sub = subreddit or os.environ.get("REDDIT_SUBREDDIT","n8n")
    url = f"https://www.reddit.com/r/{sub}/new.json?limit={REDDIT_PUBLIC_LIMIT}"
    if after: url += f"&after={after}"
    return url

def fetch_reddit_listing_page_public(after=None, subreddit=None):
    resp = safe_get(reddit_public_list_url(after, subreddit))
    if resp is None: return None
    try: return resp.json()
    except: return None

def fetch_reddit_comments_public(permalink):
    if not permalink: return None
    resp = safe_get(f"https://www.reddit.com{permalink}.json?limit=200")
    if resp is None: return None
    try: return resp.json()
    except: return None

def crawl_reddit_public(pages=REDDIT_PAGES_DEFAULT, subreddit="n8n"):
    ensure_outdir()
    seen = load_ids(REDDIT_JSONL)
    print(f"[REDDIT] mode=PUBLIC | cached={len(seen)} | subreddit={subreddit}")
    after=None; total_new=0; all_rows=[]
    for pi in range(pages):
        data=None; backoff=1.0
        for tr in range(REDDIT_LIST_MAX_RETRY):
            data = fetch_reddit_listing_page_public(after, subreddit)
            if data is not None: break
            sleep = backoff + random.uniform(0,0.5)
            print(f"[REDDIT] listing fail p{pi} -> sleep {sleep:.1f}s retry {tr+1}/{REDDIT_LIST_MAX_RETRY}")
            time.sleep(sleep); backoff=min(backoff*2,16)
        if data is None:
            print(f"[REDDIT] page {pi} listing failed after retries -> stop"); break
        children = data.get("data",{}).get("children",[])
        if not children:
            print(f"[REDDIT] page {pi} empty -> stop"); break
        after = data.get("data",{}).get("after")
        page_new=[]
        for child in tqdm(children, desc=f"Reddit Page {pi}", unit="post"):
            post = child.get("data",{})
            pid = post.get("id")
            if not pid or pid in seen:
                time.sleep(REDDIT_SLEEP); continue
            title = post.get("title",""); selftext = post.get("selftext","")
            permalink = post.get("permalink","")
            cmts_text=[]
            cmts = fetch_reddit_comments_public(permalink)
            if isinstance(cmts, list) and len(cmts)>1:
                for c in cmts[1].get("data",{}).get("children",[]):
                    body = c.get("data",{}).get("body","")
                    if body: cmts_text.append(body)
            raw = " ".join([title, selftext] + cmts_text)
            cleaned = remove_stopwords_and_noise(bs_clean_text(raw))
            item = {
                "platform":"reddit","id":pid,"title":title,
                "url":"https://www.reddit.com"+permalink if permalink else post.get("url",""),
                "created_at":dt.datetime.utcfromtimestamp(post.get("created_utc",0)).isoformat()+"Z",
                "views":post.get("view_count",0) or 0,
                "posts_count":post.get("num_comments",0),"like_count":post.get("score",0),
                "doc_text":cleaned
            }
            page_new.append(item); seen.add(pid); total_new+=1; time.sleep(REDDIT_SLEEP)
        if page_new:
            append_jsonl(REDDIT_JSONL, page_new)
            print(f"[REDDIT][PAGE {pi}] new={len(page_new)}, total_new={total_new}")
            all_rows.extend(page_new)
        else:
            print(f"[REDDIT][PAGE {pi}] no new")
        time.sleep(REDDIT_LIST_SLEEP)
        if not after: print("[REDDIT] no 'after' -> stop"); break
    if os.path.exists(REDDIT_JSONL):
        with open(REDDIT_JSONL,"r",encoding="utf-8") as f:
            for line in f:
                try: all_rows.append(json.loads(line))
                except: pass
    return all_rows

# ========= reddit: API (PRAW) =========
def crawl_reddit_api(pages=REDDIT_PAGES_DEFAULT, subreddit="n8n",
                     client_id=None, client_secret=None, user_agent=None):
    ensure_outdir()
    if not praw:
        print("[REDDIT] praw not installed -> fallback PUBLIC")
        return crawl_reddit_public(pages, subreddit)
    if not (client_id and client_secret and user_agent):
        print("[REDDIT] API creds missing -> fallback PUBLIC")
        return crawl_reddit_public(pages, subreddit)

    seen = load_ids(REDDIT_JSONL)
    print(f"[REDDIT] mode=API | cached={len(seen)} | subreddit={subreddit}")
    reddit = praw.Reddit(client_id=client_id, client_secret=client_secret, user_agent=user_agent)
    sub = reddit.subreddit(subreddit)

    total_new=0; batch=[]
    limit = max(1, pages) * 100
    for post in tqdm(sub.new(limit=limit), desc="PRAW fetching", unit="post"):
        pid = getattr(post, "id", None)
        if not pid or pid in seen: continue
        try: post.comments.replace_more(limit=0)
        except Exception: pass
        comments = [c.body for c in getattr(post, "comments", []).list() if getattr(c, "body", None)]
        raw = " ".join([(post.title or ""), (post.selftext or "")] + comments)
        cleaned = remove_stopwords_and_noise(bs_clean_text(raw))
        item = {
            "platform":"reddit","id":pid,"title":post.title or "",
            "url":f"https://www.reddit.com{post.permalink}",
            "created_at":dt.datetime.utcfromtimestamp(getattr(post,"created_utc",0)).isoformat()+"Z",
            "views":getattr(post,"view_count",0) or 0,
            "posts_count":getattr(post,"num_comments",0) or 0,
            "like_count":getattr(post,"score",0) or 0,
            "doc_text":cleaned
        }
        batch.append(item); seen.add(pid); total_new += 1
        if len(batch) >= 50:
            append_jsonl(REDDIT_JSONL, batch); batch=[]; time.sleep(0.2)
    if batch: append_jsonl(REDDIT_JSONL, batch)
    print(f"[REDDIT] API total_new={total_new}")

    all_rows=[]
    if os.path.exists(REDDIT_JSONL):
        with open(REDDIT_JSONL,"r",encoding="utf-8") as f:
            for line in f:
                try: all_rows.append(json.loads(line))
                except: pass
    return all_rows

# ========= NLP & security =========
def tfidf_top_terms(docs, topk=TOPK_TERMS):
    if not docs: return [], None, None
    v = TfidfVectorizer(ngram_range=NGRAM_RANGE, max_df=0.6, min_df=2,
                        token_pattern=r"(?u)\b[\w\u4e00-\u9fff]+\b")
    X = v.fit_transform(docs)
    s = np.asarray(X.sum(axis=0)).ravel()
    idx = s.argsort()[::-1][:topk]
    return [(v.get_feature_names_out()[i], float(s[i])) for i in idx], v, X

def compile_sec_patterns():
    return {k: re.compile(v, re.I) for k, v in SECURITY_PATTERNS.items()}

def is_mcp_related(text: str) -> bool:
    text_lower = text.lower()
    return any(keyword.lower() in text_lower for keyword in MCP_KEYWORDS)

def security_hits_and_score(text: str):
    pats = compile_sec_patterns()
    hits = [cat for cat, pat in pats.items() if pat.search(text)]
    score = sum(SEC_WEIGHTS.get(h, 1) for h in hits)
    return hits, score

# ========= visuals =========
def plot_wordcloud(texts, fname):
    if not texts: return
    txt = " ".join(texts)
    wc = WordCloud(width=1600, height=900, background_color="white",
                   max_words=400, collocations=False, colormap="viridis").generate(txt)
    wc.to_file(fname)

def plot_topkeywords(pairs, fname, topn=30):
    if not pairs: return
    pairs = pairs[:topn]
    terms, scores = zip(*pairs)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(scores), y=list(terms), color="skyblue")
    plt.title("Top TF-IDF Terms"); plt.tight_layout(); plt.savefig(fname, dpi=150); plt.close()

def plot_trend(df, fname):
    if df.empty: return
    df["month"] = df["created_at"].dt.to_period("M")
    t = df.groupby(["platform", "month"]).size().reset_index(name="count")
    plt.figure(figsize=(10, 5))
    for plat, sub in t.groupby("platform"):
        sub = sub.sort_values("month")
        plt.plot(sub["month"].astype(str), sub["count"], marker="o", label=plat)
    plt.title("Monthly Trend by Platform")
    plt.xticks(rotation=45, ha="right"); plt.legend()
    plt.tight_layout(); plt.savefig(fname, dpi=150); plt.close()

# ========= main =========
def main(args):
    ensure_outdir()

    comm = crawl_community_public(max_pages=args.max_pages)

    rid = os.environ.get("REDDIT_CLIENT_ID")
    rsecret = os.environ.get("REDDIT_CLIENT_SECRET")
    rua = os.environ.get("REDDIT_USER_AGENT")
    subreddit = args.reddit_subreddit or os.environ.get("REDDIT_SUBREDDIT","n8n")

    print(f"[DEBUG] Reddit creds present? CID={bool(rid)}, CSEC={bool(rsecret)}, UA={bool(rua)}")
    print(f"[DEBUG] reddit_subreddit={subreddit}")

    if (rid and rsecret and rua) and not args.force_public_reddit:
        print("[REDDIT] mode=API (PRAW)")
        red = crawl_reddit_api(pages=args.reddit_pages, subreddit=subreddit,
                               client_id=rid, client_secret=rsecret, user_agent=rua)
    else:
        print("[REDDIT] mode=PUBLIC (anonymous JSON)")
        red = crawl_reddit_public(pages=args.reddit_pages, subreddit=subreddit)

    rows = (comm or []) + (red or [])
    if not rows:
        print("[ERROR] No data crawled."); return

    df = pd.DataFrame(rows)
    df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)

    if args.mcp_only:
        df["is_mcp_related"] = df["doc_text"].fillna("").apply(is_mcp_related)
        df = df[df["is_mcp_related"]].copy()
        print(f"[MCP-ONLY] Filtered to MCP-related rows: {len(df)}")
        if df.empty:
            print("[ERROR] No MCP-related data found."); return
    
    df.to_csv(MERGED_CSV, index=False)
    print(f"[INFO] merged rows: {len(df)} -> {MERGED_CSV}")

    docs = df["doc_text"].fillna("").tolist()
    top_terms, v, X = tfidf_top_terms(docs)
    plot_wordcloud(docs, os.path.join(OUT_DIR, "wordcloud_all.png"))
    plot_topkeywords(top_terms, os.path.join(OUT_DIR, "top_keywords.png"))
    plot_trend(df, os.path.join(OUT_DIR, "trend_by_platform.png"))

    df["is_mcp_related"] = df["doc_text"].fillna("").apply(is_mcp_related)
    df_mcp = df[df["is_mcp_related"]].copy()
    mcp_csv = os.path.join(OUT_DIR, "topics_mcp_related.csv")
    if not df_mcp.empty:
        df_mcp.to_csv(mcp_csv, index=False)
        print(f"[MCP] MCP-related rows: {len(df_mcp)} -> {mcp_csv}")
    else:
        print(f"[MCP] No MCP-related rows found")

    df["sec_hits"] = [[] for _ in range(len(df))]
    df["sec_score"] = 0
    sec_hits_map = {}
    for i, row in df.iterrows():
        hits, score = security_hits_and_score(row.get("doc_text",""))
        df.at[i,"sec_hits"] = hits
        df.at[i,"sec_score"] = score
        for h in hits: sec_hits_map.setdefault(h, []).append(row.to_dict())

    df_sec = df[df["sec_score"]>0].copy()
    sec_csv = os.path.join(OUT_DIR, "topics_security_only.csv")
    df_sec.to_csv(sec_csv, index=False)
    print(f"[SEC] rows with security signals: {len(df_sec)} -> {sec_csv}")

    df_mcp_sec = df[(df["is_mcp_related"]) & (df["sec_score"] > 0)].copy()
    mcp_sec_csv = os.path.join(OUT_DIR, "topics_mcp_security.csv")
    if not df_mcp_sec.empty:
        df_mcp_sec.to_csv(mcp_sec_csv, index=False)
        print(f"[MCP+SEC] MCP + Security rows: {len(df_mcp_sec)} -> {mcp_sec_csv}")
    else:
        print(f"[MCP+SEC] No MCP + Security rows found")

    sec_counts = sorted(((k,len(v)) for k,v in sec_hits_map.items()), key=lambda x:x[1], reverse=True)
    sec_docs = df_sec["doc_text"].tolist()
    sec_terms, _, _ = tfidf_top_terms(sec_docs, topk=40) if len(sec_docs)>0 else ([],None,None)
    plot_wordcloud(sec_docs, os.path.join(OUT_DIR, "wordcloud_security.png"))
    plot_topkeywords(sec_terms, os.path.join(OUT_DIR, "top_keywords_security.png"))
    plot_trend(df_sec, os.path.join(OUT_DIR, "trend_security_by_platform.png"))

    if not df_mcp_sec.empty:
        mcp_sec_docs = df_mcp_sec["doc_text"].tolist()
        mcp_sec_terms, _, _ = tfidf_top_terms(mcp_sec_docs, topk=30) if len(mcp_sec_docs)>0 else ([],None,None)
        plot_wordcloud(mcp_sec_docs, os.path.join(OUT_DIR, "wordcloud_mcp_security.png"))
        plot_topkeywords(mcp_sec_terms, os.path.join(OUT_DIR, "top_keywords_mcp_security.png"))
        plot_trend(df_mcp_sec, os.path.join(OUT_DIR, "trend_mcp_security_by_platform.png"))

    mcp_sec_counts = {}
    for i, row in df_mcp_sec.iterrows():
        for hit in row.get("sec_hits", []):
            if "MCP" in hit:
                mcp_sec_counts[hit] = mcp_sec_counts.get(hit, 0) + 1

    report = os.path.join(OUT_DIR, "report_security.md")
    with open(report,"w",encoding="utf-8") as f:
        f.write(f"# n8n Security/Privacy Related Topics Report\n\nGenerated: {dt.datetime.now()}\n\n")
        f.write(f"- Total merged posts: {len(df)}\n")
        f.write(f"- Security-related posts: {len(df_sec)}\n")
        f.write(f"- MCP-related posts: {len(df_mcp)}\n")
        f.write(f"- **MCP + Security posts: {len(df_mcp_sec)}**\n\n")

        if not df_mcp_sec.empty:
            f.write("## MCP Security (focus)\n\n")
            f.write(f"Found **{len(df_mcp_sec)}** MCP-related security posts.\n\n")

            if mcp_sec_counts:
                f.write("### MCP security category counts\n")
                for cat, cnt in sorted(mcp_sec_counts.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"- {cat}: {cnt}\n")
                f.write("\n")

            f.write("### Sample MCP security posts\n")
            for i, row in df_mcp_sec.head(20).iterrows():
                title = row.get("title", "")
                url = row.get("url", "")
                platform = row.get("platform", "")
                views = row.get("views", 0)
                posts = row.get("posts_count", 0)
                sec_hits = row.get("sec_hits", [])
                sec_score = row.get("sec_score", 0)
                f.write(f"- [{title}]({url}) | {platform} | views:{views} comments:{posts} | sec_score:{sec_score} | {', '.join(sec_hits[:3])}\n")
            f.write("\n")

        f.write("## Top security categories (all)\n")
        for cat,cnt in sec_counts[:15]:
            f.write(f"- {cat} ({cnt})\n")
        f.write("\n## Sample posts (up to 5 per category)\n")
        for cat,_ in sec_counts[:15]:
            rows_cat = (sec_hits_map.get(cat) or [])[:5]
            if not rows_cat: continue
            f.write(f"### {cat}\n")
            for r in rows_cat:
                f.write(f"- [{r.get('title','')}]({r.get('url','')}) | platform:{r.get('platform','')} | views:{r.get('views',0)} comments:{r.get('posts_count',0)}\n")
            f.write("\n")
    print("\nOutputs:")
    print(f" - {MERGED_CSV}")
    print(f" - {OUT_DIR}/wordcloud_all.png / top_keywords.png / trend_by_platform.png")
    print(f" - {OUT_DIR}/topics_security_only.csv")
    print(f" - {OUT_DIR}/wordcloud_security.png / top_keywords_security.png / trend_security_by_platform.png")
    if not df_mcp.empty:
        print(f" - {OUT_DIR}/topics_mcp_related.csv (MCP-related)")
    if not df_mcp_sec.empty:
        print(f" - {OUT_DIR}/topics_mcp_security.csv (MCP security)")
        print(f" - {OUT_DIR}/wordcloud_mcp_security.png / top_keywords_mcp_security.png / trend_mcp_security_by_platform.png")
    print(f" - {report}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--max-pages", type=int, default=None, help="Discourse listing pages (public)")
    p.add_argument("--reddit-pages", type=int, default=REDDIT_PAGES_DEFAULT, help="Reddit pages (~pages*100 in API)")
    p.add_argument("--reddit-subreddit", type=str, default=os.environ.get("REDDIT_SUBREDDIT","n8n"))
    p.add_argument("--force-public-reddit", action="store_true",
                   help="Force Reddit to use public JSON even if API creds exist")
    p.add_argument("--mcp-only", action="store_true",
                   help="Only output MCP-related topics (filter out non-MCP content)")
    args = p.parse_args()
    main(args)
