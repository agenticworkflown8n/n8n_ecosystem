#!/usr/bin/env python3
"""
MCP template security: connection config (auth/verification) + empirical risks (UUID, tunneling, localhost, third-party).
Single pass, console summary only.
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = BASE / "data" / "n8n_templates_dump" / "workflows"
STATS_FILE = BASE / "data" / "MULTI-AGENT" / "multi_agent_mcp_stats.json"

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
TUNNELING = ("ngrok", "localtunnel", "rshare.io", "localhost.run", "localtest.me", "serveo", "bore.pub", "tunnel")


def _is_mcp_node(ntype: str) -> bool:
    t = ntype.lower()
    return "mcpclient" in t or "mcptrigger" in t


def _is_external(url: str) -> bool:
    if not url:
        return False
    u = str(url).lower()
    return "localhost" not in u and "127.0.0.1" not in u and "0.0.0.0" not in u


def _has_auth(params) -> bool:
    if params.get("authentication") or params.get("authType") or params.get("auth"):
        return True
    headers = params.get("headers") or params.get("headerParameters") or {}
    if not isinstance(headers, dict):
        return False
    for h in headers.get("parameters") or []:
        if not isinstance(h, dict):
            continue
        n = (h.get("name") or "").lower()
        if any(k in n for k in ("auth", "bearer", "token", "api")) and h.get("value"):
            return True
    return False


def _has_verification(params) -> bool:
    return (
        params.get("verifySSL") is not None
        or params.get("ssl") is not None
        or params.get("tls") is not None
    )


def _get_url(params) -> str:
    u = params.get("endpointUrl") or params.get("url") or params.get("serverUrl") or params.get("endpoint")
    if not u or not isinstance(u, str) or str(u).strip().startswith("="):
        return ""
    return str(u).strip()


def _tunneling(url: str) -> bool:
    return any(p in url.lower() for p in TUNNELING)


def _localhost_exposed(url: str) -> bool:
    u = url.lower()
    if "localhost" not in u and "127.0.0.1" not in u:
        return False
    if u.startswith("http://"):
        return True
    m = re.search(r":(\d+)", u)
    return m and int(m.group(1)) not in (80, 443, 8080)


def _third_party_domain(domain: str) -> bool:
    return "n8n" in domain.lower() and domain not in ("n8n.io", "n8n.cloud")


def main():
    if not STATS_FILE.exists():
        print(f"Stats not found: {STATS_FILE}")
        return
    mcp_ids = {t["id"] for t in json.loads(STATS_FILE.read_text(encoding="utf-8")).get("details", []) if t.get("has_mcp")}
    if not mcp_ids or not TEMPLATES_DIR.exists():
        print("No MCP templates or templates dir missing.")
        return

    conn = {
        "with_mcp": 0,
        "with_external": 0,
        "without_auth": 0,
        "without_verification": 0,
        "external_urls": set(),
        "auth_types": defaultdict(int),
    }
    emp = {
        "uuid_usage": defaultdict(list),
        "tunneling": [],
        "localhost_exposed": [],
        "third_party_aggregators": defaultdict(list),
        "templates_with_urls": set(),
    }
    analyzed = 0

    for path in TEMPLATES_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Error {path}: {e}")
            continue
        tid = data.get("workflow", {}).get("id")
        if tid not in mcp_ids:
            continue
        analyzed += 1
        wf = data.get("workflow", {}).get("workflow", {})
        nodes = wf.get("nodes", [])
        tname = data.get("workflow", {}).get("name", "")

        has_mcp = has_external = has_auth = has_verification = False
        for node in nodes:
            ntype = node.get("type", "")
            if not _is_mcp_node(ntype):
                continue
            has_mcp = True
            params = node.get("parameters", {})
            url = _get_url(params)
            if not url:
                continue
            emp["templates_with_urls"].add(tid)
            if _is_external(url):
                has_external = True
                conn["external_urls"].add(url)
            if _has_auth(params):
                has_auth = True
                at = params.get("authentication") or params.get("authType") or params.get("auth")
                if at:
                    conn["auth_types"][str(at)] += 1
            if _has_verification(params):
                has_verification = True
            for uuid in UUID_RE.findall(url):
                emp["uuid_usage"][uuid].append({"template_id": tid, "url": url})
            if _tunneling(url):
                emp["tunneling"].append({"template_id": tid, "template_name": tname, "url": url})
            if _localhost_exposed(url):
                emp["localhost_exposed"].append({"template_id": tid, "template_name": tname, "url": url})
            try:
                domain = (urlparse(url).netloc or url.split("/")[0]).strip()
                if domain and "." in domain and _third_party_domain(domain):
                    emp["third_party_aggregators"][domain].append({"template_id": tid, "url": url})
            except Exception:
                pass

        if has_mcp:
            conn["with_mcp"] += 1
        if has_external:
            conn["with_external"] += 1
            if not has_auth:
                conn["without_auth"] += 1
            if not has_verification:
                conn["without_verification"] += 1

    n_ext = conn["with_external"]
    n_urls = len(emp["templates_with_urls"])
    shared_uuids = {u: c for u, c in emp["uuid_usage"].items() if len(c) > 1}
    agg_count = sum(len(c) for c in emp["third_party_aggregators"].values())
    agg_pct = (100 * agg_count / n_urls) if n_urls else 0
    uuid_tpl = len({i["template_id"] for c in emp["uuid_usage"].values() for i in c})
    uuid_pct = (100 * uuid_tpl / n_urls) if n_urls else 0

    print("MCP Security (connection + empirical)")
    print("Templates analyzed:", analyzed)
    print("With MCP nodes:", conn["with_mcp"])
    print("With external servers:", conn["with_external"])
    print("External without auth:", conn["without_auth"], f"({100 * conn['without_auth'] / n_ext:.1f}%)" if n_ext else "")
    print("External without verification:", conn["without_verification"], f"({100 * conn['without_verification'] / n_ext:.1f}%)" if n_ext else "")
    print("Unique external URLs:", len(conn["external_urls"]))
    if conn["auth_types"]:
        print("Auth types:", dict(sorted(conn["auth_types"].items(), key=lambda x: -x[1])))
    print("Third-party aggregator configs:", agg_count, f"({agg_pct:.1f}% of templates with URLs)")
    print("Templates with UUID in URL:", uuid_tpl, f"({uuid_pct:.1f}%)")
    print("Shared UUIDs:", len(shared_uuids))
    print("Tunneling URLs:", len(emp["tunneling"]))
    print("Exposed localhost:", len(emp["localhost_exposed"]))


if __name__ == "__main__":
    main()
