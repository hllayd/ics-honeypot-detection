"""Collects the ENTIRE set of Censys Platform search results into a single file
by paginating. Follows next_page_token and concatenates the 'hits' list of all
pages.

Usage (PowerShell):
    $env:CENSYS_PAT = "censys_pat_xxx"           # Personal Access Token
    $env:CENSYS_ORG = "12345678-91011-1213"      # Organization ID
    py paginate_all.py

Output: from_papers_all.json  -> {"result": {"total_hits": N, "hits": [...]}}
This file can be inspected directly with inspect_results.py:
    py inspect_results.py --file from_papers_all.json
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))

# Default: query.txt -> from_papers_all.json
# For the control set:  py paginate_all.py query_control.txt control_all.json
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
QUERY_FILE = os.path.join(HERE, _args[0]) if len(_args) >= 1 else os.path.join(HERE, "query.txt")
OUT = os.path.join(HERE, _args[1]) if len(_args) >= 2 else os.path.join(HERE, "from_papers_all.json")
# Third arg: maximum pages (e.g. 1 to just see total_hits). Otherwise the default.
_max_pages_override = int(_args[2]) if len(_args) >= 3 else None

URL = "https://api.platform.censys.io/v3/global/search/query"
PAGE_SIZE = 100          # maximum
MAX_PAGES = _max_pages_override if _max_pages_override else 5000  # safety limit (500k hosts)

# --slim: reduce each host to only the fields needed for analysis (on a large
# population fetch ~5GB -> ~300MB). Does not affect detection accuracy: ICS
# structural fields, banner, http title/headers and labels are kept; the http
# body/certificate/tls are dropped.
SLIM = "--slim" in sys.argv

# Protocol-structural sub-objects to keep (for collision + signature detection)
_KEEP_STRUCT = (
    "s7", "eip", "fox", "modbus", "bacnet", "atg", "iec60870_5_104",
    "fins", "mms", "dnp3", "opc_ua", "codesys", "wdbrpc", "profinet",
    "melsec", "ge_srtp", "pcworx", "hart", "pcom",
)


def _slim_service(s):
    out = {}
    for k in ("protocol", "transport_protocol", "port", "labels", "banner",
              "software", "vendor", "product"):
        if k in s:
            v = s[k]
            if k == "banner" and isinstance(v, str):
                v = v[:2000]
            out[k] = v
    for k in _KEEP_STRUCT:
        if isinstance(s.get(k), dict):
            out[k] = s[k]
    http = s.get("http")
    if isinstance(http, dict):
        h = {}
        for k in ("title", "html_title", "headers", "server", "status_code"):
            if k in http:
                h[k] = http[k]
        # response.body is very large -> skip; keep only title/headers
        resp = http.get("response")
        if isinstance(resp, dict):
            for k in ("html_title", "headers", "status_code"):
                if k in resp:
                    h.setdefault(k, resp[k])
        if h:
            out["http"] = h
    for k in ("ftp", "snmp", "telnet"):
        o = s.get(k)
        if isinstance(o, dict) and o.get("banner"):
            out[k] = {"banner": str(o["banner"])[:1000]}
    return out


def _slim_hit(hit):
    r = hit.get("host_v1", {}).get("resource")
    if not isinstance(r, dict):
        return hit
    slim = {"ip": r.get("ip")}
    loc = r.get("location")
    if isinstance(loc, dict):
        slim["location"] = {k: loc.get(k) for k in ("country", "country_code", "city") if k in loc}
    asn = r.get("autonomous_system")
    if isinstance(asn, dict):
        slim["autonomous_system"] = {k: asn.get(k) for k in ("asn", "name") if k in asn}
    slim["services"] = [_slim_service(s) for s in r.get("services", [])]
    return {"host_v1": {"resource": slim}}


def die(msg):
    print("ERROR:", msg, file=sys.stderr)
    sys.exit(1)


def main():
    pat = os.environ.get("CENSYS_PAT")
    org = os.environ.get("CENSYS_ORG")
    if not pat:
        die("CENSYS_PAT environment variable is empty. First: $env:CENSYS_PAT = 'censys_pat_...'")
    if not org:
        print("WARNING: CENSYS_ORG is empty; will try with Free account permissions.", file=sys.stderr)

    with open(QUERY_FILE, encoding="utf-8") as f:
        query = f.read().strip()

    headers = {
        "Authorization": f"Bearer {pat}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Cloudflare blocks the default 'Python-urllib' UA (Error 1010).
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sec592-research/1.0",
    }
    if org:
        headers["X-Organization-ID"] = org

    all_hits = []
    page_token = None
    total_hits = None

    for page in range(1, MAX_PAGES + 1):
        body = {"query": query, "page_size": PAGE_SIZE}
        if page_token:
            body["page_token"] = page_token

        req = urllib.request.Request(
            URL, data=json.dumps(body).encode("utf-8"),
            headers=headers, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            die(f"HTTP {e.code} (page {page}): {detail[:500]}")
        except urllib.error.URLError as e:
            die(f"Connection error (page {page}): {e}")

        r = data.get("result", {})
        hits = r.get("hits", [])
        if SLIM:
            hits = [_slim_hit(h) for h in hits]
        all_hits.extend(hits)
        if total_hits is None:
            total_hits = r.get("total_hits")
        page_token = r.get("next_page_token")
        print(f"Page {page}: +{len(hits)} hosts  (total collected: {len(all_hits)}"
              f"{' / ' + str(total_hits) if total_hits else ''})")

        if not page_token or not hits:
            break
        time.sleep(0.3)   # gentle rate limit

    out = {"result": {"total_hits": total_hits, "hits": all_hits}}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    print(f"\nDone. {len(all_hits)} hosts written -> {OUT}")


if __name__ == "__main__":
    main()
