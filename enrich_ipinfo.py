#!/usr/bin/env python3
"""enrich_ipinfo.py - A faithful equivalent of the paper's 2_look_up_as_categories.py
step.

The paper queries the IPinfo 'IP to Company' database (standard_company.mmdb)
OFFLINE with maxminddb and adds company.type + as.type to each host. This script
does the same for Censys Platform (v3) data: it looks up every UNIQUE IP in
pop_all.json against the MMDB and writes the result to ipinfo_map.json.
paper_original_port.py uses this map.

IPinfo record (verified fields):
  { name, domain, type, asn, as_name, as_domain, as_type, country }
The paper's classification uses only 'type' (company) and 'as_type'.

Requirement:
  pip install maxminddb
  standard_company.mmdb  (download from your IPinfo account; place in this directory)

Usage:
  py enrich_ipinfo.py [--file pop_all.json] [--db standard_company.mmdb]
Output:
  ipinfo_map.json  = { ip: {name,domain,type,asn,as_name,as_domain,as_type,country} }
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def arg(name, default):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return default


def main():
    try:
        import maxminddb
    except ImportError:
        sys.exit("ERROR: 'maxminddb' is missing. Install: pip install maxminddb")

    pop = os.path.join(HERE, arg("--file", "pop_all.json"))
    db = os.path.join(HERE, arg("--db", "standard_company.mmdb"))
    out = os.path.join(HERE, "ipinfo_map.json")

    if not os.path.exists(db):
        sys.exit(f"ERROR: {db} is missing. Download the IPinfo 'IP to Company' MMDB "
                 f"file and place it here (see file header).")
    if not os.path.exists(pop):
        sys.exit(f"ERROR: {pop} is missing.")

    # unique IPs
    with open(pop, encoding="utf-8") as f:
        d = json.load(f)
    ips = set()
    for h in d["result"]["hits"]:
        rec = h.get("host_v1", {}).get("resource") if "host_v1" in h else h
        if rec and rec.get("ip"):
            ips.add(rec["ip"])
    print(f"Unique IPs: {len(ips)}")

    result = {}
    miss = 0
    with maxminddb.open_database(db) as ipinfo:
        for ip in ips:
            data = ipinfo.get(ip)
            if data is None:
                miss += 1
                continue
            # Same field selection as the paper's add_as_categories
            result[ip] = {
                "name": data.get("name"),
                "domain": data.get("domain"),
                "type": data.get("type"),            # company.type
                "asn": data.get("asn"),
                "as_name": data.get("as_name"),
                "as_domain": data.get("as_domain"),
                "as_type": data.get("as_type"),      # as.type
                "country": data.get("country"),
            }

    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)

    from collections import Counter
    ct = Counter(v.get("type") for v in result.values())
    at = Counter(v.get("as_type") for v in result.values())
    print(f"Matched: {len(result)}  |  not found in MMDB: {miss}")
    print(f"company.type distribution: {dict(ct)}")
    print(f"as.type distribution     : {dict(at)}")
    print(f"-> {out}")


if __name__ == "__main__":
    main()
