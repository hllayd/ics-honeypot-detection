#!/usr/bin/env python3
"""paper_original_port.py - A faithful port of the detection code from the
official repository of Mladenov et al. "All that Glitters is not Gold"
(EuroS&P 2025, github.com/martinmladenov/ICS-Honeypots).

Original pipeline: 3_add_indication_labels.py + 4_classify.py + parameters.py.
This port deviates from the original at ONLY ONE point:
  1) Input format: instead of the Censys Search API (v2) it consumes the Censys
     Platform API (v3) => fields such as host['s7'], host['atg'],
     host['open_port_count'] are derived from
     result.hits[].host_v1.resource.services[] in v3.

network_indication is IN PRINCIPLE THE SAME as in the paper: it uses company.type
and as.type ('hosting'/'education') from the IPinfo 'IP to Company' dataset
(original 2_look_up_as_categories.py + 3_add_indication_labels.py). That data is
extracted OFFLINE from standard_company.mmdb by enrich_ipinfo.py and written to
ipinfo_map.json; it is lazily loaded below.

TEMPORARY DEVIATION (while IPinfo 'IP to Company' access is pending): if
ipinfo_map.json is MISSING, network_indication APPROXIMATES hosting/education from
the Censys autonomous_system.name via keyword matching (HOSTING_KW/ACADEMIC_KW
below). This is NOT identical to the paper and must be reported as a deviation.
Once IPinfo access arrives and enrich_ipinfo.py is run, ipinfo_map.json is created
and the code automatically returns to the paper-faithful IPinfo path with NO
changes required.

APART FROM THAT the signatures/thresholds/decision tree are IDENTICAL to the
original:
  - conpot: plant_id='Mouser Factory', serial_number='88111222'
  - snap7 : system='SNAP7-SERVER', serial_number='S C-C2UR28922012',
            reserved_for_os='MMC 267FF11F'
  - gaspot: '0a0a0a0a' (\\n\\n\\n\\n) in the ATG banner OR a malformed-date regex
  - port thresholds: >10 (low), >30 (high)
  - classify(): HIGH=signature; MEDIUM=hosting|port>30; LOW=education|port>10;
                else real

Usage:  py paper_original_port.py [--file pop_all.json]
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- IPinfo enrichment (the equivalent of the paper's 2_look_up_as_categories.py) ----
# ipinfo_map.json = { ip: {"type": <company_type>, "as_type": <as_type>, ...} }
# produced offline from standard_company.mmdb by enrich_ipinfo.py.
_IPINFO_PATH = os.path.join(HERE, "ipinfo_map.json")
_IPINFO_MAP = None
_IPINFO_WARNED = False


def _ipinfo():
    global _IPINFO_MAP, _IPINFO_WARNED
    if _IPINFO_MAP is None:
        if os.path.exists(_IPINFO_PATH):
            with open(_IPINFO_PATH, encoding="utf-8") as f:
                _IPINFO_MAP = json.load(f)
        else:
            _IPINFO_MAP = {}
            if not _IPINFO_WARNED:
                print("WARNING: ipinfo_map.json missing => network_indication is"
                      " TEMPORARILY running on Censys AS-name keywords (NOT identical"
                      " to the paper). When IPinfo access arrives, run enrich_ipinfo.py;"
                      " the code will automatically switch back to IPinfo.",
                      file=sys.stderr)
                _IPINFO_WARNED = True
    return _IPINFO_MAP


# ---- TEMPORARY: Censys AS-name keyword approach used while IPinfo is missing ----
# (from the paper_classify.py fallback; an APPROXIMATION of the IPinfo 'IP to
#  Company' company.type/as.type fields. Not paper-faithful; a deviation in the
#  report.)
HOSTING_KW = (
    "OVH", "HETZNER", "DIGITALOCEAN", "AMAZON", "AWS", "GOOGLE", "AZURE",
    "MICROSOFT", "LINODE", "VULTR", "CONTABO", "M247", "LEASEWEB", "CHOOPA",
    "DATACAMP", "SCALEWAY", "GODADDY", "HOSTING", "CLOUD", "DATACENTER",
    "DATA CENTER", "COLO", "VPS", "SERVERS", "HOST EUROPE", "IONOS",
)
ACADEMIC_KW = (
    "UNIVERSIT", "RESEARCH", "ACADEMIC", "EDUCATION", "RENATER", "GARR",
    "DFN", "JANET", "SURFNET", "ESNET", "CAMPUS", "COLLEGE", "INSTITUTE",
    "LABORATORY", ".EDU",
)


def _as_name(record):
    return ((record.get("autonomous_system") or {}).get("name") or "").upper()

# ---- parameters.py (original values) ----
honeypot_open_port_threshold = 10
honeypot_open_port_threshold_high = 30

# ---- 3_add_indication_labels.py: s7_honeypot_defaults (original, verbatim) ----
s7_honeypot_defaults = {
    "conpot": {
        "plant_id": "Mouser Factory",
        "serial_number": "88111222",
    },
    "snap7": {
        "system": "SNAP7-SERVER",
        "serial_number": "S C-C2UR28922012",
        "reserved_for_os": "MMC 267FF11F",
    },
}

classification_unknown = "potentially_real"
classification_honeypot_low = "honeypot_low_confidence"
classification_honeypot_medium = "honeypot_medium_confidence"
classification_honeypot_high = "honeypot_high_confidence"


# ---------------------------------------------------------------------------
# v3 (Platform) -> host-level fields expected by the original code
# ---------------------------------------------------------------------------
def reformat(rec):
    """result.hits[].host_v1.resource -> host equivalent to the original
    3_reformat output."""
    services = rec.get("services", [])
    ports = {s.get("port") for s in services if s.get("port") is not None}
    s7_list = [s["s7"] for s in services if isinstance(s.get("s7"), dict)]
    # ATG: v3 has no separate parse object; the banner string is converted to
    # banner_hex.
    atg_list = []
    for s in services:
        if s.get("protocol") == "ATG":
            banner = s.get("banner")
            if banner is None:
                atg_list.append({"banner_hex": None})
            else:
                # banner string -> approximate raw bytes (re-encode via latin-1)
                try:
                    bh = banner.encode("latin-1", "ignore").hex()
                except Exception:
                    bh = banner.encode("utf-8", "ignore").hex()
                atg_list.append({"banner_hex": bh})
    info = _ipinfo().get(rec.get("ip"), {})
    return {
        "open_port_count": len(ports),
        "s7": s7_list,
        "atg": atg_list,
        # IPinfo 'IP to Company' fields (same as the paper): company.type / as.type
        "_ipinfo_company_type": info.get("type"),
        "_ipinfo_as_type": info.get("as_type"),
        # Censys AS-name for the TEMPORARY fallback
        "_as_name": _as_name(rec),
    }


# ---------------------------------------------------------------------------
# indication functions (3_add_indication_labels.py, verbatim port)
# ---------------------------------------------------------------------------
def many_open_ports(host):
    if host["open_port_count"] > honeypot_open_port_threshold:
        return ["many_open_ports"]
    return []


def many_open_ports_high(host):
    if host["open_port_count"] > honeypot_open_port_threshold_high:
        return ["many_open_ports_high"]
    return []


def network_indication(host):
    """PRINCIPLE: paper-faithful (IPinfo as.type/company.type == hosting|education).
    TEMPORARY: if IPinfo data (ipinfo_map.json) is missing, approximate
    hosting/education from the Censys AS-name via keywords. For any host that has
    IPinfo data, IPinfo is ALWAYS used.
    """
    as_type = host.get("_ipinfo_as_type")
    company_type = host.get("_ipinfo_company_type")

    # If this host has IPinfo data => the paper-faithful path
    if as_type is not None or company_type is not None:
        indications = []
        if as_type == "hosting":
            indications.append("as_hosting")
        if as_type == "education":
            indications.append("as_education")
        if company_type == "hosting":
            indications.append("company_hosting")
        if company_type == "education":
            indications.append("company_education")
        return indications

    # TEMPORARY fallback: Censys AS-name keywords (NOT paper-faithful)
    nm = host.get("_as_name", "")
    indications = []
    if any(k in nm for k in HOSTING_KW):
        indications.append("as_hosting")
    if any(k in nm for k in ACADEMIC_KW):
        indications.append("as_education")
    return indications


def s7_honeypot_default(host):
    for s7 in host["s7"]:
        for honeypot_name, defaults in s7_honeypot_defaults.items():
            for d_name, d_value in defaults.items():
                if d_name in s7 and s7[d_name] == d_value:
                    return [f"honeypot_defaults_{honeypot_name}"]
    return []


def gaspot_newlines(host):
    for atg in host["atg"]:
        if atg["banner_hex"] is None:
            continue
        if "0a0a0a0a" in atg["banner_hex"]:  # \n\n\n\n
            return ["gaspot_newlines"]
    return []


def gaspot_date(host):
    for atg in host["atg"]:
        if atg["banner_hex"] is None:
            continue
        banner = bytes.fromhex(atg["banner_hex"])
        if re.search(
            b"\\n(0[1-9]|1[012])/(0[1-9]|[12][0-9]|3[01])/[0-9]{4} "
            b"([01][0-9]|2[0-3]):([0-5][0-9])",
            banner,
        ):
            return ["gaspot_date"]
    return []


indication_functions = [
    many_open_ports,
    many_open_ports_high,
    network_indication,
    s7_honeypot_default,
    gaspot_newlines,
    gaspot_date,
]


# ---------------------------------------------------------------------------
# 4_classify.py (verbatim port)
# ---------------------------------------------------------------------------
def classify(indications):
    signature_criterium = any(
        x in indications for x in [
            "honeypot_defaults_conpot", "honeypot_defaults_snap7",
            "gaspot_newlines", "gaspot_date",
        ]
    )
    if signature_criterium:
        return classification_honeypot_high

    hosting_criterium = any(x in indications for x in ["as_hosting", "company_hosting"])
    if hosting_criterium:
        return classification_honeypot_medium

    if "many_open_ports_high" in indications:
        return classification_honeypot_medium

    education_criterium = any(x in indications for x in ["as_education", "company_education"])
    port_criterium = "many_open_ports" in indications

    if education_criterium and port_criterium:
        return classification_honeypot_medium
    if education_criterium or port_criterium:
        return classification_honeypot_low

    return classification_unknown


def classify_record(rec):
    """v3 record -> (label, indications). A single externally callable API."""
    host = reformat(rec)
    indications = []
    for f in indication_functions:
        indications += f(host)
    return classify(set(indications)), indications


# "detected as a honeypot" = HIGH or MEDIUM (paper: low = 'host of interest',
# NOT counted as a honeypot; see the paper text + funnel.py).
def is_detected_honeypot(label):
    return label in (classification_honeypot_high, classification_honeypot_medium)


def main():
    _file = "pop_all.json"
    if "--file" in sys.argv:
        _file = sys.argv[sys.argv.index("--file") + 1]
    path = os.path.join(HERE, _file)
    with open(path, encoding="utf-8") as f:
        d = json.load(f)

    from collections import Counter
    ct = Counter()
    n = 0
    for h in d["result"]["hits"]:
        rec = h.get("host_v1", {}).get("resource") if "host_v1" in h else h
        if not rec:
            continue
        label, _ = classify_record(rec)
        ct[label] += 1
        n += 1

    print("=" * 64)
    print(f"ORIGINAL PAPER CODE (port) - whole population: {n} hosts")
    print("=" * 64)
    for lab in (classification_honeypot_high, classification_honeypot_medium,
                classification_honeypot_low, classification_unknown):
        print(f"  {lab:28s}: {ct[lab]}")
    hp = ct[classification_honeypot_high] + ct[classification_honeypot_medium]
    print(f"  --> honeypot (HIGH+MEDIUM)   : {hp}")
    print(f"      (LOW = host-of-interest, not counted as honeypot: {ct[classification_honeypot_low]})")


if __name__ == "__main__":
    main()
