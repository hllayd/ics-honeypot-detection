#!/usr/bin/env python3
"""Select top residual hosts for active probing.

Purpose
- Focus on hosts that are still not HIGH/MEDIUM in passive pipeline (LOW or NONE).
- Rank by non-productive likelihood using existing weak signals + new strong candidates.
- Emit top-N candidates with protocol-aware probe bundles.

Inputs (same folder by default)
- residual_paper17.json
- deep_findings_paper17.csv
- bacnet_vendor_ids.html (optional but strongly recommended)

Output
- active_probe_top100.csv
"""

import csv
import html
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))

# Cellular / eyeball / IoT-SIM carrier AS-name keywords. Batches with L, M and
# batch10 proved these ASNs are a false-positive trap: real cellular Modbus/EIP
# gateways behind CGNAT reproduce the single-metric "honeypot" signatures
# (exc_type=11, shared default socket_addr, empty serial-side) as LEGITIMATE
# behavior. Honeypots live on hosting/transit (cloud), not on SIM fleets.
# --exclude-cellular drops these so active-probe budget targets probable hits.
CELLULAR_KEYWORDS = (
    "cellco", "verizon wireless", "verizon business", "mobility", "at&t mob",
    "orange", "telefonica", "vodafone", "t-mobile", "deutsche telekom", "dtag",
    "wireless logic", "windtre", "wind tre", "telus", "hinet", "cosmote",
    "proximus", "telenor", "m2m", "iot", "sim", "lte", "gprs", "cellular",
    "mobile", "telstra", "telecom italia", "tim ", "bouygues", "sfr", "o2",
    "three", "swisscom", "telia", "kpn", "movistar", "claro", "vivo",
)


def is_cellular(as_name: str) -> bool:
    n = (as_name or "").lower()
    return any(k in n for k in CELLULAR_KEYWORDS)


def arg(name: str, default: str) -> str:
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


def load_findings(path: str):
    out = {}
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            out[row["ip"]] = row
    return out


def load_bacnet_unique_registry(path: str):
    """Return lower(vendor_name)->expected_vendor_id for names with unique official IDs."""
    if not os.path.exists(path):
        return {}

    s = open(path, encoding="utf-8", errors="ignore").read()
    rows = re.findall(r"<tr[^>]*>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>", s, re.I | re.S)

    name_to_ids = defaultdict(set)
    for a, b in rows:
        a = html.unescape(re.sub(r"<[^<]+?>", " ", a)).strip()
        b = html.unescape(re.sub(r"<[^<]+?>", " ", b)).strip()
        b = " ".join(b.split())
        if a.isdigit() and b:
            name_to_ids[b.lower()].add(int(a))

    unique = {}
    for name, ids in name_to_ids.items():
        if len(ids) == 1:
            unique[name] = next(iter(ids))
    return unique


def probe_catalog():
    # Read-only, low-impact protocol probes that can be run from a controlled scanner box.
    return {
        "S7": "S7_READONLY",
        "MODBUS": "MODBUS_READONLY",
        "BACNET": "BACNET_READONLY",
        "EIP": "EIP_READONLY",
        "FINS": "FINS_READONLY",
        "OPC_UA": "OPCUA_READONLY",
        "MMS": "MMS_READONLY",
        "IEC60870_5_104": "IEC104_READONLY",
        "FOX": "FOX_READONLY",
        "WDBRPC": "WDBRPC_READONLY",
        "DNP3": "DNP3_READONLY",
        "ATG": "ATG_READONLY",
        "CODESYS": "CODESYS_READONLY",
        "PCWORX": "PCWORX_READONLY",
        "GE_SRTP": "GESRTP_READONLY",
        "HART": "HART_READONLY",
        "PRO_CON_OS": "PROCONOS_READONLY",
    }


def score_from_low_indicators(ind_set):
    # Higher = more likely non-productive from passive evidence.
    w = {
        "B_template_id": 90,
        "J_bacnet_reserved_id": 88,
        "G_opcua_degenerate": 86,
        "A_vendor_conflict": 84,
        "F_serial_clone": 82,
        "I_opcua_sdk_default": 78,
        "N_eip_services_no_identity": 75,
        "E_proto_implausible": 74,
        "K_colocation_cluster": 70,
        "H_bacnet_placeholder": 68,
        # Paper's own host-of-interest metrics are FIRST-CLASS members of the
        # same set: pipeline counts them in n_metrics exactly like A-M. A LOW
        # host whose single metric is a paper metric is a valid upgrade target
        # (find one NEW passive indicator via active probe -> 2 metrics -> MEDIUM).
        "paper_many_open_ports": 60,
        "paper_as_education": 54,
    }
    if not ind_set:
        return 0
    return max(w.get(x, 0) for x in ind_set)


def main():
    residual_path = os.path.join(HERE, arg("--residual", "residual_paper17.json"))
    findings_path = os.path.join(HERE, arg("--findings", "deep_findings_paper17.csv"))
    registry_html_path = os.path.join(HERE, arg("--bacnet-registry", "bacnet_vendor_ids.html"))
    out_path = os.path.join(HERE, arg("--out", "active_probe_top100.csv"))
    top_n = int(arg("--top", "100"))
    none_only = arg("--none-only", "0") in ("1", "true", "yes")
    low_only = arg("--low-only", "0") in ("1", "true", "yes")
    # --tcp-only: keep only hosts carrying a TCP ICS protocol that can be actively
    # probe (S7/MODBUS/EIP/OPC_UA). Avoids UDP-only BACnet/FINS-placeholder hosts
    # that came back 100% dead in batch7 (verified network path OK).
    tcp_only = arg("--tcp-only", "0") in ("1", "true", "yes")
    PROBEABLE_TCP = {"S7", "MODBUS", "EIP", "OPC_UA"}
    # --exclude-cellular: drop cellular/eyeball/IoT-SIM carrier ASNs (see
    # CELLULAR_KEYWORDS). These are a confirmed false-positive trap; honeypots
    # concentrate on hosting/transit, so this focuses the probe budget.
    exclude_cellular = arg("--exclude-cellular", "0") in ("1", "true", "yes")

    if not os.path.exists(residual_path):
        raise SystemExit(f"Missing residual file: {residual_path}")
    if not os.path.exists(findings_path):
        raise SystemExit(f"Missing findings file: {findings_path}")

    findings = load_findings(findings_path)
    bacnet_unique = load_bacnet_unique_registry(registry_html_path)
    probe_map = probe_catalog()

    # IPs already probed in earlier batches -> skip so each batch is fresh.
    exclude = set()
    excl_path = arg("--exclude", "")
    if excl_path and os.path.exists(os.path.join(HERE, excl_path)):
        with open(os.path.join(HERE, excl_path), encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("ip"):
                    exclude.add(row["ip"].strip())
        print(f"excluding {len(exclude)} already-probed IPs")

    d = json.load(open(residual_path, encoding="utf-8"))
    recs = []

    for h in d["result"]["hits"]:
        r = h.get("host_v1", {}).get("resource", h)
        ip = r.get("ip")
        if not ip:
            continue
        if ip in exclude:
            continue

        # --exclude-cellular: skip cellular/eyeball/IoT-SIM carrier ASNs.
        if exclude_cellular and is_cellular((r.get("autonomous_system") or {}).get("name")):
            continue

        row = findings.get(ip)
        conf = row["confidence"] if row else "NONE"

        # Goal #2: find likely misses in residual -> keep LOW/NONE only.
        if conf in ("HIGH", "MEDIUM"):
            continue
        # --none-only: discover brand-new indicators on hosts with ZERO known
        # signal (avoid selection bias toward already-flagged LOW hosts).
        if none_only and conf != "NONE":
            continue
        # --low-only: hosts with exactly one host-of-interest metric (LOW). Goal:
        # find a SECOND independent indicator to upgrade them LOW->MEDIUM.
        if low_only and conf != "LOW":
            continue

        protocols = sorted({s.get("protocol") for s in r.get("services", []) if s.get("protocol")})
        ics_protos = [p for p in protocols if p in probe_map]
        # --tcp-only: require at least one actively-probeable TCP ICS protocol.
        if tcp_only and not (PROBEABLE_TCP & set(ics_protos)):
            continue
        proto_targets = defaultdict(set)
        for s in r.get("services", []):
            p = s.get("protocol")
            if p not in probe_map:
                continue
            port = s.get("port")
            tr = s.get("transport_protocol") or "tcp"
            if port is None:
                continue
            proto_targets[p].add(f"{port}/{str(tr).lower()}")

        reasons = []
        score = 0

        # Existing LOW signals. Paper metrics (paper_many_open_ports,
        # paper_as_education) and the A-M indicators are ONE unified
        # host-of-interest set -- the pipeline scores them identically. A LOW
        # host with a single paper metric is an equally valid upgrade candidate.
        if row:
            ind_set = {x for x in (row.get("new_indicators") or "").split(";") if x}
            paper_set = {x for x in re.split(r"[;|]", row.get("paper_metrics") or "") if x}
            full_set = ind_set | paper_set
            base = score_from_low_indicators(full_set)
            if base > 0:
                reasons.append("LOW_METRICS:" + "+".join(sorted(full_set)))
                score = max(score, base)

        # New strong candidate: BACnet exact-name unique registry mismatch.
        for s in r.get("services", []):
            b = s.get("bacnet")
            if not isinstance(b, dict):
                continue
            name = (b.get("vendor_name") or "").strip().lower()
            vid = b.get("vendor_id")
            if not name or vid is None or name not in bacnet_unique:
                continue
            exp = bacnet_unique[name]
            if int(vid) != int(exp):
                score = max(score, 95)
                reasons.append(f"NEW_STRONG:bacnet_vendor_mismatch({name}:{vid}!={exp})")
                break

        # Additional passive hints for prioritizing probe queue (not final indicators yet).
        for s in r.get("services", []):
            b = s.get("bacnet")
            if not isinstance(b, dict):
                continue
            model = str(b.get("model_name") or "").strip().lower()
            oname = str(b.get("object_name") or "").strip().lower()
            loc = str(b.get("location") or "").strip().lower()
            if model == "hikcentral professional" and oname == "hikcentralprofessional":
                score = max(score, 72)
                reasons.append("HINT:hikcentral_template")
            if oname == "ups agent" and loc == "usa":
                score = max(score, 58)
                reasons.append("HINT:ups_agent_template")

        # Very low-priority baseline for NONE rows to allow deterministic sorting when needed.
        if score == 0 and conf == "NONE":
            score = 10
            reasons.append("BASE:none_no_signal")

        probe_bundle = sorted({probe_map[p] for p in ics_protos})
        target_chunks = []
        for p in sorted(proto_targets):
            target_chunks.append(f"{p}:{','.join(sorted(proto_targets[p]))}")

        recs.append({
            "ip": ip,
            "confidence": conf,
            "score": score,
            "reasons": " | ".join(reasons),
            "protocols": ";".join(protocols),
            "ics_protocols": ";".join(ics_protos),
            "protocol_targets": " | ".join(target_chunks),
            "probe_bundle": ";".join(probe_bundle),
            "asn": (r.get("autonomous_system") or {}).get("asn") or "",
            "as_name": (r.get("autonomous_system") or {}).get("name") or "",
            "country": (r.get("location") or {}).get("country") or "",
        })

    # Rank: score desc, richer protocol surface first, deterministic by IP.
    recs.sort(key=lambda x: (-int(x["score"]), -len(x["ics_protocols"].split(";") if x["ics_protocols"] else []), x["ip"]))
    top = recs[:top_n]

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "ip", "confidence", "score", "reasons", "protocols", "ics_protocols",
                "protocol_targets", "probe_bundle", "asn", "as_name", "country",
            ],
        )
        w.writeheader()
        w.writerows(top)

    print(f"WROTE {len(top)} -> {out_path}")
    # quick summary
    by_score = defaultdict(int)
    by_conf = defaultdict(int)
    for r in top:
        by_score[r["score"]] += 1
        by_conf[r["confidence"]] += 1
    print("top confidence mix:", dict(sorted(by_conf.items())))
    print("top score buckets:", dict(sorted(by_score.items(), reverse=True)[:10]))


if __name__ == "__main__":
    main()
