#!/usr/bin/env python3
"""Correlate ACTIVE probe ground-truth with PASSIVE Censys fields.

Goal (user's original strategy): use active probing to DISCOVER passive
indicators we missed. For each probed host we now know its live reality
(REAL_DEVICE / DEAD / SUSPECT). We pull the SAME host's full passive Censys
record from the residual dump and look for passive fields that separate the
classes -> candidate new passive indicators.

Inputs
- batch1_results.json, batch2_results.json (active probe outcomes)
- residual_paper17.json (passive Censys records, 110k hosts)

Method
1. Classify each probed host from active evidence:
   - REAL_DEVICE: BACnet I-Am with plausible same-family vendor OR Modbus MEI
     returned real vendor/product (Schneider/Phoenix/etc).
   - SUSPECT: cross-vendor mismatch (name vs id different brands) OR injected
     payload in identity fields OR reserved vendor id live.
   - DEAD: no protocol response at all (all timeouts/empty) -> inconclusive.
2. Join to passive record by IP; collect passive BACnet/Modbus/service fields.
3. Contrast field-value frequency REAL vs SUSPECT to surface discriminators.
"""

import json
import os
import re
import collections

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    return json.load(open(os.path.join(HERE, name), encoding="utf-8"))


# ---- 1. classify from active evidence ----

# same-family = shared leading brand token (siemens, etc.)
def brand_token(s):
    s = re.sub(r"[^a-z0-9 ]", " ", (s or "").lower())
    toks = [t for t in s.split() if t not in
            ("inc", "incorporated", "ag", "co", "kg", "gmbh", "ltd", "llc",
             "corp", "company", "electric", "industry", "industries",
             "schweiz", "the", "and")]
    return toks[0] if toks else ""


def classify(rec):
    ip = rec["ip"]
    b = rec["probes"].get("BACNET", {})
    m = rec["probes"].get("MODBUS", {})
    ia = b.get("i_am", {}) if b else {}
    props = b.get("properties", {}) if b else {}

    # injected payload in any identity field => SUSPECT
    blob = " ".join(str(v) for v in props.values())
    if re.search(r"<script|alert\(|onerror=|;//|\bunion\b", blob, re.I):
        return "SUSPECT", "injected_payload_in_identity"

    if ia.get("device_instance") is not None:
        # live BACnet; compare reported vendor_name brand vs registry via probe reason
        vn = props.get("vendor_name", "")
        # reserved-id live device
        if ia.get("vendor_id") in (555, 666, 777, 888, 911, 999, 1111):
            return "SUSPECT", f"reserved_vendor_id_live({ia.get('vendor_id')})"
        return "REAL_DEVICE", f"bacnet_live vn={vn!r} model={props.get('model_name')!r}"

    # live modbus device identification with real vendor
    di = (m.get("device_identification", {}) if m else {})
    for code in ("code1", "code2"):
        objs = di.get(code, {}).get("objects")
        if objs:
            return "REAL_DEVICE", f"modbus_devid {objs.get('vendor_name')}/{objs.get('product_code')}"

    # modbus alive (valid exception) but no id -> weakly real (speaks protocol)
    for code in ("code1", "code2"):
        err = str(di.get(code, {}).get("error", ""))
        if err.startswith("exception"):
            return "MODBUS_ALIVE_NOID", "modbus_exception_only"

    return "DEAD", "no_response"


def main():
    active = load("batch1_results.json") + load("batch2_results.json")
    cls = {}
    for rec in active:
        c, why = classify(rec)
        cls[rec["ip"]] = (c, why, rec)

    counts = collections.Counter(v[0] for v in cls.values())
    print("=== active-truth classes ===")
    for k, n in counts.most_common():
        print(f"  {k}: {n}")

    # ---- 2. join to passive residual ----
    wanted = set(cls)
    passive = {}
    res = load("residual_paper17.json")
    hits = res.get("result", {}).get("hits", res if isinstance(res, list) else [])
    for h in hits:
        r = h.get("host_v1", {}).get("resource", h)
        ip = r.get("ip") or h.get("ip")
        if ip in wanted:
            passive[ip] = r
    print(f"\njoined passive records: {len(passive)}/{len(wanted)}")

    # ---- 3. collect passive fields per class ----
    def passive_bacnet(r):
        for s in r.get("services", []):
            b = s.get("bacnet")
            if isinstance(b, dict):
                return b
        return {}

    def passive_modbus(r):
        for s in r.get("services", []):
            md = s.get("modbus")
            if isinstance(md, dict):
                return md
        return {}

    # gather field-value sets per class for BACnet identity fields
    fields = ["object_name", "vendor_name", "model_name", "description",
              "location", "firmware_revision", "application_software_version"]
    byclass = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    portcount = collections.defaultdict(list)
    svc_names = collections.defaultdict(collections.Counter)

    for ip, (c, why, rec) in cls.items():
        r = passive.get(ip)
        if not r:
            continue
        b = passive_bacnet(r)
        for f in fields:
            val = b.get(f)
            if val not in (None, ""):
                byclass[c][f][str(val)] += 1
        # generic host-level passive signals
        svcs = r.get("services", [])
        portcount[c].append(len(svcs))
        for s in svcs:
            svc_names[c][s.get("protocol") or s.get("service_name") or "?"] += 1

    print("\n=== passive service count (open services) per class ===")
    for c, lst in portcount.items():
        if lst:
            print(f"  {c}: n={len(lst)} avg_services={sum(lst)/len(lst):.1f} "
                  f"min={min(lst)} max={max(lst)}")

    print("\n=== passive protocol mix per class ===")
    for c, cnt in svc_names.items():
        print(f"  {c}: {dict(cnt.most_common(6))}")

    print("\n=== BACnet passive identity fields: REAL vs SUSPECT discriminators ===")
    for f in fields:
        real = byclass["REAL_DEVICE"][f]
        susp = byclass["SUSPECT"][f]
        if not real and not susp:
            continue
        print(f"\n-- {f} --")
        if susp:
            print("  SUSPECT:", dict(susp.most_common(6)))
        if real:
            print("  REAL   :", dict(real.most_common(6)))

    # dump full join for manual review
    out = []
    for ip, (c, why, rec) in cls.items():
        r = passive.get(ip, {})
        out.append({"ip": ip, "active_class": c, "active_why": why,
                    "passive_bacnet": passive_bacnet(r),
                    "passive_modbus_vendor": passive_modbus(r).get("mei_response", {})
                    if passive_modbus(r) else {},
                    "passive_service_count": len(r.get("services", []))})
    json.dump(out, open(os.path.join(HERE, "active_passive_join.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\nWROTE active_passive_join.json ({len(out)} hosts)")


if __name__ == "__main__":
    main()
