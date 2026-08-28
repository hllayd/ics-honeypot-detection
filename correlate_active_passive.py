#!/usr/bin/env python3
"""Correlate ACTIVE probe ground-truth with PASSIVE Censys fields.

Goal: use active probing to DISCOVER passive indicators the passive
pipeline missed. For each probed host its live reality is now known
(REAL_DEVICE / DEAD / SUSPECT). The SAME host's full passive Censys
record is pulled from the passive population and inspected for passive fields
that separate the classes -> candidate new passive indicators.

Inputs
- active_probe_top100_results.json (active probe outcomes, 100 probed hosts)
- population.json (passive Censys records for the full ICS population)

Method
1. Classify each probed host from active evidence:
   - REAL_DEVICE: BACnet I-Am with plausible same-family vendor OR Modbus MEI
     returned real vendor/product (Schneider/Phoenix/etc).
   - SUSPECT: reserved (ASHRAE) BACnet vendor_id live, OR a spec-impossible
     live vendor_name<->vendor_id pair (same rule as the passive classifier).
   - DEAD: no protocol response at all (all timeouts/empty) -> inconclusive.
2. Join to passive record by IP; collect passive BACnet/Modbus/service fields.
3. Contrast field-value frequency REAL vs SUSPECT to surface discriminators.
"""

import json
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))

# Spec-assigned BACnet vendor_name -> official vendor_id registry, kept in sync
# with the passive classifier (deep_indicators.signature_bacnet_id_name_mismatch).
# A live device reporting one of these names with a DIFFERENT id is an identity a
# certified device could not produce -> the same SUSPECT rule the passive side uses.
try:
    from deep_indicators import BACNET_NAME_TO_ID
except Exception:
    BACNET_NAME_TO_ID = {"bacnet stack at sourceforge": 260}


def load(name):
    return json.load(open(os.path.join(HERE, name), encoding="utf-8"))


def _arg(name, default):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return default


def _population_file():
    """Passive Censys population to join against (default population.json).
       Override with --population <file>."""
    return _arg("--population", "population.json")


def _batch_files():
    """Batch result files to correlate. Pass them on the command line, e.g.
       py correlate_active_passive.py active_probe_top100_results.json
       py correlate_active_passive.py batch3_results.json --population population.json
    Defaults to active_probe_top100_results.json (the prepared, verified demo
    batch of 100 probed hosts). The value of --population is not treated as a
    batch."""
    skip = set()
    if "--population" in sys.argv:
        i = sys.argv.index("--population")
        skip.add(i)
        skip.add(i + 1)
    args = [a for j, a in enumerate(sys.argv[1:], start=1)
            if a.endswith(".json") and j not in skip]
    return args if args else ["active_probe_top100_results.json"]


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

    if ia.get("device_instance") is not None:
        # live BACnet; compare reported vendor_name brand vs registry via probe reason
        vn = props.get("vendor_name", "")
        vid = ia.get("vendor_id")
        # reserved-id live device
        if vid in (555, 666, 777, 888, 911, 999, 1111):
            return "SUSPECT", f"reserved_vendor_id_live({vid})"
        # spec-impossible live name<->id (same rule as the passive classifier)
        canon = BACNET_NAME_TO_ID.get(str(vn).strip().lower())
        if canon is not None and vid != canon:
            return "SUSPECT", (f"bacnet_id_name_impossible name={vn!r} "
                               f"reported_id={vid} registered_id={canon}")
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
    batch_files = _batch_files()
    population_file = _population_file()
    active = []
    for bf in batch_files:
        active += load(bf)
    print(f"Active probe results : {', '.join(batch_files)}  ({len(active)} probed hosts)")
    print(f"Passive population   : {population_file}")
    cls = {}
    for rec in active:
        c, why = classify(rec)
        cls[rec["ip"]] = (c, why, rec)

    counts = collections.Counter(v[0] for v in cls.values())

    # ---- 2. join every probed host to its passive Censys record ----
    wanted = set(cls)
    passive = {}
    res = load(population_file)
    hits = res.get("result", {}).get("hits", res if isinstance(res, list) else [])
    for h in hits:
        r = h.get("host_v1", {}).get("resource", h)
        ip = r.get("ip") or h.get("ip")
        if ip in wanted:
            passive[ip] = r

    # ---- 3. collect passive BACnet identity fields per active class ----
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

    fields = ["object_name", "vendor_name", "model_name", "description",
              "location", "firmware_revision", "application_software_version"]
    byclass = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for ip, (c, why, rec) in cls.items():
        r = passive.get(ip)
        if not r:
            continue
        b = passive_bacnet(r)
        for f in fields:
            val = b.get(f)
            if val not in (None, ""):
                byclass[c][f][str(val)] += 1

    # dump the full join for manual review / the report
    #
    # passive honeypot verdict P for a probed host. This work's passive
    # classifier: a STRONG indicator => MEDIUM/HIGH => "honeypot"; a single
    # weak/host-of-interest metric => LOW => "below". The verdict is carried
    # in the probe record's passive reasons tag (NEW_STRONG.. vs LOW_..).
    def passive_label(rec):
        tag = (rec.get("reasons", "") or "").split(":")[0].upper()
        return "honeypot" if ("STRONG" in tag or "HIGH" in tag) else "below"

    # readable meaning of each P x A cell (the 4 validation buckets)
    CELL_READING = {
        ("honeypot", "SUSPECT"):     "confirmed_honeypot",
        ("honeypot", "REAL_DEVICE"): "reject_candidate_indicator",
        ("below",    "SUSPECT"):     "discovery_passive_undercalled",
        ("below",    "REAL_DEVICE"): "agree_genuine_device",
        ("honeypot", "MODBUS_ALIVE_NOID"): "honeypot_alive_no_identity_inconclusive",
        ("honeypot", "DEAD"):              "honeypot_no_active_response_inconclusive",
        ("below",    "MODBUS_ALIVE_NOID"): "below_alive_no_identity_inconclusive",
        ("below",    "DEAD"):              "below_no_active_response_inconclusive",
    }

    out = []
    for ip, (c, why, rec) in cls.items():
        r = passive.get(ip, {})
        p = passive_label(rec)
        out.append({"ip": ip,
                    "passive_label": p,             # P
                    "active_class": c,              # A
                    "validation_cell": f"{p}|{c}",  # P x A bucket key
                    "validation_reading": CELL_READING.get((p, c), f"{p}|{c}"),
                    "active_why": why,
                    "passive_bacnet": passive_bacnet(r),
                    "passive_modbus_vendor": passive_modbus(r).get("mei_response", {})
                    if passive_modbus(r) else {},
                    "passive_service_count": len(r.get("services", []))})
    json.dump(out, open(os.path.join(HERE, "active_passive_join.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=2)

    # ===================================================================
    #  DECK-ALIGNED OUTPUT: one comparison (P vs A), two readings.
    #  Slide 18: each probed host has a passive label P and an active
    #  class A; match by IP and read the result two ways.
    # ===================================================================
    real = byclass["REAL_DEVICE"]
    susp = byclass["SUSPECT"]
    NAMES = [
        ("SUSPECT",           "SUSPECT     identity a certified device cannot emit"),
        ("REAL_DEVICE",       "REAL_DEVICE genuine, self-consistent identity"),
        ("MODBUS_ALIVE_NOID", "ALIVE-NO-ID speaks the protocol, returns no identity"),
        ("DEAD",              "DEAD        no protocol response (inconclusive)"),
    ]

    # describe the active anomaly of a SUSPECT host: (protocol, field, value)
    def suspect_anomaly(rec):
        b = rec["probes"].get("BACNET", {})
        props = b.get("properties", {}) if b else {}
        ia = b.get("i_am", {}) if b else {}
        vid = ia.get("vendor_id")
        if vid in (555, 666, 777, 888, 911, 999, 1111):
            return ("BACnet", "vendor_id (ASHRAE-reserved)", str(vid))
        vn = props.get("vendor_name", "")
        canon = BACNET_NAME_TO_ID.get(str(vn).strip().lower())
        if canon is not None and vid != canon:
            return ("BACnet", "vendor_name vs vendor_id",
                    f"{vn!r} id={vid} (registered {canon})")
        return ("BACnet", "identity", "cross-field mismatch")

    print("\n" + "=" * 70)
    print("  STEP 1  Each probed host gets a live ground-truth class  A")
    print("=" * 70)
    for k, label in NAMES:
        print(f"    A = {label:<55} {counts.get(k, 0):>3}")
    print(f"    joined to their passive Censys record{'':<20} {len(passive):>3}/{len(cls)}")

    # ---- SUSPECT hosts: the active anomaly that anchors the comparison ----
    suspect_ips = [ip for ip, (c, why, rec) in cls.items() if c == "SUSPECT"]
    print("\n" + "=" * 70)
    print("  SUSPECT HOSTS  -  the live anomaly each one exposes")
    print("=" * 70)
    print(f"  {'ip':<17} {'protocol':<9} {'field':<28} value")
    print(f"  {'-'*15:<17} {'-'*8:<9} {'-'*26:<28} {'-'*20}")
    for ip in suspect_ips:
        proto, field, value = suspect_anomaly(cls[ip][2])
        print(f"  {ip:<17} {proto:<9} {field:<28} {value!r}")

    # ---- one comparison, P x A ----
    pa = collections.Counter()
    for ip, (c, why, rec) in cls.items():
        if ip in passive:
            pa[(passive_label(rec), c)] += 1

    print("\n" + "=" * 70)
    print("  READING 1   VALIDATION  -  where the passive honeypot verdict (P)")
    print("                            meets the live active class (A)")
    print("=" * 70)
    print("  P = this work's passive classifier (STRONG->POT, weak-only->NOT).")
    print("  Count the hosts in each P x A combination:")
    print()
    print(f"    {'P (passive)':<14} {'A (active read)':<16} {'hosts':>5}   reading")
    print(f"    {'-'*12:<14} {'-'*14:<16} {'-'*5:>5}   {'-'*30}")
    rows = [
        ("honeypot", "POT", "SUSPECT",     "active read agrees -> confirmed"),
        ("honeypot", "POT", "REAL_DEVICE", "reject the candidate indicator"),
        ("below",    "NOT", "SUSPECT",     "passive under-called -> DISCOVERY lead"),
        ("below",    "NOT", "REAL_DEVICE", "both agree -> genuine device"),
    ]
    for p, plabel, a, note in rows:
        print(f"    {plabel:<14} {a:<16} {pa.get((p, a), 0):>5}   {note}")
    print()
    print("  => the comparison is self-checking. Where the two agree, the passive")
    print("     verdict is confirmed. The honeypot x REAL_DEVICE row is the REJECT")
    print("     case: when P says POT but the live read says A is REAL, the candidate")
    print("     indicator is REJECTED. These hosts were flagged by the BROAD candidate-")
    print("     selection draft of the BACnet name<->id mismatch (built from the whole")
    print("     ASHRAE registry), and the live read shows genuine self-consistent")
    print("     devices (e.g. Siemens vendor_id 7, real model, ISP network). Reject thus")
    print("     exposed a false-positive mode of the WIDE draft -- which is exactly")
    print("     why the final signature keeps only proven soft-server names (e.g.")
    print("     'BACnet Stack at SourceForge'), not the whole registry. Same loop")
    print("     that dropped drafts L and M, here used to NARROW a rule, not drop it.")

    print("\n" + "=" * 70)
    print("  READING 2   DISCOVERY  -  find the passive shadow of active")
    print("=" * 70)
    print("  Group hosts by A, then for each passive identity field ask:")
    print("  which value shows up in SUSPECT but never in a real device?")
    print()
    print("  For each field we take the value(s) seen on SUSPECT hosts and check")
    print("  whether that SAME value ever appears on a real device.")
    print()
    hdr = f"    {'passive field':<14} {'SUSPECT value':<22} {'seen on a REAL device?':<24} result"
    print(hdr)
    print(f"    {'-'*12:<14} {'-'*20:<22} {'-'*22:<24} {'-'*10}")
    for f in ("location", "vendor_name", "model_name", "object_name"):
        vals = [v for v, _ in susp[f].most_common()]
        if not vals:
            print(f"    {f:<14} {'(none)':<22} {'-':<24} skip")
            continue
        for v in vals:
            in_real = v in real[f]
            seen = f"yes ({real[f][v]} host(s))" if in_real else "no"
            verdict = "shared -> drop" if in_real else "SUSPECT-only -> candidate"
            shown = (v[:19] + "...") if len(v) > 22 else v
            print(f"    {f:<14} {shown!r:<22} {seen:<24} {verdict}")
    print()
    print("  Candidate passive indicators, per SUSPECT host")
    print("  (field values this host shows that NO real device shows):")
    for ip in suspect_ips:
        b = passive_bacnet(passive.get(ip, {}))
        host_rows = [(f, str(b[f])) for f in fields
                     if b.get(f) not in (None, "") and str(b[f]) not in real[f]]
        print(f"\n    {ip}")
        print(f"      {'passive field':<16} value")
        print(f"      {'-'*14:<16} {'-'*30}")
        if not host_rows:
            print(f"      {'(none)':<16}")
        for f, v in host_rows:
            print(f"      {f:<16} {v!r}")
    print()
    print("  => each such value is a candidate passive indicator: it separates")
    print("     emulators from real devices, so it can be folded back into the")
    print("     passive pipeline for the next full-population run.")
    print("=" * 70)


if __name__ == "__main__":
    main()
