#!/usr/bin/env python3
"""indicators.py - Two NEW passive indicators, over the RESIDUAL set.

The two discriminators described as future work in the progress report are
computed PASSIVELY from your pop_all.json (Censys Platform export):

  Indicator A: cross/intra-protocol vendor inconsistency (vendor conflict).
      Conflicting manufacturer identities on the same host (e.g. S7=Siemens but
      Modbus MEI vendor=Schneider). A genuine PLC carries a single vendor identity.

  Indicator B: templated/sequential/low-entropy device identifier (device-id
      template). ID fields such as the serial number / memory-card serial number /
      EIP serial number are high-entropy and vendor-formatted on real devices.
      Textbook patterns like 0x00000001, 0102030405, DEADBEEF are a fake/decoy
      signal.

The residual set = the hosts remaining after funnel.py steps 0-2 (those missed by
BOTH the Censys HONEYPOT label AND the paper filter). These two indicators target
that blind spot; findings are written to separate CSVs for manual review.

Usage:  py indicators.py [--file pop_all.json]
Output: indicator_A_vendor_conflict.csv, indicator_B_template_id.csv
"""
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from math import log2

from paper_original_port import classify_record, is_detected_honeypot

HERE = os.path.dirname(os.path.abspath(__file__))


def arg(name, default):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return default


_file = arg("--file", "pop_all.json")
PATH = os.path.join(HERE, _file)
OUT_A = os.path.join(HERE, "indicator_A_vendor_conflict.csv")
OUT_B = os.path.join(HERE, "indicator_B_template_id.csv")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def host_labels(services):
    out = set()
    for s in services:
        labs = s.get("labels")
        if isinstance(labs, list):
            for L in labs:
                v = L.get("value") if isinstance(L, dict) else L
                if v:
                    out.add(str(v).upper())
    return out


def protocols_of(r):
    return sorted({s.get("protocol", "") for s in r.get("services", []) if s.get("protocol")})


# ---------------------------------------------------------------------------
# INDICATOR A: vendor inconsistency
# ---------------------------------------------------------------------------
# Reduces manufacturer strings to a canonical brand. Only UNAMBIGUOUS brands;
# anything unclear -> None (to keep false positives low). Because the results are
# manually reviewed, the evidence (source=brand) is written to the CSV.
BRAND_KW = [
    ("SIEMENS", ("SIEMENS", "SIMATIC")),
    ("SCHNEIDER", ("SCHNEIDER", "MODICON", "TELEMECANIQUE", "TSX", "BMX")),
    ("ROCKWELL", ("ROCKWELL", "ALLEN-BRADLEY", "ALLEN BRADLEY", "ALLEN_BRADLEY")),
    ("TRIDIUM", ("TRIDIUM", "NIAGARA")),
    ("WAGO", ("WAGO",)),
    ("BECKHOFF", ("BECKHOFF", "TWINCAT")),
    ("ABB", ("ABB",)),
    ("MITSUBISHI", ("MITSUBISHI", "MELSEC")),
    ("OMRON", ("OMRON",)),
    ("PHOENIX", ("PHOENIX CONTACT", "PHOENIX_CONTACT")),
    ("MOXA", ("MOXA",)),
    ("HMS", ("HMS", "ANYBUS")),
    ("DELTA", ("DELTA ELECTRONICS",)),
    ("GE", ("GENERAL ELECTRIC", "GE FANUC", "GE INTELLIGENT")),
    ("HONEYWELL", ("HONEYWELL",)),
    ("EMERSON", ("EMERSON",)),
    ("YOKOGAWA", ("YOKOGAWA",)),
    ("BOSCH", ("BOSCH", "REXROTH")),
    ("HITACHI", ("HITACHI",)),
    ("PANASONIC", ("PANASONIC",)),
    ("CODESYS", ("CODESYS", "3S-SMART")),
    ("UNITRONICS", ("UNITRONICS",)),
]


def brand_from_string(s):
    if not s:
        return None
    u = s.upper()
    for brand, kws in BRAND_KW:
        for kw in kws:
            if kw in u:
                return brand
    return None


def vendor_signals(r):
    """List of (brand, source-description) evidence carried by the host.

    Only identity-bearing fields: protocol implication (S7=Siemens proprietary),
    order-code prefix, and explicit vendor_name fields.
    """
    sigs = []  # (brand, source)
    for s in r.get("services", []):
        p = s.get("protocol")
        # --- S7: Siemens proprietary protocol ---
        if "s7" in s:
            s7 = s["s7"] or {}
            mid = (s7.get("module_id") or "").strip()
            cop = (s7.get("copyright") or "")
            b = None
            if mid[:4].upper() in ("6ES7", "6ED1", "6AG1", "6GK7"):
                b = "SIEMENS"
                sigs.append((b, f"S7.order_code={mid}"))
            elif brand_from_string(cop):
                b = brand_from_string(cop)
                sigs.append((b, f"S7.copyright={cop.strip()[:40]}"))
            else:
                # the S7comm protocol on its own implies Siemens
                sigs.append(("SIEMENS", "S7.protocol"))
        # --- Modbus MEI vendor ---
        if "modbus" in s:
            o = ((s["modbus"] or {}).get("mei_response") or {}).get("objects") or {}
            for fld in ("vendor", "product_name", "model_name", "user_application_name"):
                b = brand_from_string(o.get(fld))
                if b:
                    sigs.append((b, f"MODBUS.{fld}={str(o.get(fld)).strip()[:40]}"))
                    break
        # --- EtherNet/IP identity ---
        if "eip" in s:
            idn = (s["eip"] or {}).get("identity") or {}
            b = brand_from_string(idn.get("vendor_name")) or brand_from_string(idn.get("product_name"))
            if b:
                sigs.append((b, f"EIP.vendor={str(idn.get('vendor_name')).strip()[:40]}"))
        # --- BACnet vendor ---
        if "bacnet" in s:
            bac = s["bacnet"] or {}
            b = brand_from_string(bac.get("vendor_name")) or brand_from_string(bac.get("model_name"))
            if b:
                sigs.append((b, f"BACNET.vendor={str(bac.get('vendor_name')).strip()[:40]}"))
        # --- FOX = Niagara/Tridium ---
        if p == "FOX" or "fox" in s:
            sigs.append(("TRIDIUM", "FOX.protocol"))
    return sigs


# Maps an evidence source to a "strength kind":
#   native : the device's OWN control-plane identity (S7/Modbus/EIP) - a strong tell
#   bacnet : BACnet vendor - can be PROXIED by a supervisor (semi-strong)
#   supervisor : FOX/Niagara - legitimately aggregates other manufacturers (weak)
def _source_kind(src):
    head = src.split(".", 1)[0].upper()
    if head in ("S7", "MODBUS", "EIP"):
        return "native"
    if head == "BACNET":
        return "bacnet"
    if head == "FOX":
        return "supervisor"
    return "other"


def indicator_A(r):
    """If >=2 conflicting brands: (brands, evidence, strength, strength_reason).

    strength (only STRONG/MEDIUM; the weak GATEWAY class was REMOVED):
      STRONG  : >=2 brands each from a NATIVE control protocol (S7/Modbus/EIP).
                A single physical PLC cannot speak two different manufacturers'
                native stacks.
      MEDIUM  : single native brand; the others conflict via BACnet vendor.
    A FOX(supervisor)+BACnet conflict alone (a Niagara proxy can be LEGITIMATE) is
    IGNORED (returns None) -- it used to be the weak GATEWAY class.
    """
    sigs = vendor_signals(r)
    brands = {b for b, _ in sigs}
    if len(brands) < 2:
        return None

    # each brand -> supporting source kinds
    brand_kinds = defaultdict(set)
    for b, src in sigs:
        brand_kinds[b].add(_source_kind(src))
    native_brands = {b for b, ks in brand_kinds.items() if "native" in ks}
    has_supervisor = any("supervisor" in ks for ks in brand_kinds.values())

    if len(native_brands) >= 2:
        strength = "STRONG"
        why = f"two+ native control-protocol conflict: {sorted(native_brands)}"
    elif has_supervisor and all(
            brand_kinds[b] <= {"supervisor", "bacnet"} for b in brands):
        # FOX supervisor + BACnet: could be a legitimate proxy/gateway => weak, IGNORE
        return None
    else:
        strength = "MEDIUM"
        why = "single native brand; the others come from bacnet/supervisor sources"

    ev = []
    seen = set()
    for b, src in sigs:
        if b not in seen:
            ev.append(f"{b}<={src}")
            seen.add(b)
    return sorted(brands), ev, strength, why


# ---------------------------------------------------------------------------
# INDICATOR B: templated / sequential / low-entropy device identifier
# ---------------------------------------------------------------------------
PLACEHOLDERS = {
    "DEADBEEF", "CAFEBABE", "BAADF00D", "0BADF00D", "DEADC0DE", "FEEDFACE",
    "8BADF00D", "DEADBABE", "FACEFEED", "CAFED00D", "BADDCAFE",
    "12345678", "01234567", "87654321", "76543210", "1234567890",
    "00000000", "11111111", "FFFFFFFF", "AAAAAAAA", "55555555",
    "01020304", "0102030405", "0011223344", "AABBCCDD", "DEADBEEFDEADBEEF",
}


def shannon(s):
    if not s:
        return 0.0
    c = Counter(s)
    L = len(s)
    return -sum((n / L) * log2(n / L) for n in c.values())


def _hexval(ch):
    ch = ch.lower()
    if ch.isdigit():
        return ord(ch) - 48
    if "a" <= ch <= "f":
        return 10 + ord(ch) - 97
    return None


def max_consecutive_run(core):
    """Longest consecutive +1/-1 nibble run (e.g. 123456 -> 6)."""
    best = cur = 1
    d = 0
    for i in range(1, len(core)):
        a, b = _hexval(core[i - 1]), _hexval(core[i])
        if a is None or b is None:
            cur = 1
            d = 0
            continue
        step = b - a
        if step in (1, -1) and (d == 0 or d == step):
            cur += 1
            d = step
            best = max(best, cur)
        else:
            cur = 2 if step in (1, -1) else 1
            d = step if step in (1, -1) else 0
    return best


def byte_pair_sequential(core):
    """Whether 2-char hex byte groups such as 0102030405 form an arithmetic
    sequence."""
    if len(core) < 6 or len(core) % 2:
        return False
    try:
        bs = [int(core[i:i + 2], 16) for i in range(0, len(core), 2)]
    except ValueError:
        return False
    if len(bs) < 3:
        return False
    diffs = {bs[i + 1] - bs[i] for i in range(len(bs) - 1)}
    return diffs == {1} or diffs == {-1}


def score_identifier(raw):
    """List of suspicious-pattern reasons for an ID string (empty = clean)."""
    if raw is None:
        return []
    s = str(raw).strip()
    core = "".join(ch for ch in s if ch.isalnum())
    if len(core) < 4:
        return []
    reasons = []
    up = core.upper()
    if up in PLACEHOLDERS:
        reasons.append(f"placeholder_token({up})")
    else:
        for tok in PLACEHOLDERS:
            if len(tok) >= 6 and tok in up:
                reasons.append(f"contains_placeholder({tok})")
                break
    if len(set(up)) == 1:
        reasons.append(f"all_same_char({up[0]})")
    run = max_consecutive_run(core)
    if run >= max(6, int(0.8 * len(core))):
        reasons.append(f"sequential_run({run})")
    if byte_pair_sequential(core):
        reasons.append("byte_pair_sequence")
    ent = shannon(core)
    if len(core) >= 8 and ent < 1.0:
        reasons.append(f"low_entropy({ent:.2f}b/char)")
    return reasons


def identifier_candidates(r):
    """(source_field, raw_value) ID candidates from a host. Only SERIAL/ID fields;
    legitimately structured fields such as order-code / model / product-name are
    EXCLUDED."""
    out = []
    for s in r.get("services", []):
        if "s7" in s:
            s7 = s["s7"] or {}
            for fld in ("serial_number", "memory_serial_number", "plant_id",
                        "reserved_for_os"):
                v = s7.get(fld)
                if v not in (None, ""):
                    out.append((f"s7.{fld}", v))
        if "eip" in s:
            idn = (s["eip"] or {}).get("identity") or {}
            v = idn.get("serial_number")
            if isinstance(v, int):
                # EIP serial number is an integer -> try both 8-hex and decimal
                out.append(("eip.serial_number", f"{v:08X}"))
        if "bacnet" in s:
            bac = s["bacnet"] or {}
            v = bac.get("instance_number")
            # only watch suspiciously-round/low instance numbers
            if isinstance(v, int) and v in (0, 1, 1234, 12345, 123456, 1111, 9999):
                out.append(("bacnet.instance_number", str(v)))
    return out


def indicator_B(r):
    """List of (source, raw, reasons, strength) (empty = indicator did not fire).

    strength (only STRONG; the weak class was REMOVED):
      STRONG : (a) a placeholder token always; OR (b) a genuine SERIAL-NUMBER field
               (s7.serial_number / s7.memory_serial_number / eip.serial_number).
               A manufacturer serial number is by definition high-entropy; being
               sequential/low-entropy is nearly impossible => a strong decoy signal.
    Fields other than serial/placeholder (bacnet.instance_number / s7.plant_id /
    reserved_for_os) can also appear in legitimate deployments => weak, IGNORED.
    """
    STRONG_FIELDS = {"s7.serial_number", "s7.memory_serial_number", "eip.serial_number"}
    hits = []
    for src, raw in identifier_candidates(r):
        rs = score_identifier(raw)
        if rs:
            is_placeholder = any(x.startswith(("placeholder_token", "contains_placeholder"))
                                 for x in rs)
            if is_placeholder or src in STRONG_FIELDS:
                hits.append((src, raw, rs, "STRONG"))
            # otherwise weak => IGNORE (not appended to hits)
    return hits


# ---------------------------------------------------------------------------
def main():
    if not os.path.exists(PATH):
        sys.exit(f"ERROR: {PATH} missing.")
    print(f"Loading: {PATH}")
    with open(PATH, encoding="utf-8") as f:
        d = json.load(f)

    raw = []
    for h in d["result"]["hits"]:
        rr = h.get("host_v1", {}).get("resource") if "host_v1" in h else h
        if rr:
            raw.append(rr)
    N0 = len(raw)

    # --- residual identical to funnel steps 0-2 ---
    residual = []
    n_no_ics = n_hp = n_paper = 0
    for r in raw:
        labs = host_labels(r.get("services", []))
        if "ICS" not in labs:
            n_no_ics += 1
            continue
        if "HONEYPOT" in labs:
            n_hp += 1
            continue
        if is_detected_honeypot(classify_record(r)[0]):
            n_paper += 1
            continue
        residual.append(r)
    Nr = len(residual)

    print("=" * 72)
    print(f"Raw population         : {N0}")
    print(f"  - dropped (not ICS)  : {n_no_ics}")
    print(f"  - dropped (HONEYPOT) : {n_hp}")
    print(f"  - dropped (paper flt): {n_paper}")
    print(f"RESIDUAL SET           : {Nr}")
    print("=" * 72)

    # --- Indicator A ---
    rows_A = []
    for r in residual:
        res = indicator_A(r)
        if res:
            brands, ev, strength, why = res
            asn = (r.get("autonomous_system") or {}).get("asn")
            asname = (r.get("autonomous_system") or {}).get("name")
            cc = (r.get("location") or {}).get("country_code") or (r.get("location") or {}).get("country")
            rows_A.append([
                r.get("ip"), strength, ";".join(brands), " | ".join(ev), why,
                ",".join(protocols_of(r)), asn, asname, cc,
            ])
    # STRONG > MEDIUM ordering (for easier manual review)
    _order = {"STRONG": 0, "MEDIUM": 1}
    rows_A.sort(key=lambda row: (_order.get(row[1], 9), row[2]))

    # --- Indicator B ---
    rows_B = []
    for r in residual:
        hits = indicator_B(r)
        if hits:
            asn = (r.get("autonomous_system") or {}).get("asn")
            asname = (r.get("autonomous_system") or {}).get("name")
            cc = (r.get("location") or {}).get("country_code") or (r.get("location") or {}).get("country")
            for src, val, rs, strength in hits:
                rows_B.append([
                    r.get("ip"), strength, src, str(val), ";".join(rs),
                    ",".join(protocols_of(r)), asn, asname, cc,
                ])
    rows_B.sort(key=lambda row: (0 if row[1] == "STRONG" else 1, row[2]))

    with open(OUT_A, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "strength", "brands", "evidence", "strength_reason",
                    "protocols", "asn", "as_name", "country"])
        w.writerows(rows_A)

    with open(OUT_B, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "strength", "id_field", "raw_value", "reasons",
                    "protocols", "asn", "as_name", "country"])
        w.writerows(rows_B)

    ips_A = {row[0] for row in rows_A}
    ips_B = {row[0] for row in rows_B}
    overlap = ips_A & ips_B

    strong_ct = Counter(row[1] for row in rows_A)
    print("\nRESULTS (over the residual):")
    print(f"  Indicator A (vendor conflict): {len(ips_A)} hosts -> {os.path.basename(OUT_A)}")
    print(f"      STRONG={strong_ct['STRONG']}  MEDIUM={strong_ct['MEDIUM']}")
    print(f"  Indicator B (template/id)    : {len(ips_B)} hosts, {len(rows_B)} ID records"
          f"  -> {os.path.basename(OUT_B)}  (all STRONG)")
    print(f"  Hosts in both                : {len(overlap)}")

    # Indicator A: strength x brand-pair distribution (summary for manual review)
    pair_ct = Counter()
    for row in rows_A:
        pair_ct[(row[1], row[2])] += 1
    if pair_ct:
        print("\n  A: strength / brand-conflict distribution:")
        for (strg, pair), c in sorted(pair_ct.items(), key=lambda kv: (_order.get(kv[0][0], 9), -kv[1])):
            print(f"    {c:4d}  [{strg:7s}] {pair}")

    # Indicator B: reason distribution
    reason_ct = Counter()
    for row in rows_B:
        for rs in row[4].split(";"):
            reason_ct[rs.split("(")[0]] += 1
    if reason_ct:
        print("\n  B: reason distribution:")
        for rs, c in reason_ct.most_common():
            print(f"    {c:4d}  {rs}")


if __name__ == "__main__":
    main()
