#!/usr/bin/env python3
"""deep_indicators.py - The UNIFIED passive ICS honeypot classifier.

This is the single detection pipeline: it scores EVERY ICS host, in one pass over
the full population, against ONE combined pool of signatures and host-of-interest
indicators. The adopted signals of Mladenov et al. (their three signatures --
conpot/snap7 S7comm defaults and the GasPot ATG banner -- and two network metrics)
are folded into the SAME pool at their matching tiers (see
paper_signals()), together with this work's new signatures and indicators. The
model is monotone: because the adopted signals are retained, no host the paper
method alone would detect can ever drop below its grade; the new signals can only
hold a host in place or raise it.

There is NO residual pre-filtering step (that was an earlier approach). The paper
and Censys detections are not removed up front; instead they are retained as a
monotone floor and reported as part of the combined total.

Input : population.json  (the full Censys pull; every ICS host is scored)
        ipinfo_map.json  (per-IP AS/company category from enrich_ipinfo.py;
                          supplies the paper-faithful network_type metric)
Output: deep_findings.csv (per-host triggered indicators + confidence)
        + summary table (stdout)

--------------------------------------------------------------------------------
DISCOVERIES (verified on the low-confidence subset of the population, ABSENT from
the paper). The illustrative host counts below were observed on that subset during
development and are kept only as provenance notes; the authoritative per-indicator
counts are the ones emitted at run time into deep_findings.csv:

C) TEMPLATED DEPLOYMENT  (cross-host fingerprint + ASN entropy)
   A byte-identical ICS identity copied to many hosts is NOT honeypot evidence on
   its own (the same real device model also returns identical data). The
   DISCRIMINATOR is the Shannon entropy of the copy's ASNs. A genuine device
   population spreads over hundreds of ISPs (high entropy; e.g. modbus x26621
   entropy=6.81 = real). A honeypot deployment is run by a few actors => the same
   fingerprint concentrates in <=2-3 ASNs (low entropy; e.g. modbus 'Generic
   Vendor' x1368 entropy=0.68 Cogent+Hurricane; opc_ua x112 entropy=0.07 Alibaba
   Cloud). The paper looks at per-host static defaults; it NEVER uses the
   cross-host fingerprint / ASN-entropy axis. Novel.

D) MODBUS PLACEHOLDER IDENTITY
   A literal placeholder in the MEI device-identification: vendor='Generic Vendor'
   and/or product_code='MODBUS-001' (both=STRONG, one=MEDIUM).

E) PROTOCOL-SET IMPLAUSIBILITY
   A single host answering on >=3 DIFFERENT native ICS protocols (>=4 very strong).
   Especially a cross-vendor set (FINS=Omron + EIP=Rockwell + S7=Siemens) cannot
   coexist on one device => emulator (conpot etc.). Confound: NAT gateway
   (mitigation: only count native protocol OBJECTS + the cross-vendor condition).

F) IDENTITY (SERIAL) CLONED ACROSS ASNs
   A serial number is by definition unique. Seeing the same serial_number value
   verbatim across MULTIPLE independent ASNs (different hosting/ISPs, different
   countries) is physically impossible => a single emulator image copied to many
   hosts. It does NOT use the grammar (e.g. the 'S C-...' prefix), because that
   prefix is a real Siemens serial format that snap7 imitates => not discriminating.
   Only VALUE identity + ASN spread is evidence. Fields: s7.serial_number,
   s7.memory_serial_number, eip.identity.serial_number. >=3 ASNs => STRONG, ==2
   ASNs => MEDIUM. This catches what C (whole-object fingerprint) misses: the
   serial is identical but the rest of the object (uptime/session etc.) changes, so
   the MD5 cluster does not hold.

G) DEGENERATE PROTOCOL NEGOTIATION
   OPC-UA max_chunk_size<=1 (a real stack negotiates >=8192) or an absurd buffer.

H) BACNET TEMPLATE PLACEHOLDER
   description/location literally 'Device Description'/'Device Location' (MEDIUM).
   ('Local BACnet Device object' is common on real devices too, so it is IGNORED.)

I) OPC-UA SDK DEFAULT IDENTITY  (SPLIT INTO TWO CLASSES)
   The paper used snap7's SDK-hardcoded default ('SNAP7-SERVER') and conpot's
   'Mouser Factory'/'88111222' defaults as SIGNATURES: a default string alone =>
   HIGH (no second metric required). The same principle is applied to the OPC-UA
   implementations the paper did not scan, BUT not every SDK default is equally
   reliable:
     * FreeOpcUa (python-opcua) 'urn:freeopcua:python:server' /
       'urn:freeopcua.github.io:python:server' => SIGNATURE (STANDALONE HIGH).
       A pure-Python OPC-UA library; a real industrial PLC does not run a Python
       OPC-UA server => a host carrying this URN is an emulator/PoC/honeypot (a
       software-emulation library, like snap7). signature_opcua_freeopcua().
       89 hosts in that subset, all UNMARKED by the paper => 89 NEW HIGH.
     * open62541 'urn:open62541.server.application'/'http://open62541.org' and
       node-opcua 'NodeOPCUA-Server'/'NodeOPCUA' => host-of-interest (indicator_I,
       MEDIUM). These SDKs are also embedded in REAL commercial products, so a
       standalone HIGH would be a false positive; a second independent metric is
       required. In that subset: open62541=70, node-opcua=22.

SIG_modbus_pymodbus) the pymodbus EXAMPLE server default MEI vendor='Pymodbus'
   (and product_code='PM'). No genuine industrial device sends this identity =>
   a pymodbus-based emulator/PoC/honeypot. STANDALONE HIGH. 6 hosts in that subset.
SIG_bacnet_stackdemo) bacnet-stack (SourceForge/bacnet-stack.org) REFERENCE/DEMO
   server defaults: model_name='GNU' or object_name='SimpleServer'
   (device.c Device_Init). A commercial BACnet device does not ship with this
   identity => an unmodified demo server. STANDALONE HIGH. 69 hosts in that subset.
SIG_mms_libiec61850) the libiec61850 IEC 61850 MMS reference library (gridpot
   packages it): unmodified mms.vendor='libiec61850.com' /
   mms.model='LIBIEC61850'. A real IED reports its own vendor name =>
   demo/emulator/honeypot. STANDALONE HIGH. 19 hosts in that subset.

Note: honeypots scanned that yielded NO new signature: HoneyPLC (profile-based,
uses identities captured from real PLCs, NO hardcoded default), ICSpot/T-Pot/DiPot
(wrap Conpot => repeat Conpot defaults, already caught by C/D/H), GasPot (identity
string is in the banner text: serial '0000112233'/sw 'V364.200'; Censys only
captures the I20100 in-tank inventory, no fixed identity + random station name =>
NO IDENTITY SIGNATURE IS POSSIBLE; the paper used a banner-format anomaly, the
right approach), GridPot (wraps Conpot + libiec61850 => its identity is the Conpot
template + the libiec61850 signature).

Also part of the set: A) vendor-conflict, B) template-ID (defined in this module).

--------------------------------------------------------------------------------
CONFIDENCE (the unified two-tier model; the paper signals join the same pool):
  HIGH   = any signature fires (the new SIG_* OR the adopted conpot/snap7/gaspot).
  MEDIUM = one STRONG indicator (a new STRONG host-of-interest OR the adopted
           hosting AS-type / >30 open ports), OR at least two WEAK indicators
           (a new WEAK host-of-interest + the adopted education / >10 open ports).
  LOW    = a single WEAK indicator alone (a host of interest, not a honeypot).
Every ICS host in the full population is scored once against this combined pool.
Because the adopted signals are retained at their own tiers, the model is
monotone: any host that gains a HIGH/MEDIUM label it would not have had from the
adopted signals alone does so purely because of a new signature or indicator.
"""
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from math import log2

from paper_original_port import classify_record

HERE = os.path.dirname(os.path.abspath(__file__))


# ===========================================================================
# SHARED HELPERS + INDICATORS A and B
# ---------------------------------------------------------------------------
# Indicators A (vendor conflict) and B (template/low-entropy identifier) are two
# of this work's thirteen host-of-interest indicators (A-K, N, P). They live in
# this same module alongside C-K, N, P so that the full indicator set is defined
# in one place and scored in the single unified pass in main().
# ===========================================================================
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
    ent = shannon(Counter(core))
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


def _arg(name, default):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return default


PATH = os.path.join(HERE, _arg("--file", "population.json"))
OUT = os.path.join(HERE, _arg("--out", "deep_findings.csv"))
IPINFO = os.path.join(HERE, _arg("--ipinfo", "ipinfo_map.json"))

# Point the adopted paper module at the SAME IPinfo file (it provides the
# paper-faithful network_type / as.type == hosting|education metric).
import paper_original_port as _paper
_paper._IPINFO_PATH = IPINFO

ICS_OBJS = ("modbus", "s7", "bacnet", "eip", "fox", "iec60870_5_104",
            "opc_ua", "fins", "melsec", "mms", "dnp3")

# protocol -> manufacturer family (for cross-vendor detection)
PROTO_VENDOR = {
    "s7": "SIEMENS", "fins": "OMRON", "eip": "ROCKWELL", "melsec": "MITSUBISHI",
    "fox": "TRIDIUM", "modbus": "GENERIC", "bacnet": "BA",
    "iec60870_5_104": "TELECONTROL", "dnp3": "TELECONTROL",
    "opc_ua": "GENERIC", "mms": "TELECONTROL",
}


# Hosting/transit ASN keywords. For indicator C: a low-entropy cluster is a
# honeypot deployment ONLY IF the dominant ASN is hosting/transit. On a
# cellular/eyeball operator (Turkcell, Verizon Wireless, Asahi, Vodafone) a
# low-entropy cluster is a genuine SIM device fleet (verified) => C must NOT fire.
# Once IPinfo arrives this gate becomes authoritative via as_type=='hosting'; for
# now it is name-based.
HOSTING_TRANSIT_KW = (
    "COGENT", "HURRICANE", "ALIBABA", "OVH", "HETZNER", "DIGITALOCEAN",
    "AMAZON", "AWS", "GOOGLE", "AZURE", "MICROSOFT", "LINODE", "VULTR",
    "CONTABO", "M247", "LEASEWEB", "CHOOPA", "DATACAMP", "SCALEWAY",
    "GODADDY", "HOSTING", "CLOUD", "DATACENTER", "DATA CENTER", "COLO",
    "VPS", "SERVERS", "HOST EUROPE", "IONOS", "ORACLE", "TENCENT",
    "TELIA", "GTT", "LUMEN", "LEVEL3", "LEVEL 3", "ZENLAYER", "G-CORE",
)


def is_hosting_transit(name):
    nm = (name or "").upper()
    return any(k in nm for k in HOSTING_TRANSIT_KW)


# Authoritative IPinfo as_type map (enrich_ipinfo.py -> ipinfo_map.json).
# The indicator C hosting gate is now authoritative via as_type=='hosting' rather
# than by NAME.
_IPINFO_ASTYPE = None


def _ipinfo_astype():
    global _IPINFO_ASTYPE
    if _IPINFO_ASTYPE is None:
        p = IPINFO
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                _IPINFO_ASTYPE = {ip: (v.get("as_type") or v.get("type"))
                                  for ip, v in json.load(f).items()}
        else:
            _IPINFO_ASTYPE = {}
    return _IPINFO_ASTYPE


def cluster_is_hosting(ips, dom_name):
    """Authoritative gate: treat the cluster as hosting/transit if the majority of
    its IPs are IPinfo as_type=='hosting' (or, if IPinfo is missing, via AS-name
    keywords)."""
    m = _ipinfo_astype()
    if m:
        hosting = sum(1 for ip in ips if m.get(ip) == "hosting")
        if hosting * 2 >= len(ips):  # majority hosting
            return True
        # IPinfo present but the majority is not hosting => a real fleet, IGNORE
        return False
    return is_hosting_transit(dom_name)


def asn_of(r):
    return (r.get("autonomous_system") or {}).get("asn")


def shannon(counter):
    L = sum(counter.values())
    if L == 0:
        return 0.0
    return -sum((n / L) * log2(n / L) for n in counter.values())


def ics_objects(r):
    """Yields (objname, obj)."""
    for s in r.get("services", []):
        for k in ICS_OBJS:
            o = s.get(k)
            if isinstance(o, dict):
                yield k, o


# ---------------------------------------------------------------------------
# Indicator K: co-located identical-fingerprint ICS cluster (two-pass).
# DIFFERENT from / complementary to indicator C: C searches the global (obj,fp)
# cluster for n>=20 in ONLY hosting/transit ASes (excluding eyeball ISPs). K
# instead looks for >=5 hosts with the same AS + same /24 + identical
# (product_uri, application_name, FULL port-set) and INCLUDES eyeball ISPs: a
# byte-identical service surface on consecutive IPs of a consumer ISP is NOT a
# dispersed real fleet but a coordinated deployment (honeypot farm / emulation).
# Discovered via active probing (batch4: 27 identical WAGO PFC200 in AS4685 Asahi
# Net). Host-of-interest tier (NOT standalone): a legitimate cloud/integrator can
# also host identical devices, so it is not HIGH on its own; a second metric is
# required.
# ---------------------------------------------------------------------------
def build_colocation_labels(recs, min_cluster=5):
    """>=min_cluster hosts identical on (asn, /24, opcua product_uri,
    application_name, port-set) -> K-strength/evidence. The same /24 + full
    port-set match rules out a dispersed fleet."""
    groups = defaultdict(list)  # key -> [ip...]
    for r in recs:
        ip = r.get("ip")
        if not ip:
            continue
        pu = an = None
        for s in r.get("services", []):
            o = s.get("opc_ua")
            if isinstance(o, dict):
                for ep in o.get("endpoints", []) or []:
                    srv = ep.get("server", {}) or {}
                    pu = srv.get("product_uri")
                    a = srv.get("application_name")
                    an = a.get("text") if isinstance(a, dict) else a
                    break
                break
        if pu is None:
            continue  # only fingerprint hosts with an OPC-UA identity
        ports = frozenset(s.get("port") for s in r.get("services", []) if s.get("port"))
        try:
            s24 = ".".join(ip.split(".")[:3])
        except Exception:
            continue
        key = (asn_of(r), s24, pu, an, ports)
        groups[key].append(ip)

    ip_label = {}
    for key, ips in groups.items():
        n = len(ips)
        if n < min_cluster:
            continue
        asn, s24, pu, an, ports = key
        strength = "MEDIUM"  # host-of-interest: never STRONG/HIGH on its own
        ev = (f"colocation_cluster n={n} AS{asn} {s24}.0/24 "
              f"product_uri={pu!r} name={an!r} ports={sorted(p for p in ports)}")
        for ip in ips:
            prev = ip_label.get(ip)
            if prev is None or (prev[0] == "MEDIUM" and strength == "STRONG"):
                ip_label[ip] = (strength, ev)
    return ip_label


# ---------------------------------------------------------------------------
# Indicator C: cross-host templated deployment (two-pass)
# ---------------------------------------------------------------------------
def build_cluster_labels(recs):
    """For every (objtype, fingerprint) computes the cluster size + ASN entropy,
    returns host_ip -> C-strength/evidence."""
    groups = defaultdict(list)  # (obj, fp) -> [ip...]
    asn_by = defaultdict(Counter)
    asname_by = defaultdict(Counter)
    for r in recs:
        ip = r.get("ip")
        a = asn_of(r)
        anm = (r.get("autonomous_system") or {}).get("name")
        seen = set()
        for name, o in ics_objects(r):
            fp = hashlib.md5(json.dumps(o, sort_keys=True).encode()).hexdigest()
            key = (name, fp)
            if key in seen:
                continue
            seen.add(key)
            groups[key].append(ip)
            asn_by[key][a] += 1
            asname_by[key][anm] += 1

    ip_label = {}  # ip -> (strength, evidence)
    for key, ips in groups.items():
        n = len(ips)
        if n < 20:
            continue
        ent = shannon(asn_by[key])
        # If the dominant ASN is not hosting/transit => cellular/eyeball real fleet,
        # skip
        dom_name = asname_by[key].most_common(1)[0][0]
        if not cluster_is_hosting(ips, dom_name):
            continue
        strength = None
        if n >= 50 and ent <= 1.0:
            strength = "STRONG"
        elif n >= 20 and ent <= 1.5:
            strength = "MEDIUM"
        if not strength:
            continue
        ev = f"{key[0]}_cluster n={n} asn_entropy={ent:.2f} dom={dom_name}"
        for ip in ips:
            prev = ip_label.get(ip)
            # STRONG > MEDIUM
            if prev is None or (prev[0] == "MEDIUM" and strength == "STRONG"):
                ip_label[ip] = (strength, ev)
    return ip_label


# ---------------------------------------------------------------------------
# Indicator D: modbus placeholder identity
# ---------------------------------------------------------------------------
def indicator_D(r):
    for s in r.get("services", []):
        m = s.get("modbus")
        if not isinstance(m, dict):
            continue
        objs = (m.get("mei_response") or {}).get("objects") or {}
        vendor = objs.get("vendor")
        pc = objs.get("product_code")
        if vendor == "Generic Vendor" and pc == "MODBUS-001":
            return ("STRONG", f"modbus_placeholder vendor={vendor!r} pc={pc!r}")
        if vendor == "Generic Vendor" or pc == "MODBUS-001":
            return ("MEDIUM", f"modbus_placeholder vendor={vendor!r} pc={pc!r}")
    return None


# ---------------------------------------------------------------------------
# Indicator N: EtherNet/IP "ListServices but empty ListIdentity" stub.
# The host speaks EIP encapsulation and answers ListServices with COMMUNICATIONS
# BUT has NO identity object (vendor/serial/product). If a real EtherNet/IP stack
# answers ListServices it also returns an identity to ListIdentity; an empty
# identity = a frame imitation with no real CIP device behind it (honeypot/stub).
# Discovered and VERIFIED via active probing (batch9): 52 hosts returned a
# byte-for-byte IDENTICAL empty ListIdentity response (encap length=0); a global
# clone spread over 23 ASNs / 17 countries. Unlike L, cellular ISP is NOT a
# confound here: 75% of identity-bearing real EIP hosts are also cellular =>
# cellularity does not explain the empty identity, only these stubs are empty.
# Host-of-interest tier (NOT standalone); usually combines with E_proto_implausible
# to upgrade LOW->MEDIUM.
# ---------------------------------------------------------------------------
def indicator_N(r):
    for s in r.get("services", []):
        e = s.get("eip")
        if not isinstance(e, dict):
            continue
        if isinstance(e.get("identity"), dict):
            continue
        svcs = e.get("services")
        if not isinstance(svcs, list):
            continue
        for sv in svcs:
            nm = (sv.get("service_name") or "") if isinstance(sv, dict) else ""
            if nm.strip().upper() == "COMMUNICATIONS":
                return ("MEDIUM", "eip_services_no_identity (ListServices=COMMUNICATIONS, identity absent)")
    return None


# ---------------------------------------------------------------------------
# Indicator E: protocol-set implausibility
# ---------------------------------------------------------------------------
def _eip_vendor_id(r):
    """The numeric vendor_id in the EtherNet/IP identity (if any)."""
    for s in r.get("services", []):
        e = s.get("eip")
        if isinstance(e, dict) and isinstance(e.get("identity"), dict):
            v = e["identity"].get("vendor_id")
            if isinstance(v, str) and v.lower().startswith("0x"):
                try:
                    return int(v, 16)
                except ValueError:
                    return None
            if isinstance(v, int):
                return v
    return None


def indicator_E(r):
    fams = {}
    protos = set()
    for name, _ in ics_objects(r):
        protos.add(name)
        fams.setdefault(PROTO_VENDOR.get(name, "?"), set()).add(name)
    # FP refinement: Omron PLCs (EtherNet/IP vendor_id=47) natively speak BOTH
    # FINS AND EtherNet/IP. Seeing these two together on an Omron host is NOT
    # implausible => count as one native stack (merge eip+fins into "omron" in the
    # protocol set so nproto does not inflate and cross-vendor does not fire).
    if "eip" in protos and "fins" in protos and _eip_vendor_id(r) == 47:
        protos = (protos - {"eip", "fins"}) | {"omron_native"}
        fams.pop("ROCKWELL", None)
        fams.pop("OMRON", None)
        fams.setdefault("OMRON", set()).add("omron_native")
    nproto = len(protos)
    # cross-vendor: different manufacturer-specific families
    vendor_specific = [f for f in fams if f in
                       ("SIEMENS", "OMRON", "ROCKWELL", "MITSUBISHI", "TRIDIUM")]
    if nproto >= 4:
        return ("STRONG", f"{nproto}_native_ics_proto {sorted(protos)}")
    if nproto == 3:
        return ("MEDIUM", f"3_native_ics_proto {sorted(protos)}")
    if len(vendor_specific) >= 2:
        return ("MEDIUM", f"cross_vendor {sorted(vendor_specific)} {sorted(protos)}")
    return None


# ---------------------------------------------------------------------------
# Indicator F: identity (serial) cloned across ASNs (two-pass)
# ---------------------------------------------------------------------------
def identity_values(r):
    """Yields (objtype, field, value): serial fields that ought to be unique."""
    for s in r.get("services", []):
        o = s.get("s7")
        if isinstance(o, dict):
            for f in ("serial_number", "memory_serial_number"):
                v = (o.get(f) or "").strip()
                if len(v) >= 6:
                    yield ("s7", f, v)
        e = s.get("eip")
        if isinstance(e, dict) and isinstance(e.get("identity"), dict):
            v = (e["identity"].get("serial_number") or "")
            v = str(v).strip()
            if len(v) >= 6:
                yield ("eip", "identity.serial_number", v)


def build_clone_labels(recs):
    """Counts how many DIFFERENT ASNs the same (objtype, field, value) identity is
    seen in. host_ip -> (strength, evidence). >=3 ASNs STRONG, ==2 ASNs MEDIUM."""
    asn_by = defaultdict(set)       # (obj, field, value) -> {asn...}
    country_by = defaultdict(set)   # (obj, field, value) -> {country...}
    hosts_by = defaultdict(list)    # (obj, field, value) -> [ip...]
    for r in recs:
        ip = r.get("ip")
        a = asn_of(r)
        cty = (r.get("location") or {}).get("country")
        for key in set(identity_values(r)):
            asn_by[key].add(a)
            country_by[key].add(cty)
            hosts_by[key].append(ip)

    ip_label = {}
    for key, asns in asn_by.items():
        nasn = len({a for a in asns if a is not None})
        if nasn < 2:
            continue
        strength = "STRONG" if nasn >= 3 else "MEDIUM"
        obj, fld, val = key
        ev = (f"{obj}.{fld}={val!r} same_value {nasn}_ASN "
              f"{len(country_by[key])}_country {len(hosts_by[key])}_host")
        for ip in hosts_by[key]:
            prev = ip_label.get(ip)
            if prev is None or (prev[0] == "MEDIUM" and strength == "STRONG"):
                ip_label[ip] = (strength, ev)
    return ip_label


# ---------------------------------------------------------------------------
# Indicator G: degenerate OPC-UA negotiation
# ---------------------------------------------------------------------------
def indicator_G(r):
    for s in r.get("services", []):
        o = s.get("opc_ua")
        if not isinstance(o, dict):
            continue
        try:
            mcs = int(o.get("max_chunk_size"))
        except (TypeError, ValueError):
            mcs = None
        if mcs is not None and mcs <= 1:
            return ("MEDIUM", f"opcua_max_chunk_size={mcs}")
    return None


# ---------------------------------------------------------------------------
# Indicator H: BACnet template placeholder
# ---------------------------------------------------------------------------
def indicator_H(r):
    for s in r.get("services", []):
        o = s.get("bacnet")
        if not isinstance(o, dict):
            continue
        desc = o.get("description")
        loc = o.get("location")
        if desc == "Device Description" or loc == "Device Location":
            return ("MEDIUM", f"bacnet_placeholder desc={desc!r} loc={loc!r}")
        # location='localhost'/127.0.0.1: a real controller deployed in the field
        # does not report its Device_Location as 'localhost' => emulator/demo/lazy
        # commissioning. Not standalone (host-of-interest): a commissioning
        # oversight is possible.
        if isinstance(loc, str) and loc.strip().lower() in (
                "localhost", "127.0.0.1", "::1"):
            return ("MEDIUM", f"bacnet_placeholder location={loc!r}")
        # 'Local BACnet Device object' is common on real devices too => weak, IGNORE
    return None


# ===========================================================================
# SIGNATURE LAYER (the paper's default-string logic): a honeypot/emulator
# implementation default => HIGH on its own. The paper used the snap7
# 'SNAP7-SERVER' and conpot 'Mouser Factory'/'88111222' signatures this way: no
# second metric required. The signatures added here are in the SAME class
# (standalone HIGH).
# ===========================================================================
# FreeOpcUa (python-opcua / opcua-asyncio): a pure-Python OPC-UA library.
# A real industrial PLC does NOT run a Python OPC-UA server; a host exposed to the
# Internet as an "ICS device" with this SDK's SAMPLE URN = a software
# emulator/PoC/honeypot (a software-emulation library like snap7). Never seen on a
# real field device => same class as the snap7 signature: STANDALONE HIGH.
SIG_FREEOPCUA = {
    "urn:freeopcua:python:server",
    "urn:freeopcua.github.io:python:server",
}


def signature_opcua_freeopcua(r):
    """FreeOpcUa implementation default => a standalone HIGH signature (like the
    paper)."""
    for s in r.get("services", []):
        o = s.get("opc_ua")
        if not isinstance(o, dict):
            continue
        for ep in o.get("endpoints", []) or []:
            if not isinstance(ep, dict):
                continue
            srv = ep.get("server") or {}
            au = srv.get("application_uri")
            pu = srv.get("product_uri")
            if au in SIG_FREEOPCUA or pu in SIG_FREEOPCUA:
                hit = au if au in SIG_FREEOPCUA else pu
                return f"opcua_impl_default freeopcua {hit!r}"
    return None


# The pymodbus library EXAMPLE server default: MEI vendor='Pymodbus',
# product_code='PM'. No genuine industrial device sends this identity =>
# a pymodbus-based emulator/PoC/honeypot. STANDALONE HIGH (like snap7).
def signature_modbus_pymodbus(r):
    for s in r.get("services", []):
        m = s.get("modbus")
        if not isinstance(m, dict):
            continue
        objs = (m.get("mei_response") or {}).get("objects") or {}
        v = objs.get("vendor")
        pc = objs.get("product_code")
        pn = objs.get("product_name")
        if v == "Pymodbus" or (isinstance(pn, str) and "pymodbus" in pn.lower()):
            return f"modbus_impl_default pymodbus vendor={v!r} pc={pc!r}"
    return None


# bacnet-stack (bacnet-stack.org / SourceForge) REFERENCE/DEMO server defaults:
# model_name='GNU', object_name='SimpleServer' (device.c Device_Init). A commercial
# BACnet device does not appear with model 'GNU' or object name 'SimpleServer' =>
# an unmodified demo server. STANDALONE HIGH.
def signature_bacnet_stackdemo(r):
    for s in r.get("services", []):
        b = s.get("bacnet")
        if not isinstance(b, dict):
            continue
        mn = b.get("model_name")
        on = b.get("object_name")
        if mn == "GNU" or on == "SimpleServer":
            return f"bacnet_impl_default stackdemo model={mn!r} obj={on!r}"
    return None


# libiec61850 (the IEC 61850 MMS reference library, packaged by gridpot):
# unmodified default IED identity mms.vendor='libiec61850.com',
# mms.model='LIBIEC61850'. A real IED (SEL/ABB/Siemens/GE) reports its own vendor
# name; leaving the library's own domain as the vendor = demo/emulator/honeypot
# (same class as snap7). STANDALONE HIGH.
def signature_mms_libiec61850(r):
    for s in r.get("services", []):
        m = s.get("mms")
        if not isinstance(m, dict):
            continue
        v = m.get("vendor")
        mdl = m.get("model")
        if (isinstance(v, str) and "libiec61850" in v.lower()) or mdl == "LIBIEC61850":
            return f"mms_impl_default libiec61850 vendor={v!r} model={mdl!r}"
    return None


# MMS placeholder signature: a real IED does not identify itself with the literal
# "vendor" (the field name left as its value = an unconfigured template/emulator).
# STANDALONE HIGH.
def signature_mms_placeholder(r):
    for s in r.get("services", []):
        m = s.get("mms")
        if not isinstance(m, dict):
            continue
        v = m.get("vendor")
        mdl = m.get("model")
        if isinstance(v, str) and v.strip().lower() == "vendor":
            return f"mms_placeholder unconfigured vendor={v!r} model={mdl!r}"
    return None


# ---------------------------------------------------------------------------
# CAPABILITY-BASED (spec-impossibility) signature: BACnet vendor_id <-> vendor_name
# mismatch. ASHRAE vendor IDs (id<->organisation name) and the name are
# spec-assigned. Censys reads BACnet vendor_name from the device's Device object
# Vendor_Name property (it does NOT derive it from the id; evidence: the same name
# can appear with a different id). Hence a host reporting a name that belongs to
# only one id in the official registry with a DIFFERENT id shows an identity that a
# real/certified device could NOT produce => a signature.
# Concrete case: name='BACnet Stack at SourceForge' is assigned ONLY to id=260 in
# ASHRAE; appearing together with id=1430 (ASHRAE=Hangzhou Hikvision) is impossible
# (120 hosts). Framing: an "interesting emulator/soft-server" signal like
# snap7/libiec61850, not absolute honeypot proof. STANDALONE HIGH.
BACNET_NAME_TO_ID = {"bacnet stack at sourceforge": 260}


def signature_bacnet_id_name_mismatch(r):
    for s in r.get("services", []):
        b = s.get("bacnet")
        if not isinstance(b, dict):
            continue
        vid = b.get("vendor_id")
        vn = b.get("vendor_name")
        if isinstance(vn, str):
            canon = BACNET_NAME_TO_ID.get(vn.strip().lower())
            if canon is not None and vid != canon:
                return (f"bacnet_id_name_impossible name={vn!r} reported_id={vid} "
                        f"registered_id={canon}")
    return None


# ---------------------------------------------------------------------------
# Indicator J (HOST-OF-INTEREST, NOT standalone): use of an ASHRAE-reserved BACnet
# vendor_id. 555/666/777/888/911/999/1111 are reserved by ASHRAE and assigned to
# no certified device => a conformant/certified device cannot report these.
# However this means "uncertified/non-conformant device", which is not honeypot on
# its own (a cheap device may usurp an ID) => a host-of-interest metric.
BACNET_RESERVED_IDS = {555, 666, 777, 888, 911, 999, 1111}


def indicator_J(r):
    for s in r.get("services", []):
        b = s.get("bacnet")
        if not isinstance(b, dict):
            continue
        vid = b.get("vendor_id")
        if isinstance(vid, int) and vid in BACNET_RESERVED_IDS:
            vn = b.get("vendor_name")
            return ("MEDIUM", f"bacnet_reserved_vendor_id id={vid} name={vn!r}")
    return None


# ---------------------------------------------------------------------------
# Indicator I (HOST-OF-INTEREST, NOT standalone): open62541 / node-opcua SDK
# default identity. These two SDKs are also embedded in REAL commercial products =>
# making them HIGH on their own would be a false positive. Hence not a signature
# but a host-of-interest metric (a second independent metric is required for HIGH).
# ---------------------------------------------------------------------------
# (strength, sdk, {application_uri...}, {product_uri...}, {application_name...})
OPCUA_SDK_DEFAULTS = (
    ("MEDIUM", "open62541",
     {"urn:open62541.server.application", "urn:unconfigured:application"},
     {"http://open62541.org"},
     {"open62541-based OPC UA Application"}),
    ("MEDIUM", "node-opcua",
     set(),
     {"NodeOPCUA-Server"},
     {"NodeOPCUA"}),
    # OPC Foundation ANSI C stack SAMPLE/test server: a real product does not appear
    # on the Internet with the sample-server name (SDK sample). Could be an embedded
    # test => host-of-interest.
    ("MEDIUM", "uastack-sample",
     set(),
     set(),
     {"UA StackTest Server (AnsiC/2048)", "UA Sample Server"}),
)


def indicator_I(r):
    for s in r.get("services", []):
        o = s.get("opc_ua")
        if not isinstance(o, dict):
            continue
        for ep in o.get("endpoints", []) or []:
            if not isinstance(ep, dict):
                continue
            srv = ep.get("server") or {}
            au = srv.get("application_uri")
            pu = srv.get("product_uri")
            an = srv.get("application_name")
            if isinstance(an, dict):
                an = an.get("text")
            for strength, sdk, aset, pset, nset in OPCUA_SDK_DEFAULTS:
                if au in aset or pu in pset or an in nset:
                    hit = au if au in aset else (pu if pu in pset else an)
                    return (strength, f"opcua_sdk_default {sdk} {hit!r}")
    return None


# ---------------------------------------------------------------------------
# Indicator P: OPC-UA endpoint self-advertises a loopback/wildcard address.
#
# The OPC-UA analogue of indicator H (BACnet location='localhost'). A real OPC-UA
# server advertises an EndpointUrl reachable by a remote client; a host advertising
# 'opc.tcp://localhost'/'127.0.0.1'/'0.0.0.0' is a never-customised
# emulator/demo/lazy commissioning (a meaningless address remotely). This is a
# fully-complete passive fact seen in Censys's OWN enumeration (the endpoint_url
# field) => needs no active confirmation, like H.
#
# FP protection: ONLY loopback/wildcard. RFC1918 (192.168/10/172.16-31) is
# EXCLUDED; a real OPC-UA server behind NAT legitimately advertises its LAN IP.
# Not standalone (host-of-interest): a commissioning oversight is possible => MEDIUM.
_OPCUA_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def indicator_P(r):
    for s in r.get("services", []):
        o = s.get("opc_ua")
        if not isinstance(o, dict):
            continue
        for ep in o.get("endpoints", []) or []:
            if not isinstance(ep, dict):
                continue
            url = ep.get("endpoint_url")
            if not isinstance(url, str):
                continue
            m = re.match(r"opc\.tcp://\[?([^\]:/]+)", url.strip())
            if m and m.group(1).strip().lower() in _OPCUA_LOOPBACK_HOSTS:
                return ("MEDIUM", f"opcua_loopback_endpoint {m.group(1)!r}")
    return None


# ---------------------------------------------------------------------------
# UNIFIED MODEL: the paper's signals ALSO join the scoring pool. The paper
# signals enter the pool at their own tiers:
#   - signature (conpot/snap7/gaspot)          => HIGH layer (like the new SIG_*)
#   - hosting (as/company) OR >30 ports        => standalone-MEDIUM (like a new STRONG)
#   - education OR >10 ports                    => weak host-of-interest (like a new WEAK)
# The model is thus MONOTONE: no host the paper called a honeypot is ever demoted;
# the paper tier is a FLOOR and the new signals can only push upward.
# ---------------------------------------------------------------------------
_PAPER_SIGS = {"honeypot_defaults_conpot", "honeypot_defaults_snap7",
               "gaspot_newlines", "gaspot_date"}


def paper_metrics(r):
    """Backward-compatibility: the set of weak (host-of-interest) paper metrics.
    (paper_signals() returns the richer classification.)"""
    _, indications = classify_record(r)
    m = set()
    if "many_open_ports" in indications:
        m.add("paper_many_open_ports")
    if any(x in indications for x in ("as_education", "company_education")):
        m.add("paper_as_education")
    return m


def paper_signals(r):
    """Maps the paper signals to the layers of the unified model.
    Returns: (paper_sig:set, paper_strong:set, paper_weak:set)
      paper_sig    = signature (=> HIGH)
      paper_strong = hosting / >30 ports (=> standalone MEDIUM, like a new STRONG)
      paper_weak   = education / >10 ports (=> weak metric, like a new WEAK)
    """
    _, indications = classify_record(r)
    ind = set(indications)
    sig = ind & _PAPER_SIGS
    strong = set()
    if ind & {"as_hosting", "company_hosting"}:
        strong.add("paper_hosting")
    if "many_open_ports_high" in ind:
        strong.add("paper_many_open_ports_high")
    weak = set()
    if ind & {"as_education", "company_education"}:
        weak.add("paper_as_education")
    if "many_open_ports" in ind:
        weak.add("paper_many_open_ports")
    return sig, strong, weak


# Indicators A, C, D, E and F carry a genuine STRONG/WEAK split (the same STRONG
# hit crosses the standalone-MEDIUM threshold, a WEAK hit does not). To stay
# symmetric with the adopted method — which already emits two distinct tokens for
# its graded indicators (paper_many_open_ports vs paper_many_open_ports_high, and
# paper_hosting vs paper_as_education) — these indicators emit two distinct
# identifiers as well, so a STRONG firing and a WEAK firing are never conflated in
# the per-signal counts or the combination breakdown. Single-grade indicators
# (B always STRONG; G/H/I/J/K/N/P always WEAK) keep a single identifier.
_SPLIT_INDICATORS = {"A_vendor_conflict", "C_templated_deploy",
                     "D_modbus_placeholder", "E_proto_implausible",
                     "F_serial_clone"}


def graded_key(base, grade):
    if base in _SPLIT_INDICATORS:
        return f"{base}_strong" if grade == "STRONG" else f"{base}_weak"
    return base


# ---------------------------------------------------------------------------
def main():
    if not os.path.exists(PATH):
        sys.exit(f"ERROR: {PATH} missing.")
    def _hr(title):
        print("\n" + "=" * 62)
        print(f" {title}")
        print("=" * 62)

    _hr("STEP 1/4  Load population and select ICS hosts")
    print(f"   [1.1] reading {os.path.basename(PATH)} ...")
    with open(PATH, encoding="utf-8") as f:
        d = json.load(f)
    recs = [h.get("host_v1", {}).get("resource") for h in d["result"]["hits"]]
    recs = [r for r in recs if r]
    N_all = len(recs)
    print(f"         parsed hosts          : {N_all:>10,}")
    # Keep only ICS hosts; the unified classifier then scores EVERY ICS host in a
    # single pass. There is no residual pre-filtering: the adopted paper signals
    # join the same pool via paper_signals(), so paper/Censys detections are kept
    # as a monotone floor rather than removed up front.
    recs = [r for r in recs if "ICS" in host_labels(r.get("services", []))]
    N = len(recs)
    print(f"   [1.2] keep ICS-labelled hosts : {N:>10,} / {N_all:,}")

    _hr("STEP 2/4  Cross-host (relational) indicators  [two-pass precompute]")
    print("   [2.1] Indicator C  templated deployment across hosts ...")
    cluster = build_cluster_labels(recs)
    print(f"         -> {len(cluster):>10,} hosts flagged")
    print("   [2.2] Indicator F  identity/serial cloned across ASNs ...")
    clones = build_clone_labels(recs)
    print(f"         -> {len(clones):>10,} hosts flagged")
    print("   [2.3] Indicator K  co-location fingerprint cluster ...")
    colo = build_colocation_labels(recs)
    print(f"         -> {len(colo):>10,} hosts flagged")

    _hr("STEP 3/4  Score every host in one pass")
    print("   evaluated per host, in order:")
    print("     3.1 signature layer        : 9 default-identity signatures (HIGH alone)")
    print("     3.2 single-host indicators : A B D E G H I J N P")
    print("     3.3 adopted paper metrics  : network AS-type, open-port count")
    print("     3.4 merge step-2 results, then classify HIGH / MEDIUM / LOW")

    rows = []
    conf_counter = Counter()
    ind_counter = Counter()
    upgraded = 0       # paper-LOW promoted to MEDIUM (host-of-interest)
    sig_high = 0       # DIRECTLY HIGH thanks ONLY to a new signature (paper-tier)
    censys_hp_count = 0  # hosts carrying Censys' own built-in HONEYPOT label

    for i, r in enumerate(recs, 1):
        if i % 20000 == 0 or i == N:
            print(f"       scoring ... {i:>10,} / {N:,}")
        ip = r.get("ip")
        if "HONEYPOT" in host_labels(r.get("services", [])):
            censys_hp_count += 1
        triggered = {}  # name -> (strength, evidence)

        # --- SIGNATURE layer (like the paper: default-string => HIGH on its own) ---
        signatures = {}  # name -> (strength, evidence)
        sig_ev = signature_opcua_freeopcua(r)
        if sig_ev:
            signatures["SIG_opcua_freeopcua"] = ("STRONG", sig_ev)
        sig_ev = signature_modbus_pymodbus(r)
        if sig_ev:
            signatures["SIG_modbus_pymodbus"] = ("STRONG", sig_ev)
        sig_ev = signature_bacnet_stackdemo(r)
        if sig_ev:
            signatures["SIG_bacnet_stackdemo"] = ("STRONG", sig_ev)
        sig_ev = signature_mms_libiec61850(r)
        if sig_ev:
            signatures["SIG_mms_libiec61850"] = ("STRONG", sig_ev)
        sig_ev = signature_mms_placeholder(r)
        if sig_ev:
            signatures["SIG_mms_placeholder"] = ("STRONG", sig_ev)
        sig_ev = signature_bacnet_id_name_mismatch(r)
        if sig_ev:
            signatures["SIG_bacnet_id_name_mismatch"] = ("STRONG", sig_ev)

        a = indicator_A(r)
        if a:
            triggered[graded_key("A_vendor_conflict", a[2])] = (a[2], "|".join(a[0]))
        b = indicator_B(r)
        if b:
            # indicator_B now returns only STRONG (the weak class was removed)
            triggered["B_template_id"] = ("STRONG", b[0][0])
        if ip in cluster:
            g, ev = cluster[ip]
            triggered[graded_key("C_templated_deploy", g)] = (g, ev)
        if ip in clones:
            g, ev = clones[ip]
            triggered[graded_key("F_serial_clone", g)] = (g, ev)
        if ip in colo:
            triggered["K_colocation_cluster"] = colo[ip]
        for name, fn in (("D_modbus_placeholder", indicator_D),
                         ("E_proto_implausible", indicator_E),
                         ("G_opcua_degenerate", indicator_G),
                         ("H_bacnet_placeholder", indicator_H),
                         ("I_opcua_sdk_default", indicator_I),
                         ("J_bacnet_reserved_id", indicator_J),
                         ("N_eip_services_no_identity", indicator_N),
                         ("P_opcua_loopback_endpoint", indicator_P)):
            res = fn(r)
            if res:
                triggered[graded_key(name, res[0])] = res

        pm = paper_metrics(r)
        # --- UNIFIED MODEL: the paper signals also join the pool ---
        paper_sig, paper_strong, paper_weak = paper_signals(r)
        # signature layer = the new SIG_* + the paper signatures (conpot/snap7/gaspot)
        has_signature = bool(signatures) or bool(paper_sig)
        # standalone-MEDIUM STRONG pool = the new STRONG host-of-interest +
        #   the paper hosting/>30-port (the paper's direct-MEDIUM signals)
        hoi_strong = any(g == "STRONG" for g, _ in triggered.values()) or bool(paper_strong)
        # weak metric pool = the new WEAK host-of-interest + the paper weak signals
        #   (education / >10 ports)
        weak_metrics = (sum(1 for g, _ in triggered.values() if g != "STRONG")
                        + len(paper_weak))
        # add the signatures to triggered so they appear in the CSV/counts too
        triggered.update(signatures)
        n_metrics = len(triggered) + len(paper_strong) + len(paper_weak) + len(paper_sig)
        if n_metrics == 0:
            continue

        # --- UNIFIED PAPER+OURS MODEL (monotone; the paper tier is a floor) ---
        # HIGH  = signature (the new SIG_* OR the paper conpot/snap7/gaspot)
        # MEDIUM= standalone STRONG (a new STRONG OR the paper hosting/>30-port),
        #         or >=2 weak metrics (a new WEAK + the paper education/>10-port)
        # LOW   = a single weak metric
        if has_signature:
            conf = "HIGH"
        elif hoi_strong:
            conf = "MEDIUM"
        elif weak_metrics >= 2:
            conf = "MEDIUM"
        else:
            conf = "LOW"

        # DIRECTLY HIGH thanks ONLY to one of the new signatures (not a paper signature):
        if signatures and not paper_sig:
            sig_high += 1

        # The paper alone would have rated this host LOW (only 1 weak paper metric,
        # 0 paper-STRONG/signature); the new indicator(s) lifted it to MEDIUM+.
        paper_alone_high = bool(paper_sig) or bool(paper_strong)
        paper_alone_weak = len(paper_weak)
        if (not paper_alone_high and conf in ("MEDIUM", "HIGH")
                and paper_alone_weak >= 1
                and (hoi_strong or bool(signatures)
                     or (weak_metrics - len(paper_weak)) >= 1)):
            upgraded += 1

        for k in triggered:
            ind_counter[k] += 1
        for k in (paper_sig | paper_strong | paper_weak):
            ind_counter[k] += 1
        conf_counter[conf] += 1

        censys_hp = "yes" if "HONEYPOT" in host_labels(r.get("services", [])) else "no"
        metrics = sorted(pm | paper_strong | paper_weak | paper_sig | set(triggered))
        rows.append({
            "ip": ip,
            "censys_honeypot?": censys_hp,
            "confidence": conf,
            "n_independent_metrics": n_metrics,
            "asn": asn_of(r),
            "as_name": (r.get("autonomous_system") or {}).get("name"),
            "country": (r.get("location") or {}).get("country"),
            "metrics": ";".join(metrics),
            "evidence": " || ".join(f"{k}:{v[0]}:{v[1]}" for k, v in sorted(triggered.items())),
        })

    rows.sort(key=lambda x: (-{"HIGH": 3, "MEDIUM": 2, "LOW": 1}[x["confidence"]],
                             -x["n_independent_metrics"]))
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    _hr("STEP 4/4  Write findings and summarise")
    print(f"   findings written  -> {OUT}")
    print(f"   flagged hosts (>=1 metric): {len(rows):,} / {N:,}")
    print("   --- confidence distribution ---")
    for c in ("HIGH", "MEDIUM", "LOW"):
        print(f"   {c:7s}: {conf_counter[c]}")
    print(f"   Censys' own HONEYPOT label (all ICS hosts): {censys_hp_count:,}")
    print(f"   -> paper alone would rate LOW but a new metric lifts to MEDIUM+: {upgraded}")
    print(f"   -> DIRECTLY HIGH via a NEW default-string SIGNATURE (paper-tier, standalone): {sig_high}")
    print("--- Indicator triggers (hosts) ---")
    for k, v in ind_counter.most_common():
        print(f"   {k:24s}: {v}")
    print("=" * 72)
    print(f"-> {OUT}")

    # ---- HEADLINE SUMMARY (demo) --------------------------------------------
    # Paper-alone honeypot count on this SAME population, produced by
    # paper_original_port.py (Mladenov et al. method, authoritative IPInfo).
    # Kept as a documented constant so the demo prints the additive gain.
    PAPER_ALONE_HONEYPOTS = 20005
    honeypot = conf_counter["HIGH"] + conf_counter["MEDIUM"]
    delta = honeypot - PAPER_ALONE_HONEYPOTS
    pct = 100.0 * delta / PAPER_ALONE_HONEYPOTS
    share = 100.0 * honeypot / N
    print()
    print("#" * 72)
    print("  RESULTS")
    print("#" * 72)
    print(f"  Exposed ICS hosts scanned          : {N:>10,}")
    print(f"  Censys' own HONEYPOT label         : {censys_hp_count:>10,}")
    print(f"  Likely honeypots (HIGH + MEDIUM)   : {honeypot:>10,}   "
          f"({share:.1f}%)")
    print(f"      HIGH   (signature-certain)     : {conf_counter['HIGH']:>10,}")
    print(f"      MEDIUM (from indicators)       : {conf_counter['MEDIUM']:>10,}")
    print(f"  Adopted method alone (Mladenov)    : {PAPER_ALONE_HONEYPOTS:>10,}")
    print(f"  THIS WORK adds                     : {'+' + format(delta, ','):>10}   "
          f"(+{pct:.1f}%)")
    print("#" * 72)


if __name__ == "__main__":
    main()
