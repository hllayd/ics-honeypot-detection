# -*- coding: utf-8 -*-
"""Characterise the flagged (HIGH+MEDIUM) honeypot set against the full ICS
population and render the result charts.

Analyses produced (each is written as a PNG under fig_analysis/ and summarised
in analysis_stats.json):

  1. Confidence-tier counts (HIGH / MEDIUM / LOW) and the most common protocols
     among the flagged hosts.                        -> fig61_protocols.png
  2. Top-15 countries by absolute honeypot count.    -> fig62_country_count.png
  3. Honeypot proportion per country (flagged / total ICS, countries with
     >=200 ICS hosts) against the global proportion.  -> fig63_proportion.png
  4. Top-15 autonomous systems hosting the flagged set.-> fig64_as.png
  5. IP-range business-type breakdown of the flagged set (IPInfo company.type:
     hosting / isp / business / education / ...).      -> fig65_biztype.png
  6. Open-port-count distribution (CDF), flagged hosts vs. unflagged ("real")
     hosts, with the median for each.                  -> fig65_ports_cdf.png
  7. Multi-protocol distribution: number of distinct ICS protocols a single
     flagged host emulates (bucketed 1..6+).           -> fig66_multiproto.png
  8. Signature / indicator combinations: how many hosts are flagged by each
     distinct signature + host-of-interest set (the answer to "which
     combination flagged how many hosts"), plus the per-signal singleton
     counts.                                            -> fig67_combinations.png
  9. Oddballs: the flagged hosts with the largest open-port counts (table only,
     in analysis_stats.json).

Inputs:  deep_findings_aug20.csv (classifier output), population_aug20.json
         (full ICS population), ipinfo_map.json (AS/company categories).
Outputs: PNG charts (150 dpi) under fig_analysis/ + analysis_stats.json.
"""
import csv, json, collections, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV = "deep_findings_aug20.csv"
POP = "population_aug20.json"
IPI = "ipinfo_map.json"
FIGDIR = "fig_analysis"
os.makedirs(FIGDIR, exist_ok=True)

# ---------- load flagged findings ----------
rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
hm = [r for r in rows if r["confidence"] in ("HIGH", "MEDIUM")]
print("flagged rows:", len(rows), "| H+M:", len(hm))

# ---------- load population: per-host country + open-port count + ICS presence ----------
pop = json.load(open(POP, encoding="utf-8"))
hits = pop["result"]["hits"]
def res(h): return h.get("host_v1", {}).get("resource", h)

ip_country = {}
ip_portcount = {}
country_total = collections.Counter()
for h in hits:
    r = res(h)
    ip = r.get("ip")
    c = (r.get("location") or {}).get("country") or "Unknown"
    svcs = r.get("services", [])
    ports = {s.get("port") for s in svcs if s.get("port") is not None}
    ip_country[ip] = c
    ip_portcount[ip] = len(ports)
    country_total[c] += 1
print("population hosts:", len(hits))

# ---------- load ipinfo (company.type / as_type) ----------
ipi = json.load(open(IPI, encoding="utf-8")) if os.path.exists(IPI) else {}

stats = {}

# =========================================================
# 6.1 Global distribution: tiers + most popular protocol among H+M
# =========================================================
tier = collections.Counter(r["confidence"] for r in rows)
stats["tiers"] = dict(tier)
proto_hm = collections.Counter()
for r in hm:
    for p in (r["protocols"] or "").split(";"):
        p = p.strip()
        if p:
            proto_hm[p] += 1
# keep only ICS-relevant? paper reports industrial protocol; show top 12 overall
top_proto = proto_hm.most_common(12)
stats["top_protocols_hm"] = top_proto

fig, ax = plt.subplots(figsize=(7, 4))
labels = [p for p, _ in top_proto][::-1]
vals = [v for _, v in top_proto][::-1]
ax.barh(labels, vals, color="#c0392b")
ax.set_xlabel("H+M honeypot hosts")
ax.set_title("6.1  Most common protocols among suspected honeypots (H+M)")
for i, v in enumerate(vals):
    ax.text(v, i, " " + f"{v:,}", va="center", fontsize=8)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig61_protocols.png", dpi=140); plt.close(fig)

# =========================================================
# 6.2 / country distribution of honeypots (count) + top-15
# =========================================================
hp_country = collections.Counter(r["country"] or "Unknown" for r in hm)
top_country = hp_country.most_common(15)
stats["top_countries_hm"] = top_country

fig, ax = plt.subplots(figsize=(7, 4.5))
labs = [c for c, _ in top_country][::-1]
vals = [v for _, v in top_country][::-1]
ax.barh(labs, vals, color="#2c3e50")
ax.set_xlabel("Suspected honeypots (H+M)")
ax.set_title("6.2  Top-15 countries by honeypot count")
for i, v in enumerate(vals):
    ax.text(v, i, " " + f"{v:,}", va="center", fontsize=8)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig62_country_count.png", dpi=140); plt.close(fig)

# =========================================================
# 6.3 Proportion of honeypots per country (H+M / total ICS)
#     restrict to countries with a meaningful denominator (>=200 ICS hosts)
# =========================================================
prop = []
for c, tot in country_total.items():
    if tot >= 200:
        prop.append((c, hp_country.get(c, 0) / tot, hp_country.get(c, 0), tot))
prop.sort(key=lambda x: x[1], reverse=True)
top_prop = prop[:15]
stats["top_proportion_country"] = [(c, round(p, 3), hp, tot) for c, p, hp, tot in top_prop]
overall_prop = len(hm) / len(hits)
stats["overall_proportion"] = round(overall_prop, 4)

fig, ax = plt.subplots(figsize=(7, 4.5))
labs = [f"{c} ({hp}/{tot})" for c, p, hp, tot in top_prop][::-1]
vals = [p * 100 for c, p, hp, tot in top_prop][::-1]
ax.barh(labs, vals, color="#8e44ad")
ax.axvline(overall_prop * 100, color="red", ls="--", lw=1,
           label=f"global {overall_prop*100:.1f}%")
ax.set_xlabel("Honeypots as % of exposed ICS hosts")
ax.set_title("6.3  Honeypot proportion per country (>=200 ICS hosts)")
ax.legend(fontsize=8)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig63_proportion.png", dpi=140); plt.close(fig)

# =========================================================
# 6.4 Popularity per AS: top ASes hosting honeypots
# =========================================================
as_country = collections.Counter()
as_name_map = {}
for r in hm:
    key = r["asn"] or "?"
    as_country[key] += 1
    as_name_map[key] = (r["as_name"] or "").strip()
top_as = as_country.most_common(15)
stats["top_as_hm"] = [(a, as_name_map.get(a, ""), n) for a, n in top_as]

fig, ax = plt.subplots(figsize=(7.5, 4.5))
def short(nm, a):
    nm = nm.split(" - ")[0].split(",")[0]
    return f"AS{a} {nm[:22]}"
labs = [short(as_name_map.get(a, ""), a) for a, _ in top_as][::-1]
vals = [n for _, n in top_as][::-1]
ax.barh(labs, vals, color="#16a085")
ax.set_xlabel("Suspected honeypots (H+M)")
ax.set_title("6.4  Top-15 ASes hosting suspected honeypots")
for i, v in enumerate(vals):
    ax.text(v, i, " " + f"{v:,}", va="center", fontsize=8)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig64_as.png", dpi=140); plt.close(fig)

# =========================================================
# 6.5a Characteristics: business type (company.type) distribution of H+M
# =========================================================
btype = collections.Counter()
astype = collections.Counter()
for r in hm:
    e = ipi.get(r["ip"], {})
    btype[(e.get("type") or "unknown")] += 1
    astype[(e.get("as_type") or "unknown")] += 1
stats["business_type_hm"] = dict(btype)
stats["as_type_hm"] = dict(astype)

order = ["hosting", "isp", "business", "education", "government", "unknown"]
bt = [(k, btype.get(k, 0)) for k in order if btype.get(k, 0)]
colors = ["#e74c3c", "#3498db", "#f39c12", "#2ecc71", "#9b59b6", "#95a5a6"]
fig, ax = plt.subplots(figsize=(7.5, 5.5))
vals = [v for _, v in bt]
wedges, _ = ax.pie(vals, colors=colors[:len(bt)], startangle=90,
                   wedgeprops=dict(width=0.45, edgecolor="white"))
ax.set_title("6.5  Suspected honeypots by IP-range business type\n(IPInfo company.type)")
legend_labels = [f"{k}: {v:,} ({v/len(hm)*100:.1f}%)" for k, v in bt]
ax.legend(wedges, legend_labels, title="Business type",
          loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=9)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig65_biztype.png", dpi=140,
                                bbox_inches="tight"); plt.close(fig)

# =========================================================
# 6.5b Open-port-count CDF: honeypots (H+M) vs real
# =========================================================
hm_ips = {r["ip"] for r in hm}
flagged_ips = {r["ip"] for r in rows}  # any tier
real_ips = [ip for ip in ip_portcount if ip not in flagged_ips]
hp_ports = sorted(ip_portcount[ip] for ip in hm_ips if ip in ip_portcount)
real_ports = sorted(ip_portcount[ip] for ip in real_ips)
def cdf(xs):
    n = len(xs)
    return xs, [(i + 1) / n for i in range(n)]
stats["median_ports_hm"] = hp_ports[len(hp_ports)//2] if hp_ports else 0
stats["median_ports_real"] = real_ports[len(real_ports)//2] if real_ports else 0

fig, ax = plt.subplots(figsize=(7, 4))
for xs, lab, col in [(hp_ports, "honeypots (H+M)", "#c0392b"),
                     (real_ports, "real (unflagged)", "#2c3e50")]:
    if xs:
        x, y = cdf(xs)
        ax.plot(x, y, label=lab, color=col, lw=1.6)
ax.set_xscale("log")
ax.set_xlabel("open port count (log)")
ax.set_ylabel("CDF")
ax.set_title("6.5  Open-port-count CDF: honeypots vs real")
ax.legend(fontsize=8); ax.grid(alpha=0.3)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig65_ports_cdf.png", dpi=140); plt.close(fig)

# =========================================================
# 6.6 Multi-protocol honeypots: number of DISTINCT ICS protocols emulated
# =========================================================
ICS = {"MODBUS", "S7", "S7COMM", "BACNET", "EIP", "FOX", "IEC60870_5_104",
       "WDBRPC", "CODESYS", "OPC_UA", "OPCUA", "FINS", "MMS", "DNP3",
       "MELSEC", "GE_SRTP", "PCWORX", "HART", "PROCONOS", "ATG"}
ics_count = collections.Counter()
for r in hm:
    ps = {p.strip().upper() for p in (r["protocols"] or "").split(";") if p.strip()}
    n = len(ps & ICS)
    ics_count[min(n, 6)] += 1  # bucket 6+ together
stats["multi_protocol_hist"] = {k: ics_count.get(k, 0) for k in range(1, 7)}

fig, ax = plt.subplots(figsize=(7, 4))
ks = list(range(1, 7))
vs = [ics_count.get(k, 0) for k in ks]
labs = [str(k) if k < 6 else "6+" for k in ks]
ax.bar(labs, vs, color="#d35400")
ax.set_xlabel("distinct ICS protocols emulated by one host")
ax.set_ylabel("H+M honeypot hosts")
ax.set_title("6.6  Multi-protocol honeypots")
for i, v in enumerate(vs):
    ax.text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=8)
fig.tight_layout(); fig.savefig(f"{FIGDIR}/fig66_multiproto.png", dpi=140); plt.close(fig)

# =========================================================
# 6.7 Signature / indicator combinations: how many hosts per combination
#     (which signature + host-of-interest set flags each host, and how often)
# =========================================================
combo_counter = collections.Counter()
single_counter = collections.Counter()
for r in hm:
    parts = []
    for src in ("new_indicators", "paper_metrics"):
        for x in (r.get(src) or "").split(";"):
            x = x.strip()
            if x:
                parts.append(x)
    if not parts:
        continue
    combo = " + ".join(sorted(set(parts)))
    combo_counter[combo] += 1
    for x in set(parts):
        single_counter[x] += 1
top_combo = combo_counter.most_common(20)
stats["signature_indicator_combinations"] = top_combo
stats["signature_indicator_singletons"] = single_counter.most_common()
stats["distinct_combinations"] = len(combo_counter)

# The adopted method (Mladenov et al.) reaches its HIGH+MEDIUM honeypot verdict
# using only these signals: two coarse network indicators (with STRONG/WEAK grades)
# and the ATG/S7 signatures. A combination is "promoted" by this work only when the
# adopted signals in it would NOT already place the host in the paper's honeypot set,
# so that the contributed signal is what lifts it in — this is exactly the delta
# between the paper's 20,005-host set and this work's 22,387-host set.
_ADOPTED_SIG = {"honeypot_defaults_conpot", "honeypot_defaults_snap7",
                "gaspot_newlines", "gaspot_date"}
_ADOPTED_STRONG = {"paper_hosting", "paper_many_open_ports_high"}
_ADOPTED_WEAK = {"paper_many_open_ports", "paper_as_education"}


def paper_is_honeypot(combo):
    """Would the adopted method alone label this combination HIGH+MEDIUM?
    HIGH = any adopted signature; MEDIUM = one STRONG or two WEAK adopted indicators."""
    parts = set(combo.split(" + "))
    if parts & _ADOPTED_SIG:
        return True
    if parts & _ADOPTED_STRONG:
        return True
    if len(parts & _ADOPTED_WEAK) >= 2:
        return True
    return False


def combo_is_promoted(combo):
    """True when the host is in this work's honeypot set on the strength of a
    contributed signal and would NOT be flagged by the adopted method alone."""
    return not paper_is_honeypot(combo)


def abbrev_signal(s):
    """Compact label for one signal: our indicators -> their letter (A..P),
    everything else (paper metrics / signatures) kept as-is."""
    import re
    m = re.match(r"^([A-KNP])_", s)
    return m.group(1) if m else s


def abbrev_combo(combo):
    return " + ".join(abbrev_signal(x) for x in combo.split(" + "))


stats["signature_indicator_combinations_flagged"] = [
    [c, n, combo_is_promoted(c)] for c, n in top_combo]

# largest at top: keep most_common order, place with explicit y positions so
# duplicate/near labels can never collapse onto the same row.
labs = [abbrev_combo(c) for c, _ in top_combo]
vals = [v for _, v in top_combo]
promoted = [combo_is_promoted(c) for c, _ in top_combo]
y = list(range(len(vals)))[::-1]  # row 0 at top

C_PROMOTED = "#c0392b"  # combinations lifted into the honeypot set by our contribution
C_ADOPTED = "#95a5a6"   # combinations the adopted method would already flag
bar_colors = [C_PROMOTED if c else C_ADOPTED for c in promoted]

fig, ax = plt.subplots(figsize=(9.5, 6.5))
ax.barh(y, vals, color=bar_colors)
ax.set_yticks(y)
lbl_objs = ax.set_yticklabels(labs, fontsize=8)
# colour the tick labels to match their bar (same order as labs)
for tick, c in zip(lbl_objs, promoted):
    tick.set_color(C_PROMOTED if c else "#333333")
ax.set_xlim(0, max(vals) * 1.12)
ax.set_xlabel("H+M honeypot hosts")
ax.set_title("6.7  Top-20 signature / indicator combinations by host count",
             fontsize=10, loc="right")
for yi, v, c in zip(y, vals, promoted):
    ax.text(v + max(vals) * 0.01, yi, f"{v:,}", va="center", fontsize=8,
            color=C_PROMOTED if c else "#333333")
from matplotlib.patches import Patch
fig.tight_layout(rect=[0, 0.05, 1, 1])
fig.legend(handles=[Patch(color=C_PROMOTED,
                          label="newly promoted to honeypot by a contributed signal"),
                    Patch(color=C_ADOPTED,
                          label="already flagged by the adopted method")],
           fontsize=8, loc="lower center", ncol=2, frameon=False)
fig.savefig(f"{FIGDIR}/fig67_combinations.png", dpi=140); plt.close(fig)

# =========================================================
# 6.8 Oddballs: hosts with an unusually large number of open ports
# =========================================================
odd = sorted(((ip_portcount.get(r["ip"], 0), r["ip"], r["country"],
               r["as_name"], r["protocols"]) for r in hm),
             reverse=True)[:15]
stats["oddballs"] = [(n, ip, c, (an or "")[:40]) for n, ip, c, an, _ in odd]

json.dump(stats, open("analysis_stats.json", "w", encoding="utf-8"),
          indent=2, ensure_ascii=False)
print("saved figures to", FIGDIR, "and analysis_stats.json")
print("tiers:", dict(tier))
print("biz type:", dict(btype))
print("median ports hm/real:", stats["median_ports_hm"], stats["median_ports_real"])
print("multiproto:", stats["multi_protocol_hist"])
print("distinct signature/indicator combinations:", stats["distinct_combinations"])
