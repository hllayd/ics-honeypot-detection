# Passive Detection of ICS Honeypots at Scale

Code for a SEC592 master's project that extends the passive honeypot-detection
methodology of Mladenov, Erdődi and Smaragdakis, *"All that Glitters is not Gold:
Uncovering Exposed Industrial Control Systems and Honeypots in the Wild"* (IEEE
EuroS&P 2025), to a Censys Platform population and adds new passive indicators,
protocol signatures, and an optional read-only active-probing validation stage.

The adopted method (`paper_original_port.py`) is a faithful port of the detection
logic from the authors' repository
(<https://github.com/martinmladenov/ICS-Honeypots>). All other analysis in this
repository is original work built on top of that method.

## What this work adds over the paper

The adopted method rests on a small number of protocol signatures (S7comm and ATG)
and two coarse network metrics (open-port count and AS type). This project widens
the detection surface along several independent axes:

- **A broader honeypot/implementation study to mine new signatures.** Rather than
  reusing the paper's three signatures, a wide corpus of ICS honeypots and the open
  protocol libraries they embed was reviewed (see *Honeypot corpus examined*), and
  each was inspected for an implementation-default identity a genuine field device
  would never emit. This yields **five new default-identity signatures across four
  additional protocols** (OPC-UA, BACnet, Modbus, MMS) on top of the adopted three —
  for example the FreeOpcUa/pymodbus/bacnet-stack/libiec61850 library defaults.
- **A capability-based (specification-impossibility) signature, not just a string
  match.** Unlike a default-string signature, which flags a *known* placeholder
  value, this rule flags an internal contradiction that a genuine, certified device
  could never produce by specification — regardless of any specific string. The one
  implemented (`SIG_bacnet_id_name_mismatch`) pairs a BACnet `vendor_name` with a
  `vendor_id` that the central ASHRAE registry assigns to a *different*
  organization; a real BACnet device cannot report a registered name against the
  wrong registered id. Because it keys on a spec violation rather than a literal
  default, it is robust to firmware/version drift and to attackers who simply change
  the default strings. Counting it, this work adds **six new signatures** in total
  (five default-identity + one capability-based).
- **Cross-host (relational) indicators, not just per-host tests.** The paper judges
  each host in isolation. This work adds indicators that compare a host *against
  the rest of the population*: identical hardware serials appearing across
  unrelated ASNs (`F_serial_clone`), large byte-identical deployments concentrated
  in low-diversity hosting space (`C_templated_deploy`), and same-AS/same-/24
  co-location clusters sharing an identity (`K_colocation_cluster`). A cloned or
  templated emulator only becomes visible when one host is viewed relative to
  others, so these signs are invisible to a purely per-host classifier.
- **Deeper single-host consistency checks.** Additional per-host indicators exploit
  states that are physically or specification-impossible for a real device:
  conflicting native vendor stacks on one host (`A_vendor_conflict`), an implausible
  number of unrelated native protocols (`E_proto_implausible`), spec-violating
  OPC-UA parameters (`G_opcua_degenerate`), ASHRAE-reserved BACnet vendor IDs
  (`J_bacnet_reserved_id`), and template/placeholder identity fields (B, D, H, N, P).
- **An optional read-only active-probing loop** that both validates the passive
  verdicts on a sample and feeds newly observed honeypot signs back into the
  passive rule set (see [*Optional read-only active-probing validation and
  discovery*](#optional-read-only-active-probing-validation-and-discovery)).

In total the detection surface grows from the adopted 3 signatures + 2 network
metrics to **9 signatures and 15 host-of-interest indicators**.

## Honeypot corpus examined

To ground the signature work, a broad corpus of publicly available ICS honeypots
and the open ICS protocol libraries they embed was reviewed. The **Kind** column
marks each entry as an ICS honeypot in its own right or an ICS protocol library /
reference stack; for the library entries the **Notes** state which honeypot(s)
embed them. A key structural observation is that most of these honeypots wrap
Conpot (GridPot, ICSpot, T-Pot and DiPot all reproduce Conpot's default
identities); the remaining fingerprintable defaults come not from the honeypots'
own code but from the open protocol libraries they embed (snap7, FreeOpcUa,
open62541, node-opcua, pymodbus, bacnet-stack, libiec61850).

| Name | Kind | Notes |
|------|------|-------|
| Conpot | ICS honeypot | Reference low-interaction ICS honeypot; ships templates for S7comm, Modbus, BACnet, EtherNet/IP (ENIP), IEC-104, and others. |
| snap7 | ICS protocol library | Open-source S7 server library; source of the `SNAP7-SERVER` S7comm signature adopted from Mladenov et al. Runs standalone as a soft-PLC and is also embeddable in S7 honeypots. |
| GasPot | ICS honeypot | ATG (Veeder-Root) honeypot; source of the ATG banner heuristics adopted from Mladenov et al. |
| GridPot | ICS honeypot | Wraps Conpot and adds an IEC 61850 / MMS layer via the libiec61850 reference library. |
| HoneyPLC | ICS honeypot | Profile-based honeypot using identities captured from real PLCs; no hard-coded default identity. |
| ICSpot | ICS honeypot | Wraps Conpot; reproduces Conpot defaults. |
| T-Pot | ICS honeypot | Honeypot platform/orchestrator that bundles Conpot among others. |
| DiPot | ICS honeypot | Distributed honeypot built around Conpot. |
| CryPLH | ICS honeypot | High-interaction PLC honeypot (S7/Siemens-oriented). |
| FreeOpcUa (python-opcua / opcua-asyncio) | ICS protocol library | Pure-Python OPC-UA server library; example server ships default application/product URIs. Embedded by OPC-UA honeypots and soft servers. |
| open62541 | ICS protocol library | Open-source C OPC-UA stack; sample server ships a default application URN. Embedded by OPC-UA honeypots and soft servers. |
| node-opcua | ICS protocol library | Node.js OPC-UA stack; sample server ships default product/application names. Embedded by OPC-UA honeypots and soft servers. |
| pymodbus | ICS protocol library | Python Modbus library; example server ships a default MEI vendor identity. Embedded by Modbus honeypots and soft-PLCs. |
| bacnet-stack | ICS protocol library | BACnet reference stack (SourceForge); demo device ships default model/object names. Embedded by BACnet honeypots and DIY BACnet traps. |
| libiec61850 | ICS protocol library | IEC 61850 (MMS) reference library; ships a default IED identity. Packaged/embedded by the GridPot honeypot. |

## Signatures (9 total)

A signature keys on an implementation-default identity string that a genuine field
device would not emit but that a specific honeypot / demo / reference-library
implementation leaves at its default. **A single signature match is, on its own,
sufficient for a HIGH-confidence label.** Three are adopted from Mladenov et al.
(two S7comm defaults — conpot and snap7 — and one ATG banner) and the rest are
contributed by this work,
spanning four additional protocols (OPC-UA, BACnet, Modbus, MMS) plus one
capability-based rule.

| # | Signature / rule | Source | Protocol | Found in | Passive field(s) | Why it is strong evidence |
|---|------------------|--------|----------|----------|------------------|---------------------------|
| B1 | `s7_conpot_default` | Adopted | S7comm | Conpot | `s7.plant_id`, `s7.serial_number` | `plant_id`='Mouser Factory' and `serial_number`='88111222' are Conpot's unmodified S7 template defaults; a genuine CPU never emits them. |
| B2 | `s7_snap7_default` | Adopted | S7comm | snap7 | `s7.system`, `s7.serial_number`, `s7.reserved_for_os` | `system`='SNAP7-SERVER', `serial_number`='S C-C2UR28922012', `reserved_for_os`='MMC 267FF11F' are the snap7 server-library defaults. |
| B3 | `atg_gaspot_banner` | Adopted | ATG | GasPot | ATG service banner (raw bytes / `banner_hex`) | Banner with anomalous consecutive newlines (`\n\n\n\n`) or a malformed date format — GasPot artifacts not produced by a real ATG. |
| 1 | `SIG_opcua_freeopcua` | This work | OPC-UA | FreeOpcUa (python-opcua) | `opc_ua.endpoints[].server.application_uri` / `product_uri` | URI left at the SDK default (`urn:freeopcua:python:server`). A real PLC does not run this pure-Python library; the unchanged example URN marks a demo server. |
| 2 | `SIG_bacnet_stackdemo` | This work | BACnet | bacnet-stack (demo device) | `bacnet.model_name`, `bacnet.object_name` | `model_name`='GNU' or `object_name`='SimpleServer' — the reference stack's demo identity. A shipped product carries the manufacturer's own names. |
| 3 | `SIG_bacnet_id_name_mismatch` | This work | BACnet | Capability-based | `bacnet.vendor_id` vs `bacnet.vendor_name` | A registered ASHRAE vendor NAME paired with a vendor ID the registry assigns to a DIFFERENT organization. This pairing is spec-impossible for a certified device. |
| 4 | `SIG_modbus_pymodbus` | This work | Modbus | pymodbus (example server) | `modbus.mei_response.objects.vendor` / `product_code` / `product_name` | MEI vendor left at the pymodbus example default ('Pymodbus'). A real device reports its true manufacturer. (Confirmed live: probed hosts returned `vendor_name`='Pymodbus'.) |
| 5 | `SIG_mms_libiec61850` | This work | MMS | libiec61850 / GridPot | `mms.vendor`, `mms.model` | IED identity left at the IEC 61850 reference-library default (`vendor` contains 'libiec61850' / `model`='LIBIEC61850'). A real relay reports its own vendor. |
| 6 | `SIG_mms_placeholder` | This work | MMS | Unconfigured template / emulator | `mms.vendor` | MMS vendor left as the literal string 'vendor' — the field name used as its own value. No real IED identifies itself this way. |

## Host-of-interest indicators (15 total)

Unlike a signature, a single indicator is not conclusive; confidence is built from
combinations. Each indicator is graded **STRONG** or **WEAK**. The word WEAK
(rather than "medium") is used deliberately so that the indicator *strength* is
never confused with the final MEDIUM confidence *label*: a STRONG indicator
captures a state that is physically or specification-impossible for a genuine,
productively-operated device, so on its own it is enough for a MEDIUM label; a WEAK
indicator captures a suspicious state that still has a plausible innocent
explanation, so it needs a second independent metric to reach MEDIUM. Two
indicators are adopted from Mladenov et al. (P1, P2) and thirteen (A–K, N, P) are
contributed by this work.

| # | Indicator | Source | Passive field(s) | Grade | Reason for the grade |
|---|-----------|--------|------------------|-------|----------------------|
| P1 | `network_type` | Adopted | IPInfo `as.type` & `company.type` | STRONG (hosting) / WEAK (education) | Genuine industrial devices are implausible in hosting/datacenter space (STRONG); academic residence is only suggestive (WEAK). |
| P2 | `open_port_count` | Adopted | number of exposed services | STRONG (>30) / WEAK (>10) | >30 exposed ports is extremely implausible for a real PLC (STRONG); a merely elevated count (>10) is suggestive only (WEAK). |
| A | `A_vendor_conflict` | This work | native vendor identities across `s7` / `modbus` / `eip` (vs BACnet vendor) | STRONG (both conflicting brands native) → `A_vendor_conflict_strong` / WEAK (only one conflicting brand native, the other BACnet/supervisor-derived) → `A_vendor_conflict_weak` | This indicator only fires when a host presents **two or more conflicting vendor brands** (it never fires on a single vendor). It is STRONG when *every* conflicting brand is asserted by the device's own native control stack (S7/Modbus/EIP), because one physical device cannot natively speak two manufacturers' stacks. It is WEAK when only one side of the conflict is native and the other is derived solely from BACnet/supervisor data, which a legitimate multi-vendor gateway/proxy could aggregate. |
| B | `B_template_id` | This work | `s7.serial_number`, `s7.memory_serial_number`, `eip.identity.serial_number` | STRONG | A placeholder token, or a genuine serial reused as a shared template identifier. A truly unique serial should not recur. |
| C | `C_templated_deploy` | This work | per-(object,fingerprint) cluster size + `autonomous_system.asn` Shannon entropy + IPInfo `as.type` | STRONG (n≥50 & entropy≤1.0) / WEAK (n≥20 & entropy≤1.5) | A large byte-identical deployment with very low AS diversity, concentrated in hosting space, is near-impossible for a real fleet (STRONG); a looser cluster is suggestive (WEAK). Cellular/eyeball ISPs are excluded so real SIM fleets are not caught. |
| D | `D_modbus_placeholder` | This work | `modbus.mei_response.objects.vendor`, `product_code` | STRONG (both placeholder) / WEAK (one) | Both fields at the Conpot placeholder ('Generic Vendor' + 'MODBUS-001') is conclusive (STRONG); only one is weaker (WEAK). |
| E | `E_proto_implausible` | This work | set of native ICS protocols present + `eip.identity.vendor_id` | STRONG (≥4 native protocols) / WEAK (exactly 3, or ≥2 cross-vendor families) | A single device natively speaking ≥4 unrelated vendor stacks is physically impossible (STRONG); 3, or a cross-vendor pair, is implausible but conceivable behind a gateway (WEAK). Omron FINS+EtherNet/IP is whitelisted. |
| F | `F_serial_clone` | This work | `s7.serial_number` / `s7.memory_serial_number` / `eip.identity.serial_number` across ASNs | STRONG (≥3 ASNs) / WEAK (2 ASNs) | The same unique hardware serial in ≥3 independent ASNs is physically impossible = a cloned emulator image (STRONG); 2 ASNs is weaker (WEAK). |
| G | `G_opcua_degenerate` | This work | `opc_ua.max_chunk_size` | WEAK | `max_chunk_size`≤1 violates the OPC-UA spec floor (8192), but a constrained embedded stack could conceivably emit it. |
| H | `H_bacnet_placeholder` | This work | `bacnet.description`, `bacnet.location` | WEAK | Literal template default ('Device Description' / 'Device Location') or `location`='localhost' — commissioning laziness a real device could also exhibit. |
| I | `I_opcua_sdk_default` | This work | `opc_ua.endpoints[].server.application_uri` / `product_uri` / `application_name` | WEAK | open62541 / node-opcua / UA-sample default identity. These SDKs are also embedded in genuine products, so a hit cannot be standalone HIGH — weak by design. |
| J | `J_bacnet_reserved_id` | This work | `bacnet.vendor_id` | WEAK | An ASHRAE-reserved vendor id (555/666/777/888/911/999/1111) implies a non-conformant device, but a cheap device could squat such an id. |
| K | `K_colocation_cluster` | This work | `autonomous_system.asn` + host /24 prefix + `product_uri` / `object_name` | WEAK | Same AS and same /24 co-location cluster. Network proximity alone has legitimate explanations (a single-site fleet). |
| N | `N_eip_services_no_identity` | This work | `eip.services[].service_name` (=COMMUNICATIONS) and absence of `eip.identity` | WEAK | Answers EtherNet/IP ListServices but returns no ListIdentity — a frame-imitating stub; incomplete-but-genuine stacks can exist (usually pairs with E). |
| P | `P_opcua_loopback_endpoint` | This work | `opc_ua.endpoints[].endpoint_url` | WEAK | EndpointUrl advertises a loopback/wildcard address (localhost / 127.0.0.1 / 0.0.0.0 / ::1) a remote client cannot use — a commissioning omission a real server could also leave. |

## Pipeline overview

The detection is a **single unified pipeline**: every ICS host in the full
population is scored once, in one pass, against **one combined pool** of
signatures and host-of-interest indicators. The adopted signals of Mladenov et al.
(their three signatures — conpot/snap7 S7comm defaults and the GasPot ATG banner —
and two network metrics) are folded into the *same* pool at
their matching tiers, together with this work's new signatures and indicators.
The model is monotone — no detection the adopted method alone would make can be
lost — so there is **no residual pre-filtering step**; paper/Censys detections are
retained as a floor and reported as part of the combined total.

Two-tier confidence:

- **HIGH** — any signature fires (the three adopted S7comm/ATG signatures **or** any new one).
- **MEDIUM** — one **STRONG** indicator, **or** two **WEAK** indicators. (Adopted metrics join at their tiers: hosting AS-type and >30 open ports are STRONG; education AS-type and >10 open ports are WEAK.)
- **LOW** — a single WEAK indicator alone (a host of interest, not counted as a honeypot).

Run in order:

| Step | Script | Purpose & Inputs/Outputs |
|------|--------|--------------------------|
| 1 | `paginate_all.py` | **Purpose:** retrieve the full ICS population from the Censys Platform API (paginated). **Inputs:** `query_population.txt` (the published Censys query — the ICS protocol list used for this work's population) and the Censys Platform API (`CENSYS_PAT` / `CENSYS_ORG`). **Output:** `population.json` (the full raw ICS host records). |
| 2 | `enrich_ipinfo.py` | **Purpose:** add company/AS category to every unique IP via the IPinfo *IP-to-Company* MMDB (equivalent to the paper's `2_look_up_as_categories.py`). **Inputs:** `population.json` and the `standard_company.mmdb` IPinfo database. **Output:** `ipinfo_map.json` (`{ ip: {name, domain, type, asn, as_name, as_domain, as_type, country} }`). |
| 3 | `deep_indicators.py` | **The unified classifier.** Defines this work's new detectors and scores every ICS host in a single pass over the full population, against the complete pool of **9 signatures** and **15 host-of-interest indicators** (the 13 new ones, A–K, N and P, plus the 2 adopted network metrics folded in via `paper_signals()`). **Inputs:** `population.json` (and the adopted logic imported from `paper_original_port.py`). **Output:** `deep_findings.csv` (per-host triggered signatures/indicators + confidence tier). |
| 4 | `honeypot_analysis.py` | Characterises the flagged (HIGH+MEDIUM) honeypot set against the full ICS population and renders the result charts. It computes the protocol mix, the per-country host counts and the honeypot proportion per country, the autonomous-system and AS/business-type breakdown, the open-port-count distribution (CDF), and the multi-protocol distribution. **Inputs:** `deep_findings.csv`, `population.json`, and `ipinfo_map.json`. **Outputs:** `.png` charts (150 dpi) under `fig_analysis/` together with an `analysis_stats.json` summary of the underlying numbers. |

Supporting module (imported by the pipeline, not a separate step):

- `paper_original_port.py` — faithful port of the adopted Mladenov et al. classifier; its signals are folded into the unified pool via `paper_signals()`.

### Optional read-only active-probing validation and discovery

The passive pipeline above assigns confidence only from Censys scan data. It never
touches the hosts. The active-probing stage is a **separate, optional, read-only
check**. Every probe only reads a value or asks for status; it never writes,
controls, or changes anything, and because
it never alters a host's state it is safe against production-adjacent ICS. It has
two goals — **validation** (are the passive labels correct?) and **discovery** (which
live signs also have a passive shadow?). Both reuse a single join between the passive
verdict `P` and the active ground-truth class `A`.

**Step 0 — Candidate selection (`select_active_probe_candidates.py`).** The probe
budget is limited, so each batch probes a ranked shortlist of about 100 hosts, not the
whole population. Only hosts the passive pipeline left **below threshold** (`LOW` or
`NONE`) are eligible — the aim is to catch misses, not to re-check hosts already flagged
`HIGH`/`MEDIUM`. Each eligible host is scored by its strongest weak passive signal (a
reserved BACnet id, an OPC-UA SDK default, a shared serial, …), with an exact BACnet
vendor-name/id registry mismatch ranked highest, then ordered by score and by how many
actively-probeable protocols it exposes. The top hundred are written to
`active_probe_top100.csv` with a per-protocol probe bundle. Successive batches exclude
already-probed IPs, and optional filters drop UDP-only or cellular-carrier hosts that
earlier batches showed to be a false-positive trap. **Fourteen such batches were run in
total, probing about 1,400 host records in all.**

**Step 1 — Probe queries (`probe_active.py`).** The prober asks each host for its own
identity using the native read/status request of the protocol on that port:

| Protocol (port) | Read-only request | Fields returned |
|-----------------|-------------------|-----------------|
| BACnet (UDP 47808) | Who-Is → I-Am, then ReadProperty on the Device object | device instance, vendor id, object-name, vendor-name, model-name, description, location, firmware/software revision |
| Modbus/TCP (502) | Read Device Identification (MEI 0x0E, function 0x2B; basic + regular) | vendor name, product code |
| EtherNet/IP (TCP 44818) | ListIdentity + ListServices | serial number, product name, vendor/device ids |
| S7comm (TCP 102) | COTP connect + S7 identification read | module/vendor identity |
| OPC-UA (TCP 4840) | Hello → OpenSecureChannel → GetEndpoints | endpoint URLs, application_uri, ServerStatus/BuildInfo |

**Step 2 — Classify the live answer into `A` (`correlate_active_passive.py`, `classify()`).**
Each answer is mapped to one ground-truth class by fixed rules:

| Class `A` | Rule |
|-----------|------|
| `SUSPECT` | an identity field carries an injected web payload (e.g. `<script>`, SQL `union`), **or** a live device reports a reserved/non-existent vendor id (555, 666, 911, 999, …), **or** the reported vendor name and vendor id belong to different brands |
| `REAL_DEVICE` | a plausible, self-consistent identity: a live BACnet device with a same-family vendor and model, or a Modbus identification returning a genuine vendor and product |
| `ALIVE-NO-ID` | speaks the protocol (e.g. a valid Modbus exception) but returns no identity → weakly real |
| `DEAD` | no protocol response at all → inconclusive, excluded from the contrast |

**Step 3a — Validation (compare `P` with `A`).** Join every probed host by IP.
Agreement (`P` = honeypot and `A` = `SUSPECT`) confirms the label; disagreement
(`P` = honeypot but `A` = `REAL_DEVICE`) rejects it. This is **not** an exhaustive
re-check of every flagged host: the candidate selector deliberately targets
below-threshold hosts, so validation covers a **representative sample** across the
different classification pathways, not the full positive set — a confidence check on the
method, not a statistical precision measurement. On that sample it confirmed positives
and rejected the draft indicators **L** and **M**, whose hosts turned out to be genuine
cellular gateways. Two concrete cases show both directions:

- *Positive confirmation:* hosts flagged for a reserved BACnet vendor id (indicator **J**)
  answered a live Who-Is with `vendor_id 888` / name `Hankyong`; 888 is not an assigned
  ASHRAE vendor id, so a live device using it is an emulator — matching the passive verdict.
- *Cross-host confirmation:* the same EtherNet/IP serial `0x006cb804` appeared passively
  across four autonomous systems, and a read-only ListIdentity to each returned the
  identical serial and product string, confirming a single cloned emulator image
  (indicator **F**) rather than four separate PLCs.

**Step 3b — Discovery (find the passive shadow of `A`).** Group the probed hosts by
their active class `A`, then, for each passive field, contrast the value frequencies
between the `SUSPECT` and `REAL_DEVICE` groups. A value that concentrates in `SUSPECT`
and is absent from real devices is a discriminator; if the same value **also has a
passive shadow** in the Censys data, it becomes a new, purely passive rule for the next
run. This is how indicator **N** (EtherNet/IP ListServices with an empty ListIdentity,
raw `63 00 00 00 00 00 00 00 01 00 00 00`), the WAGO co-location indicator **K**
(`urn:wago-com:opcua-server`), and the open62541 default `application_uri`
(`urn:unconfigured:application`) behind indicator **I** were first found. These three are
the indicators that active probing genuinely *discovered*. By contrast, the
default-identity signatures such as `SIG_modbus_pymodbus` and `SIG_mms_libiec61850` were
derived from analysing known honeypot/emulator software, **not** from probing. Active
probing therefore builds better passive rules; it is not the detector itself.

| Script | Purpose & Inputs/Outputs |
|--------|--------------------------|
| `select_active_probe_candidates.py` | **Purpose:** rank candidate hosts (from the passive findings) into a probe shortlist, tagging each with the protocols/ports to query. **Inputs:** `population.json` and `deep_findings.csv`. **Output:** `active_probe_top100.csv` (the ranked probe shortlist). |
| `probe_active.py` | Pure-Python **read-only** ICS prober (no writes / no control commands) that runs the shortlisted queries and records the raw + parsed identity fields. **Input:** a probe shortlist CSV (e.g. `active_probe_top100.csv`, via `--csv`). **Output:** a results JSON (e.g. `batch1_results.json`, via `--out`). |
| `correlate_active_passive.py` | Correlate the active ground-truth with the passive Censys fields to confirm verdicts and surface new candidate passive indicators. **Inputs:** the probe results JSONs (`batch1_results.json`, `batch2_results.json`) and `population.json`. **Output:** `active_passive_join.json` (per-host active-vs-passive comparison). |
| [`probe_playbook.md`](probe_playbook.md) | Per-protocol read-only probe playbook — the exact queries to run and the honeypot signs to look for. **Input/Output:** documentation only (no data files). |

## Requirements

- Python 3.11+
- `pip install maxminddb matplotlib`
- A [Censys Platform](https://censys-python.readthedocs.io/) Personal Access Token.
- The IPinfo [*IP to Company* database](https://ipinfo.io/products/ip-company-database),
  saved as `standard_company.mmdb` in this directory. **It is commercial data and is
  not redistributed here** — download it with your own IPinfo account.

## Reproduction

```powershell
$env:CENSYS_PAT = "censys_pat_xxx"
$env:CENSYS_ORG = "your-org-id"

py paginate_all.py query_population.txt   # -> population.json
py enrich_ipinfo.py                       # -> ipinfo_map.json
py deep_indicators.py                     # unified classifier -> deep_findings.csv
py honeypot_analysis.py                   # -> figures + analysis_stats.json
```

## Ethics

All active probing is strictly read-only: no write,
control, or function-changing operations are issued. Generated data files contain
real host IP addresses and are intentionally excluded from version control (see
`.gitignore`).

## Acknowledgement

This work adopts and extends the method of Mladenov, Erdődi and Smaragdakis
(EuroS&P 2025). Please cite their paper when using the adopted detection logic.

## License

MIT — see [LICENSE](LICENSE).
