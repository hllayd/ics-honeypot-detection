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

## Pipeline overview

The detection is a **single unified pipeline**: every ICS host in the full
population is scored once, in one pass, against **one combined pool** of
signatures and host-of-interest indicators. The adopted signals of Mladenov et al.
(their two signatures and two network metrics) are folded into the *same* pool at
their matching tiers, together with this work's new signatures and indicators.
The model is monotone — no detection the adopted method alone would make can be
lost — so there is **no residual pre-filtering step**; paper/Censys detections are
retained as a floor and reported as part of the combined total.

Two-tier confidence:

- **HIGH** — any signature fires (the two adopted S7comm/ATG signatures **or** any new one).
- **MEDIUM** — one **STRONG** indicator, **or** two **WEAK** indicators. (Adopted metrics join at their tiers: hosting AS-type and >30 open ports are STRONG; education AS-type and >10 open ports are WEAK.)
- **LOW** — a single WEAK indicator alone (a host of interest, not counted as a honeypot).

Run in order:

| Step | Script | Purpose |
|------|--------|---------|
| 1 | `paginate_all.py` | Retrieve the full ICS population from the Censys Platform API (paginated). |
| 2 | `enrich_ipinfo.py` | Add company/AS category to every unique IP via the IPinfo *IP-to-Company* MMDB (equivalent to the paper's `2_look_up_as_categories.py`). |
| 3 | `deep_indicators.py` | **The unified classifier.** Defines all 9 signatures and all 13 new host-of-interest indicators (A–K, N, P), folds in the adopted signals via `paper_signals()`, scores every ICS host in a single pass over the full population, and writes `deep_findings.csv`. |
| 4 | `honeypot_analysis.py` | Reproduce the paper's Section-6 analyses on the resulting honeypot set (figures + `analysis_stats.json`). |

Supporting module (imported by the pipeline, not a separate step):

- `paper_original_port.py` — faithful port of the adopted Mladenov et al. classifier; its signals are folded into the unified pool via `paper_signals()`.

Optional read-only active-probing validation:

| Script | Purpose |
|--------|---------|
| `select_active_probe_candidates.py` | Rank residual hosts for active probing. |
| `probe_active.py` | Pure-Python **read-only** ICS prober (no writes / no control commands). |
| `correlate_active_passive.py` | Correlate active ground-truth with passive Censys fields to discover missed indicators. |
| `probe_playbook.txt` | Read-only probe playbook (authorized targets only). |

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

py paginate_all.py                 # -> pop_all.json
py enrich_ipinfo.py                # -> ipinfo_map.json
py deep_indicators.py              # unified classifier -> deep_findings.csv
py honeypot_analysis.py            # -> figures + analysis_stats.json
```

## Ethics

All active probing is strictly read-only against authorized targets: no write,
control, or function-changing operations are issued. Generated data files contain
real host IP addresses and are intentionally excluded from version control (see
`.gitignore`).

## Acknowledgement

This work adopts and extends the method of Mladenov, Erdődi and Smaragdakis
(EuroS&P 2025). Please cite their paper when using the adopted detection logic.

## License

MIT — see [LICENSE](LICENSE).
