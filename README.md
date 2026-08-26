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

Passive detection pipeline (run in order):

| Step | Script | Purpose |
|------|--------|---------|
| 1 | `paginate_all.py` | Retrieve the full ICS population from the Censys Platform API (paginated). |
| 2 | `enrich_ipinfo.py` | Add company/AS category to every unique IP via the IPinfo *IP-to-Company* MMDB (equivalent to the paper's `2_look_up_as_categories.py`). |
| 3 | `paper_original_port.py` | Faithful port of the adopted Mladenov et al. classifier (HIGH/MEDIUM honeypot labelling). |
| 4 | `build_residual.py` | Build the **residual** set: ICS hosts that neither Censys nor the paper method flagged. |
| 5 | `indicators.py` | Two new passive indicators (vendor conflict, template identifier) over the residual set. |
| 6 | `deep_indicators.py` | Full set of new passive signatures + indicators + the unified monotone classifier. |
| 7 | `honeypot_analysis.py` | Reproduce the paper's Section-6 analyses on the resulting honeypot set (figures + `analysis_stats.json`). |

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
py build_residual.py               # -> residual.json
py deep_indicators.py              # -> deep_findings.csv
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
