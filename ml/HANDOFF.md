# Handoff: ML → app / UI

What the ML side gives you, where to find it, and what to be careful about in the UI.
The ML is finished. The submission (`top500.csv`) is frozen. You should not need to rerun anything.

## 1. What you get

One row per CVE on the 2026 scoreboard (72,670 rows), with:
- the likelihood that it gets exploited (added to CISA KEV),
- a rank and a tier,
- three plain-English reasons,
- the inputs for the BOD 26-04 priority.

It comes as two tables. You can read them from the database or from files.

| Source | Where |
|---|---|
| TigerData (Postgres) | tables `cve_predictions` and `vuln_clusters`, loaded by `python -m src.export_tigerdata` (needs `TIGERDATA_URL`) |
| Files | `ml/outputs/predictions.parquet`, `ml/outputs/clusters.csv` |

**The Parquet file is gitignored.** You won't find it after a `git pull`. Ask the ML side to run the export
into TigerData, or to send you the file directly. `clusters.csv` is in git.

## 2. `cve_predictions`: one row per CVE

| Column | Type | What it means | UI notes |
|---|---|---|---|
| `cve_id` | text, primary key | e.g. `CVE-2026-18886` | link to `https://nvd.nist.gov/vuln/detail/<id>` |
| `published` | date | publication date | |
| `snapshot_month` | text `YYYY-MM` | the month whose data we used | June CVEs show `2026-07` (June data is missing upstream) |
| `vendor` | text | best guess of the vendor | can be a CNA name like "Mitre", "Github", "Vulncheck" or `CNA 1a2b3c4d` when unknown |
| `p_exploit` | float 0-1 | model probability | very skewed: median 0.0001, top about 0.97. Show the rank or tier, not the raw % |
| `rank` | int 1-72,670 | 1 = most likely | ranks 1-500 = our submitted top 500 |
| `tier` | text | `Fix now` (rank 1-100), `This week` (101-500), `Monitor` (rest) | the main badge |
| `epss_pct` | float 0-1 or null | EPSS percentile within its month | null = no EPSS yet. Show "top X%" |
| `exploit_flags` | JSON list | any of `exploitdb`, `metasploit`, `nuclei`, `poc_github` | show as chips. `[]` = no public exploit code |
| `impact_score` | float 0-1 | technical impact (CVSS or attack keywords) | display only, NOT used in the ranking |
| `cluster_id` | int | vulnerability family; `-1` = no family | join to `vuln_clusters` |
| `cluster_name` | text | keyword label of the family | raw keywords, see §4 |
| `reasons` | JSON list of up to 3 strings | why it ranks high, e.g. `"5.1% of past ServiceNow CVEs were exploited (6x typical)"` | show as-is. Low-ranked CVEs still get reasons, so show them mainly for the top tiers |
| `shap_top` | JSON object | the model weight behind each reason | debugging / tooltip only |
| `kev_likelihood` | float 0-1 | percentile of `p_exploit` | **use this** as the BOD "likelihood" factor |
| `technical_impact` | float 0-1 | same as `impact_score` | BOD "impact" factor |
| `exploit_automation` | float | sum of model weights from EPSS + exploit flags | **can be negative and is not 0-1**. Don't show it as a %. Prefer `exploit_flags` + `epss_pct` in the UI |

Not in the table: the **description**. If you want to show it or feed it to Gemini / Granite, the processed
ML file `ml/data/processed/predict.parquet` has `cve_id, description`. That file is also gitignored, so ask us.
You can also load `vulnerabilities.csv` from the raw data.

## 3. Priority = likelihood × impact × exposure (app side)

ML provides `kev_likelihood` and `technical_impact`. `asset_exposure` comes from the user's inventory in the
app (e.g. internet-facing = 1.0, internal = 0.5, not owned = 0). Compute the combined score in the app.
**Don't write it back into `rank`.** `rank` is the model's order and must match `top500.csv`.

## 4. `vuln_clusters`: the "Discovery" families

Columns: `cluster_id, name, size, kev_hits_train, kev_rate_train, n_scoreboard, lift_vs_prior, n_train`.
- `kev_rate_train` = share of 2022-2025 CVEs in that family that reached KEV. `lift_vs_prior` = how many times
  the average rate. Top families: Chrome/Chromium (about 15x), Windows DWM / kernel EoP, Ivanti Connect Secure,
  Apple iOS, Telerik deserialization, Oracle WebLogic.
- `name` is raw keywords ("security severity, chromium security, ..."). Some names repeat. For the slide or UI,
  generate a short name with the LLM from `ml/outputs/cluster_samples.json`, which holds 10 sample descriptions
  per cluster (that is in the spec as an optional step).
- 37% of CVEs belong to no family (`-1`). Label them "Unclustered", not as a family.

## 5. Numbers you may show (and how to say them)

| Claim | Number |
|---|---|
| 2025 validation, at the same depth as the scoreboard | **24 of 52** exploited CVEs found vs **15** for "exploit code first, then EPSS" |
| 2026 scoreboard (judges' list, checked after the fact) | **19 of 60** vs baselines **7** (CVSS), **6** (EPSS), **8** (exploit code) |
| IBM Granite text embeddings | removing them costs about 4-5 of those validation hits |
| Base rate | about 1 in 650 new CVEs is later confirmed exploited |

Say "about 2.4x the best standard ranking". Don't promise precision. The confidence intervals are wide
(about ±6 hits). The 2026 answer key was looked at after each round; that is disclosed in
`docs/findings.md`. Keep the wording consistent with it.

## 6. Things NOT to do in the UI
- Don't present `p_exploit` as a calibrated "97% chance". Use the tier or "top N".
- Don't show CVSS as a reason for the ranking. The model does not use CVSS; it's leakage-prone (see
  `docs/columns_used.md`).
- Don't re-rank the top 500 in anything labelled "model ranking". It must match the submitted `top500.csv`.

## 7. Where to look / who to ask
- Leakage decisions and columns: `ml/docs/columns_used.md`.
- Findings for the slides: `ml/docs/findings.md` (round 4 table = numbers to quote; round 5 = what we tried).
- Pipeline: `ml/README.md`, `bash ml/run_all.sh`. Not needed for the UI.
- Branch: the latest ML work is on `ml-round5` (not yet merged into `main`). `top500.csv` is identical on both.
