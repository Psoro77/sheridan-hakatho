# Aegis: ML component (CLAUDE.md)

Context for any AI coding agent working on the **machine learning part** of Aegis, our submission to the
**[IBM] Before the Breach** track at Sheridan Datathon 2026 (final deadline **Sunday Nov 8, 12:00 PM EST**).

Read this whole file before writing code. The rules in "Leakage rules" are not optional.

---

## 1. What we are building

Aegis predicts which newly published vulnerabilities (CVEs) attackers will exploit, so security teams know
what to fix first and why. The ML part produces:

1. **`top500.csv`**: the 500 CVEs from `scoreboard_2026.csv` most likely to be added to CISA KEV.
   One column, header `cve_id`. **This is scored by the judges.**
2. **A score for every scoreboard CVE** (`predictions.parquet`): probability, rank, tier, top reasons.
   This feeds the app (stored in TigerData) and the Gemini or Granite explanations.
3. **Evidence for the pitch**: validation metrics vs baselines, feature importance, vulnerability clusters
   with their KEV rates, and an ablation table.

Baselines to beat (hits in top 500 on the 2026 scoreboard): **CVSS-first 7, EPSS-first 6,
exploit code then EPSS 8.**

Judging: Discovery 35%, Data Use 25%, Communication 25%, Impact 15%. "Data Use" explicitly rewards
showing we checked for leakage, so log every decision.

---

## 2. Required technology

- **IBM Granite embeddings** (Hugging Face `ibm-granite`) for CVE descriptions. This is our mandatory IBM tech
  in the ML part. Confirm the exact model ID on Hugging Face; prefer the smallest English or multilingual
  R2 embedding model (under 100M parameters, runs on CPU).
- **Entire** is enabled on this repo: work in small commits so sessions and checkpoints stay readable.
  Record project rules and decisions in Entire Brain (especially the leakage rules below).
- **TigerData** (Postgres) is the app's database. ML writes Parquet; `export_tigerdata.py` loads it.
- Gemini or Granite is used for explanation text. That lives in the app, not in this ML package. ML only
  supplies structured reasons.

---

## 3. Data

All raw files are in `ml/data/raw/` (gitignored, about 850 MB). Join on `cve_id`. `weakness_types.csv`
matches entries of `cwe_ids` (split on `;`). If a CSV reader fails, set quote and escape characters to `"`.
Read version columns as text. Load only the columns you need.

| File | Use |
|---|---|
| `vulnerabilities.csv` | Features: description, published, assigner, CVSS parts, CWE |
| `known_exploited.csv` | **Labels** (KEV up to 2025-12-31) and vendor history |
| `exploit_signals_2024.csv`, `exploit_signals_2025.csv` | Monthly EPSS and exploit flags to build training rows |
| `scoreboard_2026.csv` | Rows to predict (EPSS and flags already frozen at `snapshot_month`) |
| `weakness_types.csv` | Readable CWE names |
| `affected_products.csv`, `references.csv` | **Do not use for features** (see leakage rules). OK for exploration only |

Known data quirks:
- The CVE ID year is the reservation year, not the publish year. **Always use `published`.**
- EPSS changed models in March 2025 (and v5 arrived mid-2026). **Never use raw EPSS across months; use
  the percentile rank within its month.**
- February 2025 signals are missing about 14,500 CVEs. Treat as missing, not zero.
- About 11,800 IDs in the signals files are rejected and not in `vulnerabilities.csv`. Drop them.
- 62 KEV entries have `date_added` before `published` (zero-days). They are excluded automatically by the
  "not in KEV at end of snapshot month" rule.
- June 2026 signals are missing; the scoreboard uses July as `snapshot_month` for June CVEs.

---

## 4. Leakage rules (must follow)

NIST files are today's versions (`last_modified` mid-2026 or later for every row). NIST analyzes attacked
vulnerabilities first, and news and research links are added after attacks. Any feature that reflects
"NIST has looked at this" or "people wrote about this later" is leakage.

**Never use as features:**
- `nvd_status`, `last_modified`, `n_affected_cpes`, `n_references`
- `cvss3_source` (NIST's score replaces the vendor's when NIST analyzes, so the source reveals analysis)
- anything from `references.csv` or `affected_products.csv`
- "is the score blank" or "is the CWE blank" indicator features

**Use with caution (ablation required, see section 7):**
- CVSS component values (`attack_vector`, `privileges_required`, `user_interaction`, impacts, `cvss4_*`)
- `cwe_ids`
- description phrases that state exploitation ("exploited in the wild", "aware of a report",
  "actively exploited"). Vendors like Apple or Google sometimes write these at publication, which is
  legitimate, but they may also have been edited in later. Build them as a separate flagged feature
  `desc_itw_phrase`, measure it, and document the decision.

**Safe:**
- `description` text (embeddings, keywords), `published`, `assigner`
- scoreboard and signals EPSS percentile and exploit flags **at the snapshot month only**
- KEV history **strictly before** the prediction period (vendor and CWE attack rates)

**Time rule:** every feature for a CVE must be computable at the end of its snapshot month. Any
"historical rate" (vendor KEV rate, cluster KEV rate) must only use labels known before the period
being predicted.

Keep `docs/columns_used.md` up to date: columns used, columns excluded, and why. It goes into the
Devpost write-up.

---

## 5. Building the dataset (mirror the benchmark exactly)

The scoreboard predicts each CVE **at its publish month**. Training rows must look the same.

For a period P:
1. Universe = CVEs from `vulnerabilities.csv` with `published` in P (drop rejected IDs).
2. `snapshot_month` = publish month (if signals are missing for that month, use the next month, as the
   scoreboard does for June 2026).
3. Drop CVEs already in KEV by the end of `snapshot_month`.
4. Join EPSS and flags from the signals file at `snapshot_month`. Missing means NaN EPSS and 0 flags
   (same as the scoreboard).
5. **Label** = 1 if `date_added` in KEV is after the end of `snapshot_month` and on or before the label
   cutoff, else 0.

Splits:

| Split | Published | Label cutoff | Purpose |
|---|---|---|---|
| train_A | 2024-01 to 2024-12 | 2024-12-31 | train for validation |
| valid | 2025-01 to 2025-09 | 2025-12-31 | **model selection** (mirrors scoreboard: 9 months, roughly 1 to 11 months of horizon) |
| train_final | 2024-01 to 2025-09 | 2025-12-31 | final model |
| predict | `scoreboard_2026.csv` | (judges: 2026-11-04) | submission |

History features for `valid` use KEV up to 2024-12-31; for `predict` use KEV up to 2025-12-31.
Optionally add 2021 to 2023 CVEs to training for text and vendor features (EPSS is missing there; set it to NaN).

Save each split to `ml/data/processed/*.parquet`.

---

## 6. Features

| Group | Features | Notes |
|---|---|---|
| Exploit signals | `epss_pct` (percentile within month), `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `n_exploit_flags` | Maps to BOD 26-04 "exploit automation" |
| Vendor | `vendor` from `assigner` plus description matching against vendor names in KEV history; `vendor_kev_rate` (smoothed, past only); `vendor_kev_count` | Usually the strongest signal |
| Product type | keywords: vpn, firewall, gateway, router, edge, appliance, exchange, sharepoint, citrix, load balancer, file transfer, cms, plugin | Edge and internet-facing devices dominate KEV |
| Attack type | keywords: unauthenticated, remote code execution, command injection, authentication bypass, deserialization, path traversal, sql injection, privilege escalation | Maps to "technical impact" |
| Text similarity | `kev_sim_max`, `kev_sim_mean_top5`: cosine similarity of the Granite embedding to past KEV descriptions | Past-only KEV set |
| Text model | `text_lr_score`: logistic regression on the Granite embeddings (train-period fit), used as a single feature | Avoids feeding hundreds of embedding columns to the trees |
| Clusters | `cluster_id`, `cluster_kev_rate` (smoothed, past labels only) | See below |
| CVSS (caution) | attack vector, privileges, user interaction, scope, C/I/A impact | Ablate |
| CWE (caution) | top CWEs one-hot, `cwe_kev_rate` past only | Ablate |
| Time | `days_to_label_cutoff` or publish month index | Earlier CVEs have more time to be added |

Smoothing for any rate: `(hits + m * prior) / (count + m)` with `m = 20`.

### Clustering
- Granite embeddings, then UMAP to about 15 dimensions, then **HDBSCAN** (`sklearn.cluster.HDBSCAN`,
  `min_cluster_size` about 50). Noise (`-1`) gets the global prior.
- Fallback if slow: **MiniBatchKMeans** with k of about 150 (has `predict`).
- Do not use plain DBSCAN (no `predict`, `eps` cannot be tuned in high dimensions).
- Fitting clusters on all descriptions (including 2026) is fine (unsupervised, text known at
  publication). Rates must use past labels only.
- Name each cluster with the LLM from 10 sample descriptions and save to `outputs/clusters.csv`
  (`cluster_id, name, size, kev_rate_train, n_scoreboard`). This feeds the "Discovery" slide.

### Embeddings
- Embed the description of every CVE in train, valid and predict once. Cache to
  `ml/data/processed/embeddings.npy` plus an ID index. Never recompute if the cache exists.
- Run on GPU (Colab or Vultr) if available; CPU works but start it early.

---

## 7. Model and evaluation

**Model:** LightGBM or XGBoost binary classifier. Extreme class imbalance: use
`scale_pos_weight` (negatives over positives) and early stopping on validation.
Start with a logistic regression baseline to sanity-check the pipeline.

**Primary metric: `hits@500`** = number of label-1 CVEs among the 500 highest scores in `valid`.
Also report `hits@100`, `hits@1000`, PR-AUC. **Never use accuracy.**

**Always compare against baselines on the same `valid` set:** CVSS-first, EPSS-first,
exploit-flags-then-EPSS. Save to `outputs/metrics.json`.

**Ablation table** (`outputs/ablation.csv`), each row = hits@500 on `valid`:
1. EPSS and flags only
2. plus vendor and keyword features
3. plus Granite text features (`kev_sim_*`, `text_lr_score`)
4. plus clusters
5. plus CVSS and CWE (caution group)
6. plus `desc_itw_phrase`

Keep caution features only if they help **and** their gain does not come from missingness patterns.
Record the decision in `docs/columns_used.md`.

**Final ranking for `top500.csv`:** model probability only (no environment factor). Sort descending,
take 500, write `cve_id`. Verify exactly 500 unique IDs, all present in the scoreboard.

**Seed everything** (`seed = 42`). Results must be reproducible with one command.

---

## 8. Explanations and app outputs

- Use SHAP (`shap.TreeExplainer`) on the final model. For each scoreboard CVE, store the top 3 positive
  drivers as human-readable reasons, for example "Vendor attacked 14 times before",
  "Unauthenticated remote code execution", "Similar to past KEV entries (0.82)".
- Tier: `Fix now` (top 100), `This week` (101 to 500), `Monitor` (rest). Adjust after seeing the score distribution.
- Map features to CISA BOD 26-04 factors in the output so the UI can use professional terms:
  `exploit_automation` (exploit flags, EPSS pct), `kev_likelihood` (model probability),
  `technical_impact` (CVSS impact and attack keywords). `asset_exposure` comes from the user's
  inventory in the app, not from ML.
- The app computes the combined priority = likelihood x impact x exposure. ML only provides likelihood and impact.

`outputs/predictions.parquet` schema:
`cve_id, published, snapshot_month, vendor, p_exploit, rank, tier, epss_pct, exploit_flags,
impact_score, cluster_id, cluster_name, reasons (JSON list of 3 strings), shap_top (JSON)`

---

## 9. Repo layout

```

```

Commands (one per step, each idempotent):
```
python -m src.build_dataset
python -m src.embed
python -m src.cluster
python -m src.features
python -m src.train --split train_A --eval valid
python -m src.evaluate
python -m src.train --split train_final
python -m src.predict
python -m src.explain
python -m src.export_tigerdata
```

Stack: Python 3.11, pandas + pyarrow, scikit-learn 1.3 or later, lightgbm (or xgboost),
sentence-transformers, umap-learn, shap, psycopg. Pin versions in `requirements.txt`.

---

## 10. Working rules for agents

- Before any feature work, re-read section 4. If a new feature might leak, ask the team or add it to the
  caution group and ablate it. Do not silently add it.
- Never read the scoreboard's future: no lookups beyond `snapshot_month`, no KEV after the cutoff for the split.
- Do not tune on the scoreboard (it has no labels; any "tuning" there would be guessing).
- Print shapes, positive counts and date ranges after building each split; they are the first check
  when something looks wrong.
- Prefer simple, explainable features over clever ones. Every top feature must be explainable in one
  sentence on a slide.
- Write notable findings (surprising vendors, clusters, CWE patterns) to `docs/findings.md` as you go.
  The pitch needs one strong "Discovery".

## 11. Time plan (Saturday night to Sunday)

1. Dataset splits and baselines on `valid` (first, everything depends on it)
2. Start embeddings early (long job), build vendor and keyword features meanwhile
3. LightGBM v1, then hits@500 vs baselines
4. Text similarity and clusters, then ablation
5. Final train, `top500.csv` (**freeze by 8:00 AM Sunday**)
6. SHAP reasons, predictions export, findings for slides