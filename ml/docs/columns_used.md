# Columns used, excluded, and why

Living document for the Devpost write-up. See `CLAUDE.md` section 4 for the leakage rules.

## Time rule
Every feature of a CVE is computable at the end of its `snapshot_month` (= publish month, as in the
scoreboard). Every historical rate uses only KEV entries with `date_added` <= the row's
**history cutoff** = Dec 31 of the year before publication (2024 rows: 2023-12-31, 2025 rows:
2024-12-31, scoreboard 2026 rows: 2025-12-31), and only CVEs published by that cutoff.
`build_dataset.py` asserts that all positives were added to KEV after their snapshot month and that
every history cutoff is before publication.

## Used

| Source | Column | Feature(s) | Why it's safe |
|---|---|---|---|
| vulnerabilities | `description` | Granite embeddings → `kev_sim_max`, `kev_sim_mean_top5`, `text_lr_score`, `cluster_kev_rate`; keyword flags `kw_*`; `desc_len` | Written at publication |
| vulnerabilities | `published` | snapshot month, `days_to_label_cutoff`, history cutoff | Known at publication |
| vulnerabilities | `assigner` | `assigner_kev_count`, `assigner_kev_rate`, `assigner_n_hist` (org from email domain or CNA UUID) | Known at publication; rates use past labels only |
| known_exploited | `vendor`, `product`, `date_added` | Vendor and product names matched in the description (vocabulary rebuilt per history cutoff from past KEV only) → `desc_vendor_*`, `desc_product_*`, 12-month `*_kev_12m` heat; labels | Only entries with `date_added` <= history cutoff for features |
| exploit_signals_2024/2025, scoreboard | `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github` | `epss_pct` (percentile **within snapshot month**), flags, `n_exploit_flags` | Value at snapshot month only; raw EPSS not used across months (model changes 2025-03, 2026) |

## Caution group (ablated, see `outputs/ablation.csv`)

| Column | Feature | Concern |
|---|---|---|
| CVSS components, `cvss3_score`, `cvss4_score` | ordinal `cvss_*`, scores | NIST analyses attacked CVEs first, so presence/values of NIST scores can reflect later analysis. Tested both raw and median-imputed (removes the missingness signal) |
| `cwe_ids` | top-20 CWE one-hot, `cwe_kev_rate` (past only) | Same: CWE often filled in by NIST analysis |
| `description` | `desc_itw_phrase` ("exploited in the wild", "aware of a report", ...) | Vendors (Apple, Google) write this at publication, but descriptions can be edited later |

Decisions (two-fold validation, `outputs/experiments.csv`):
- **CVSS / CWE: rejected (leakage).** They give +4 to +9 hits, but 100% of exploited CVEs are NIST-analysed
  with no blank CVSS/CWE (vs 65% and ~4% of the rest), and only 19% of 2026 scoreboard scores are NIST-sourced
  vs 37 to 48% in training. The gain reflects NIST's post-attack analysis. (`cvss3_source`/`nvd_status` were
  used only for this diagnostic, never as features.)
- **`desc_itw_phrase`: kept as a ranking rule** (these rows go first). +3 to +5 hits on both folds for every
  model; the phrases come from CNAs at publication (VulnCheck, MITRE, GitHub, Meta).

## Never used

| Column | Reason |
|---|---|
| `nvd_status`, `last_modified` | Reflect NIST analysis done after attacks |
| `n_references`, `n_affected_cpes` | Grow after attacks (news, advisories, NIST CPE analysis) |
| `cvss3_source` | NIST's score replaces the vendor's when NIST analyses, so the source reveals analysis |
| `references.csv`, `affected_products.csv` | Added/curated after publication; exploration only |
| "score is blank" / "CWE is blank" indicators | Direct proxy for "NIST hasn't analysed this" |
| KEV `short_description`, `known_ransomware_use` | Written by CISA after exploitation (KEV `vendor`/`product` names are used only as a matching vocabulary from entries added before the history cutoff) |

## Embedding model
IBM Granite `ibm-granite/granite-embedding-30m-english` (30M params, 384-dim), `max_seq_length=128`.
We first used `granite-embedding-small-english-r2` (47M, ModernBERT), but on our CPU-only laptop it
embedded 12 texts/s (about 5.5 h for 235k descriptions) against 63 texts/s for the 30M model (about 1 h).

## Other features added in round 2
- `prior_lr_score`: past-only LR on Granite embedding + keyword flags + one-hot vendor/product/assigner,
  fit on CVEs published 2022 → history cutoff; scored rows are published after the cutoff.
- Sibling features (`sib_*`): same assigner, same snapshot month, published within ±3 days; only the
  siblings' snapshot-time values (text score, flags, ITW phrase, EPSS). Sibling KEV status is NOT used.
