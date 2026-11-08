# Findings log

Notable results for the pitch ("Discovery"). Newest at the bottom.

## Dataset (build_dataset)
- train_A: 39,868 CVEs (2024), **40 positives** (added to KEV after their publish month, by 2024-12-31).
- valid: 35,280 CVEs (2025-01 to 2025-09), **52 positives** by 2025-12-31.
- train_final: 75,148 CVEs, 119 positives. Scoreboard: 72,670 CVEs.
- Roughly 85 CVEs per year are added to KEV within their own publish month; like the scoreboard,
  these are dropped (they were known before the snapshot).
- Base rate is about 0.15%: fewer than 1 in 650 new CVEs is later confirmed exploited.

## Baselines on valid (hits@500 of 52 positives)
- CVSS first: 8, EPSS first: 8, public exploit code then EPSS: 18.
- On 2026 the track reports 7 / 6 / 8, so valid is easier than the scoreboard for flag-based ranking
  (fewer 2026 rows have flags at snapshot, or flags are noisier).

## What the 2025 positives look like
- 5 of 52 had **no EPSS score at the end of their publish month** (e.g. a Chrome V8 zero-day published
  late in the month). EPSS-only ranking can never find these; vendor and text can.
- Recurrent vendors: Ivanti (3), SysAid (2), Kentico (2), Samsung (2), Adobe (2), Microsoft (2),
  TeleMessage (2), Dassault 3DS (3). Several come in pairs/triples published the same day (chained bugs).
- `desc_itw_phrase` ("exploited in the wild", "aware of a report"...): 24 valid CVEs, **5 positives
  (21% vs 0.15% base rate)**. Kept in the caution group; 19 scoreboard CVEs carry the phrase.

## Modelling notes
- With ~40 positives, a default LightGBM with `scale_pos_weight = neg/pos` (~1000) memorised the
  positives: adding vendor features *reduced* hits@500 from 18 to 7 and early stopping on valid AP
  stopped after 2 to 10 rounds. Fix: depth-2 trees, `scale_pos_weight = sqrt(neg/pos)`, L2 = 10,
  fixed 300 rounds, 5-seed bagging.
- `text_lr_score` is trained on **all CVEs published 2022 → history cutoff** labelled with past KEV
  (hundreds of positives), not on the split itself, so it is past-only and needs no out-of-fold trick.

## Round 2 (2026-11-08 night): what moved the needle
Validation now uses **two folds**: A = train_A → valid (52 positives), B = trainB (2024-01..2025-03,
labels to 2025-03-31) → validB (2025-04..09, 32 positives). Full table: `outputs/experiments.csv`.

- **58% of exploited CVEs had no public exploit code at snapshot** (30 of 52 on valid). Flag-based
  ranking can never find them; EPSS gets 0 hits in the top 1,000 among them.
- **Segmented top 500** (350 slots for CVEs with exploit code, 150 for those without): +2 to +3 hits on both
  folds for every model. The tree couldn't learn "different rules per segment" from 40 positives.
- **"Exploited in the wild" rows first**: +3 to +5 hits on both folds for every model. Phrases come from
  CNAs at publication (VulnCheck, MITRE, GitHub advisories, Meta), not later edits.
- **Nuclei templates**: 8% KEV rate vs 3% for GitHub PoCs on valid; splitting flags lets the LR weight them.
- **Product matching** (KEV product names like "FortiOS", "Connect Secure", "Windows") raised vendor
  coverage from 36% to 45-49%; vocabularies are built per history cutoff (past KEV only).
- **Prior model** (Granite embedding + keywords + one-hot vendor/product/assigner, trained on 2022 → cutoff
  history with 246 to 605 positives) is the strongest single LR feature.
- **Leakage caught**: adding CVSS/CWE gave the best-looking result (55 vs 51), but 100% of exploited CVEs are
  NIST-analysed with no blank CVSS/CWE vs 65% / ~4% of the rest, and 2026 has 19% NIST-sourced scores vs
  37 to 48% in training. Rejected; kept in the table as a reported leakage test.

| Model (strategy) | Fold A | Fold B | Sum |
|---|---|---|---|
| Exploit code then EPSS (baseline) | 18 | – | – |
| v2 LightGBM core (plain) | 19 | 15 | 34 |
| Compact LR v2 (plain) | 22 | 18 | 40 |
| **Compact LR v2 (segmented + ITW first), selected** | **28** | **23** | **51** |
| LightGBM + caution CVSS/CWE (rejected, leakage) | 30 | 25 | 55 |

Post-hoc 2026 check (60 positives, report only, run once after selection): baselines 7 / 6 / 8;
v1 9, v2 11, **round 2 submitted top500: 17**. For transparency: the same model ranked by plain
probability (no segment/ITW rule) would get 19 on 2026; on validation it was clearly worse (40 vs 51),
so we kept the fold-selected strategy rather than pick by the answer key.
