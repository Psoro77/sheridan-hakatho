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
