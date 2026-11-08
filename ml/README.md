# Aegis ML

Predicts which newly published CVEs will be added to CISA KEV. See `../CLAUDE.md` for the spec.

```
python -m venv ../.venv && ../.venv/Scripts/pip install -r requirements.txt
bash run_all.sh        # or run the steps in it one by one
```

Raw data defaults to `../IBM/data/data` (override with `AEGIS_RAW_DIR`).

Outputs (`outputs/`): `top500.csv` (submission), `predictions.parquet` (app), `metrics.json`,
`ablation.csv`, `clusters.csv`, `feature_importance.csv`, `shap_importance.csv`.
Docs: `docs/columns_used.md` (leakage decisions), `docs/findings.md` (discoveries).
