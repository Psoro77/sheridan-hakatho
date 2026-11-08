"""Compare baselines and models per validation fold -> outputs/metrics.json.

Each fold (V0, V1, V2) has its own out-of-time model, so scores are only comparable within a fold.
Results are reported per fold at scoreboard depth (k = 500 x rows / 72,670) and summed.

python -m src.evaluate
"""
from __future__ import annotations

import json

import pandas as pd

from .config import OUTPUT_DIR, PROCESSED_DIR, SCOREBOARD_ROWS, TOP_K
from .metrics import baseline_scores, hits_at_k, ranking_report
from .train import FOLDS


def main() -> None:
    ms = pd.read_parquet(OUTPUT_DIR / "valid_scores.parquet")
    score_cols = [c for c in ms.columns if c.startswith("score_")]
    results: dict = {}
    for f, (_, va_name) in FOLDS.items():
        va = pd.read_parquet(PROCESSED_DIR / f"{va_name}.parquet")
        k = max(1, round(TOP_K * len(va) / SCOREBOARD_ROWS))
        m = va[["cve_id", "label"]].merge(ms[ms["fold"] == f].drop(columns=["label", "fold"]), on="cve_id", how="left")
        y = m["label"].to_numpy()
        scores = {**baseline_scores(va), **{c.removeprefix("score_"): m[c].fillna(-1).to_numpy() for c in score_cols}}
        for name, s in scores.items():
            r = results.setdefault(name, {})
            r[f"{f}@{k}"] = hits_at_k(y, s, k)
            r[f"{f}_pr_auc"] = ranking_report(y, s)["pr_auc"]
    for r in results.values():
        r["sum@depth"] = sum(v for key, v in r.items() if "@" in key and not key.startswith("sum"))
    out = {"note": "per-fold out-of-time scores at scoreboard depth; folds V0 (2024-07..12), V1 (2025-01..04), "
                   "V2 (2025-05..09)", "results": results}
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(out, indent=2))
    print(pd.DataFrame(results).T.sort_values("sum@depth", ascending=False).to_string())


if __name__ == "__main__":
    main()
