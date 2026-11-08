"""Compare baselines and model on the valid split -> outputs/metrics.json.

python -m src.evaluate
"""
from __future__ import annotations

import json

import pandas as pd

from .config import OUTPUT_DIR, PROCESSED_DIR
from .metrics import baseline_scores, ranking_report


def main() -> None:
    valid = pd.read_parquet(PROCESSED_DIR / "valid.parquet")
    results = {}
    for name, score in baseline_scores(valid).items():
        results[name] = ranking_report(valid["label"], score)

    model_path = OUTPUT_DIR / "valid_scores.parquet"
    if model_path.exists():
        ms = pd.read_parquet(model_path)
        ms = valid[["cve_id", "label"]].merge(ms, on="cve_id", how="left")
        for col in [c for c in ms.columns if c.startswith("score_")]:
            results[col.removeprefix("score_")] = ranking_report(ms["label"], ms[col])

    # Scoreboard-equivalent depth: top 500 of 72,670 = 0.69% -> k = 243 on valid's 35,280 rows.
    from .config import SCOREBOARD_ROWS, TOP_K
    from .metrics import hits_at_k

    k_eq = round(TOP_K * len(valid) / SCOREBOARD_ROWS)
    ms = valid[["cve_id", "label"]].merge(pd.read_parquet(model_path), on="cve_id", how="left") if model_path.exists() else None
    for name, score in baseline_scores(valid).items():
        results[name][f"hits@{k_eq}(scoreboard_depth)"] = hits_at_k(valid["label"].to_numpy(), score, k_eq)
    if ms is not None:
        for col in [c for c in ms.columns if c.startswith("score_")]:
            results[col.removeprefix("score_")][f"hits@{k_eq}(scoreboard_depth)"] = hits_at_k(
                ms["label"].to_numpy(), ms[col].fillna(-1).to_numpy(), k_eq)
    out = {"split": "valid", "note": "model scores are out-of-time from folds V1 (2025-01..04) and V2 (2025-05..09)",
           "results": results}
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(out, indent=2))
    print(pd.DataFrame(results).T.to_string())


if __name__ == "__main__":
    main()
