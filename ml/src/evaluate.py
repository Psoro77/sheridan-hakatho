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

    out = {"split": "valid", "results": results}
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(out, indent=2))
    print(pd.DataFrame(results).T.to_string())


if __name__ == "__main__":
    main()
