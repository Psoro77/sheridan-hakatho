"""Score the scoreboard with the final model and write top500.csv.

python -m src.predict
"""
from __future__ import annotations

import json

import lightgbm as lgb
import numpy as np
import pandas as pd

from .config import ML_DIR, MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, TOP_K, seed_everything
from .data_io import load_scoreboard


def load_models() -> tuple[list[lgb.Booster], dict]:
    meta = json.loads((MODEL_DIR / "final_meta.json").read_text())
    models = [lgb.Booster(model_file=str(MODEL_DIR / f"lgbm_final_{s}.txt")) for s in range(meta["n_models"])]
    return models, meta


def prepare(df: pd.DataFrame, meta: dict) -> pd.DataFrame:
    X = df[meta["features"]].copy()
    for c, v in meta.get("caution_medians", {}).items():
        if c in X:
            X[c] = X[c].fillna(v)
    return X


def main() -> None:
    seed_everything()
    models, meta = load_models()
    f = pd.read_parquet(PROCESSED_DIR / "features_predict.parquet")
    X = prepare(f, meta)
    p = np.mean([m.predict(X) for m in models], axis=0)
    out = f[["cve_id"]].copy()
    out["p_exploit"] = p
    out["rank"] = out["p_exploit"].rank(ascending=False, method="first").astype(int)
    out = out.sort_values("rank")
    out.to_parquet(OUTPUT_DIR / "scores_predict.parquet", index=False)

    top = out.head(TOP_K)[["cve_id"]]
    sb = set(load_scoreboard()["cve_id"])
    assert len(top) == TOP_K and top["cve_id"].is_unique and top["cve_id"].isin(sb).all()
    top.to_csv(OUTPUT_DIR / "top500.csv", index=False)
    top.to_csv(ML_DIR / "top500.csv", index=False)
    print(f"wrote top500.csv ({len(top)} unique IDs, all in scoreboard)")
    print(f"score range top500: {out['p_exploit'].iloc[TOP_K - 1]:.4f} .. {out['p_exploit'].iloc[0]:.4f}")


if __name__ == "__main__":
    main()
