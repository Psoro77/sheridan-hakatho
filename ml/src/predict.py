"""Score the scoreboard with the final model and write top500.csv.

Final order = selected strategy from validation (outputs/selected_features.json):
ITW-phrase rows first (if selected), then k_flag slots for rows with exploit code and the rest for rows
without (if segmented), then everyone else by score.

python -m src.predict
"""
from __future__ import annotations

import json

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd

from .config import ML_DIR, MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, TOP_K, seed_everything
from .data_io import load_scoreboard
from .train import final_order, lr_frame, rank_pct


def load_meta() -> dict:
    return json.loads((MODEL_DIR / "final_meta.json").read_text())


def component_scores(f: pd.DataFrame, meta: dict) -> dict[str, np.ndarray]:
    """Calibrated-ish probability per component."""
    out = {}
    for comp in meta["components"]:
        cols = comp["features"]
        if comp["type"] == "lgbm":
            ms = [lgb.Booster(model_file=str(MODEL_DIR / f"{comp['name']}_{s}.txt")) for s in range(meta["n_models"])]
            out[comp["name"]] = np.mean([m.predict(f[cols]) for m in ms], axis=0)
        else:
            m = joblib.load(MODEL_DIR / f"{comp['name']}.joblib")
            # class_weight='balanced' trains at a 50/50 prior; shift the logit back to the real base rate.
            r = meta["train_pos_rate"]
            logit = m.decision_function(lr_frame(f, cols)) + np.log(r / (1 - r))
            out[comp["name"]] = 1 / (1 + np.exp(-logit))
    return out


def main() -> None:
    seed_everything()
    meta = load_meta()
    f = pd.read_parquet(PROCESSED_DIR / "features_predict.parquet")
    comps = component_scores(f, meta)
    p = np.mean(list(comps.values()), axis=0)
    order_score = (np.mean([rank_pct(v) for v in comps.values()], axis=0) if len(comps) > 1 else p)
    frac = meta.get("flag_frac")
    k_flag = None if frac is None else round(frac * TOP_K)
    order = final_order(order_score, f["n_exploit_flags"] > 0, f["desc_itw_phrase"] == 1, k_flag, meta["itw_first"])

    out = f[["cve_id"]].copy()
    out["p_exploit"] = p
    out["order_score"] = order
    out["rank"] = pd.Series(order).rank(ascending=False, method="first").astype(int).to_numpy()
    out = out.sort_values("rank")
    out.to_parquet(OUTPUT_DIR / "scores_predict.parquet", index=False)

    top = out.head(TOP_K)[["cve_id"]]
    sb = set(load_scoreboard()["cve_id"])
    assert len(top) == TOP_K and top["cve_id"].is_unique and top["cve_id"].isin(sb).all()
    top.to_csv(OUTPUT_DIR / "top500.csv", index=False)
    top.to_csv(ML_DIR / "top500.csv", index=False)
    tf = f.set_index("cve_id").loc[top["cve_id"]]
    print(f"wrote top500.csv ({len(top)} unique IDs, all in scoreboard) | model={meta['experiment']} "
          f"strategy={meta['strategy']} flag_frac={frac} k_flag={k_flag}")
    print(f"top500 composition: itw={int(tf['desc_itw_phrase'].sum())} flagged={int((tf['n_exploit_flags'] > 0).sum())} "
          f"by month={tf['snapshot_month'].value_counts().sort_index().to_dict()}")


if __name__ == "__main__":
    main()
