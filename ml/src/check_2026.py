"""POST-HOC CHECK ONLY: score rankings against live 2026 KEV labels (IBM/data/external/kev_live).

These labels are the answer key. They are read ONLY here; nothing in the training or selection
pipeline imports this module, and it is not part of run_all.sh. Model choices are made on `valid`
before running this; results are reported, never used to pick a model.

python -m src.check_2026
"""
from __future__ import annotations

import json

import pandas as pd

from .config import OUTPUT_DIR, REPO_DIR, TOP_K
from .metrics import baseline_scores, ranking_report

LABELS = REPO_DIR / "IBM" / "data" / "external" / "kev_live" / "scoreboard_2026_with_kev_labels.csv"
JUDGE_CUTOFF = "2026-11-04"


def candidate_report(sb: pd.DataFrame) -> dict:
    """REPORT ONLY, run after selection is frozen: every LR candidate refit on train_final and ranked
    with ITW first, so the write-up can show the 2026 number of the candidates we did NOT pick too."""
    from .config import PROCESSED_DIR
    from .train import LR_EXPERIMENTS, MIN_TRAIN_HORIZON, final_order, lr_frame, make_compact_lr

    tr = pd.read_parquet(PROCESSED_DIR / "features_train_final.parquet")
    tr = tr[tr["days_to_label_cutoff"] >= MIN_TRAIN_HORIZON].reset_index(drop=True)
    f = (pd.read_parquet(PROCESSED_DIR / "features_predict.parquet").drop(columns=["label"])
         .merge(sb[["cve_id", "label"]], on="cve_id"))
    out = {}
    for name, cols in LR_EXPERIMENTS.items():
        m = make_compact_lr().fit(lr_frame(tr, cols), tr["label"].astype(int))
        o = final_order(m.decision_function(lr_frame(f, cols)), f["n_exploit_flags"] > 0, f["desc_itw_phrase"] == 1,
                        None, True)
        out[name] = int(f.loc[pd.Series(o).rank(ascending=False, method="first").to_numpy() <= TOP_K, "label"].sum())
    return out


def main() -> None:
    lab = pd.read_csv(LABELS, usecols=["cve_id", "date_added"], parse_dates=["date_added"])
    lab["label"] = (lab["date_added"] <= JUDGE_CUTOFF).astype(int)
    sb = pd.read_parquet(OUTPUT_DIR.parent / "data" / "processed" / "predict.parquet")
    sb = sb.drop(columns=["label"]).merge(lab[["cve_id", "label"]], on="cve_id", how="left")
    sb["label"] = sb["label"].fillna(0).astype(int)
    print(f"scoreboard rows {len(sb):,}, positives through {JUDGE_CUTOFF}: {sb['label'].sum()}")

    res = {k: ranking_report(sb["label"], s) for k, s in baseline_scores(sb).items()}
    top = pd.read_csv(OUTPUT_DIR / "top500.csv")
    hits = int(sb.loc[sb["cve_id"].isin(top["cve_id"]), "label"].sum())
    res["submitted_top500"] = {"hits@500": hits}
    scores = OUTPUT_DIR / "scores_predict.parquet"
    if scores.exists():
        s = sb[["cve_id", "label"]].merge(pd.read_parquet(scores), on="cve_id")
        # NOTE: ranks by plain model probability, NOT the submitted order (rules applied). Label it so.
        res["model_plain_probability_order"] = ranking_report(s["label"], s["p_exploit"])
        found = s.sort_values("rank").head(TOP_K).query("label == 1")["cve_id"].tolist()  # rank = submitted order
        res["submitted_top500"]["found_ids"] = found
        res["positive_ranks"] = {"breachlight": sorted(s.loc[s["label"] == 1, "rank"].astype(int).tolist())}
    # REPORT ONLY, for the app's "needles in the haystack" chart: rank of each 2026 positive per ordering.
    import numpy as np
    y = sb["label"].to_numpy()
    for k, sc in baseline_scores(sb).items():
        order = np.argsort(-np.nan_to_num(np.asarray(sc, dtype=float), nan=-1e9), kind="stable")
        res.setdefault("positive_ranks", {})[k] = sorted((np.flatnonzero(y[order]) + 1).tolist())
    res["all_candidates_itw_first"] = candidate_report(sb)
    (OUTPUT_DIR / "check_2026.json").write_text(json.dumps(res, indent=2))
    print(pd.Series(res["all_candidates_itw_first"]).to_string())
    print(pd.DataFrame({k: {m: v.get(m) for m in ("hits@100", "hits@500", "hits@1000", "pr_auc")}
                        for k, v in res.items()}).T.to_string())


if __name__ == "__main__":
    main()
