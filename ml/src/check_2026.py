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
        res["model"] = ranking_report(s["label"], s["p_exploit"])
        found = s.sort_values("rank").head(TOP_K).query("label == 1")["cve_id"].tolist()
        res["model"]["found_ids"] = found
    (OUTPUT_DIR / "check_2026.json").write_text(json.dumps(res, indent=2))
    print(pd.DataFrame({k: {m: v.get(m) for m in ("hits@100", "hits@500", "hits@1000", "pr_auc")}
                        for k, v in res.items()}).T.to_string())


if __name__ == "__main__":
    main()
