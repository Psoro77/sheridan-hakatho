"""Train LightGBM (and an LR sanity baseline).

python -m src.train --split train_A --eval valid      # model selection + ablation
python -m src.train --split train_final               # final model for the scoreboard
"""
from __future__ import annotations

import argparse
import json

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .config import MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, SEED, seed_everything
from .features import FEATURE_GROUPS
from .metrics import ranking_report

ABLATION = [
    ("1_exploit", ["exploit"], False),
    ("2_+vendor_kw", ["exploit", "vendor_kw"], False),
    ("3_+text", ["exploit", "vendor_kw", "text"], False),
    ("4_+cluster", ["exploit", "vendor_kw", "text", "cluster"], False),
    ("5_+caution", ["exploit", "vendor_kw", "text", "cluster", "caution"], False),
    ("5b_+caution_imputed", ["exploit", "vendor_kw", "text", "cluster", "caution"], True),
    ("6_+itw", ["exploit", "vendor_kw", "text", "cluster", "caution", "itw"], False),
    ("6b_core+itw", ["exploit", "vendor_kw", "text", "cluster", "itw"], False),
]
DEFAULT_GROUPS = ["exploit", "vendor_kw", "text", "cluster"]
N_SEEDS = 5
SELECTION_PATH = OUTPUT_DIR / "selected_features.json"

# Heavily regularized: only ~40 positives in train_A. Early stopping on ~50 valid positives stopped
# at 2 to 10 iterations (noise), so we use a fixed number of rounds and sqrt(neg/pos) class weight
# (full neg/pos ~1000x made trees memorize the 40 positives; see docs/findings.md).
PARAMS = dict(
    objective="binary", learning_rate=0.02, num_leaves=4, max_depth=2, min_child_samples=20,
    min_sum_hessian_in_leaf=1e-3, feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
    lambda_l2=10.0, verbose=-1,
)
N_ROUNDS = 300


def columns_for(groups: list[str]) -> list[str]:
    return [c for g in groups for c in FEATURE_GROUPS[g]]


def impute_caution(train: pd.DataFrame, others: list[pd.DataFrame]) -> None:
    """Fill caution NaNs with train medians so the model can't learn from 'NIST hasn't scored this'."""
    cols = FEATURE_GROUPS["caution"]
    med = train[cols].median()
    for d in (train, *others):
        d[cols] = d[cols].fillna(med)


def fit_lgbm(Xtr, ytr, seed=SEED, n_rounds=N_ROUNDS):
    pos = max(1, int(ytr.sum()))
    params = {**PARAMS, "scale_pos_weight": float(np.sqrt((len(ytr) - pos) / pos)), "seed": seed}
    return lgb.train(params, lgb.Dataset(Xtr, ytr), num_boost_round=n_rounds)


def multi_seed(Xtr, ytr, Xva, yva) -> tuple[np.ndarray, list[int]]:
    """Average rank of N_SEEDS bagged models (variance is high with ~50 positives)."""
    scores = []
    for s in range(N_SEEDS):
        m = fit_lgbm(Xtr, ytr, seed=SEED + s)
        scores.append(pd.Series(m.predict(Xva)).rank(pct=True).to_numpy())
    return np.mean(scores, axis=0), [N_ROUNDS] * N_SEEDS


def run_validation() -> None:
    tr = pd.read_parquet(PROCESSED_DIR / "features_train_A.parquet")
    va = pd.read_parquet(PROCESSED_DIR / "features_valid.parquet")
    ytr, yva = tr["label"].astype(int).to_numpy(), va["label"].astype(int).to_numpy()
    print(f"train_A {tr.shape} pos={ytr.sum()} | valid {va.shape} pos={yva.sum()}")

    rows, valid_scores = [], pd.DataFrame({"cve_id": va["cve_id"]})
    for name, groups, impute in ABLATION:
        cols = columns_for(groups)
        a, b = tr.copy(), va.copy()
        if impute:
            impute_caution(a, [b])
        score, iters = multi_seed(a[cols], ytr, b[cols], yva)
        rep = ranking_report(yva, score)
        rows.append({"row": name, "groups": "+".join(groups), "n_features": len(cols), **rep,
                     "best_iter_mean": int(np.mean(iters))})
        valid_scores[f"score_lgbm_{name}"] = score
        print(f"{name:22s} hits@100={rep['hits@100']:>3} hits@500={rep['hits@500']:>3} "
              f"hits@1000={rep['hits@1000']:>3} pr_auc={rep['pr_auc']} iters={iters}")

    abl = pd.DataFrame(rows)
    abl.to_csv(OUTPUT_DIR / "ablation.csv", index=False)

    # LR sanity baseline on the default groups.
    cols = columns_for(DEFAULT_GROUPS)
    lr = make_pipeline(SimpleImputer(strategy="median"), StandardScaler(),
                       LogisticRegression(C=0.1, max_iter=3000, class_weight="balanced", random_state=SEED))
    lr.fit(tr[cols], ytr)
    valid_scores["score_logreg_default"] = lr.decision_function(va[cols])
    print("logreg default:", ranking_report(yva, valid_scores["score_logreg_default"]))

    # Selection rule (logged): start from core; add a caution group only if it gains >= 2 hits@500
    # AND the gain survives median imputation (i.e. it does not come from missingness).
    h = abl.set_index("row")["hits@500"]
    groups = list(DEFAULT_GROUPS)
    best_core = max(h["2_+vendor_kw"], h["3_+text"], h["4_+cluster"])
    decisions = {}
    if h["5_+caution"] - h["4_+cluster"] >= 2 and h["5b_+caution_imputed"] - h["4_+cluster"] >= 2:
        groups.append("caution")
        decisions["caution"] = "kept (gain survives imputation)"
    else:
        decisions["caution"] = "dropped (no robust gain on valid)"
    base_itw = h["6_+itw"] - h["5_+caution"] if "caution" in groups else h["6b_core+itw"] - h["4_+cluster"]
    if base_itw >= 2:
        groups.append("itw")
        decisions["itw"] = f"kept (+{base_itw} hits@500)"
    else:
        decisions["itw"] = f"dropped ({base_itw:+} hits@500)"
    impute = "caution" in groups
    n_iter = int(abl.loc[abl["groups"] == "+".join(groups), "best_iter_mean"].iloc[0]) if (
        abl["groups"] == "+".join(groups)).any() else int(abl["best_iter_mean"].median())
    sel = {"groups": groups, "impute_caution": impute, "best_iter_train_A": n_iter,
           "decisions": decisions, "best_core_hits@500": int(best_core)}
    SELECTION_PATH.write_text(json.dumps(sel, indent=2))
    print("selection:", sel)

    # Score column the evaluator reports as "model".
    sel_name = next((n for n, g, imp in ABLATION if g == groups and imp == impute), None)
    if sel_name:
        valid_scores["score_model_selected"] = valid_scores[f"score_lgbm_{sel_name}"]
    valid_scores.to_parquet(OUTPUT_DIR / "valid_scores.parquet", index=False)


def run_final() -> None:
    sel = json.loads(SELECTION_PATH.read_text())
    tr = pd.read_parquet(PROCESSED_DIR / "features_train_final.parquet")
    cols = columns_for(sel["groups"])
    if sel["impute_caution"]:
        impute_caution(tr, [])
    y = tr["label"].astype(int).to_numpy()
    # Same number of rounds as validated: row count scaling is unreliable with this few positives.
    n_rounds = N_ROUNDS
    print(f"train_final {tr.shape} pos={y.sum()} features={len(cols)} rounds={n_rounds}")
    for s in range(N_SEEDS):
        m = fit_lgbm(tr[cols], y, seed=SEED + s, n_rounds=n_rounds)
        m.save_model(str(MODEL_DIR / f"lgbm_final_{s}.txt"))
    medians = tr[FEATURE_GROUPS["caution"]].median().to_dict() if sel["impute_caution"] else {}
    (MODEL_DIR / "final_meta.json").write_text(json.dumps(
        {"features": cols, "n_rounds": n_rounds, "n_models": N_SEEDS, "caution_medians": medians, **sel}, indent=2))
    imp = pd.Series(m.feature_importance("gain"), index=cols).sort_values(ascending=False)
    imp.to_csv(OUTPUT_DIR / "feature_importance.csv", header=["gain"])
    print(imp.head(15).to_string())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="train_A", choices=["train_A", "train_final"])
    ap.add_argument("--eval", default=None)
    args = ap.parse_args()
    seed_everything()
    if args.split == "train_A":
        run_validation()
    else:
        run_final()


if __name__ == "__main__":
    main()
