"""Model selection on two validation folds, then the final model.

python -m src.train --split train_A --eval valid      # experiments on fold A (train_A->valid) + fold B (trainB->validB)
python -m src.train --split train_final               # final model for the scoreboard
"""
from __future__ import annotations

import argparse
import json

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .config import MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, SEED, TOP_K, seed_everything
from .features import FEATURE_GROUPS
from .metrics import bootstrap_ci, ranking_report

FOLDS = {"A": ("train_A", "valid"), "B": ("trainB", "validB")}
N_SEEDS = 5
SELECTION_PATH = OUTPUT_DIR / "selected_features.json"
K_GRID = list(range(0, TOP_K + 1, 50))

# Heavily regularized: only ~40 to 60 train positives. Early stopping on ~50 valid positives stopped
# at 2 to 10 iterations (noise), so: fixed rounds, sqrt(neg/pos) class weight, depth-2 trees, bagging.
PARAMS = dict(
    objective="binary", learning_rate=0.02, num_leaves=4, max_depth=2, min_child_samples=20,
    min_sum_hessian_in_leaf=1e-3, feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
    lambda_l2=10.0, verbose=-1,
)
N_ROUNDS = 300

CORE = ["exploit", "vendor_kw", "text", "cluster"]
LGBM_EXPERIMENTS = {
    "L1_exploit": ["exploit"],
    "L2_+vendor_kw": ["exploit", "vendor_kw"],
    "L3_+text": ["exploit", "vendor_kw", "text"],
    "L4_core(+cluster)": CORE,
    "L5_core+prior": CORE + ["prior"],
    "L6_core+sibling": CORE + ["sibling"],
    "L7_core+prior+sibling": CORE + ["prior", "sibling"],
    "L8_core+prior+sibling+caution": CORE + ["prior", "sibling", "caution"],
    "L9_core+prior+sibling+itw": CORE + ["prior", "sibling", "itw"],
}
# Compact, robust LR: few strong, explainable features (works well with ~50 positives).
COMPACT_V1 = [
    "epss_pct", "n_exploit_flags", "days_before_snapshot", "days_to_label_cutoff",
    "assigner_kev_rate", "desc_vendor_kev_rate", "vendor_kev_count",
    "text_lr_score", "kev_sim_max", "cluster_kev_rate", "kw_unauth", "kw_rce", "desc_itw_phrase",
]
COMPACT_V2 = [
    "epss_pct", "exploitdb", "metasploit", "nuclei", "poc_github", "days_before_snapshot", "days_to_label_cutoff",
    "assigner_kev_rate", "desc_vendor_kev_rate", "desc_product_kev_rate", "vendor_kev_count",
    "desc_product_kev_count", "kev_vendor_kev_12m", "desc_product_kev_12m",
    "text_lr_score", "prior_lr_score", "kev_sim_max", "cluster_kev_rate", "kw_unauth", "kw_rce",
    "desc_itw_phrase", "sib_batch_size", "sib_max_text_lr", "sib_any_flag", "sib_any_itw",
]
LR_EXPERIMENTS = {"C1_compact_v1": COMPACT_V1, "C2_compact_v2": COMPACT_V2}
# Reported but never selectable: CVSS/CWE gains come from NIST's post-attack analysis (100% of
# positives are NIST-analysed with no blank CVSS/CWE vs 65% / ~4% of negatives; 2026 has only 19%
# NIST-sourced scores vs 37-48% in training). See docs/columns_used.md.
REPORT_ONLY = {"L8_core+prior+sibling+caution"}
LOG_COLS = {"vendor_kev_count", "desc_product_kev_count", "kev_vendor_kev_12m", "desc_product_kev_12m",
            "sib_batch_size", "assigner_kev_count", "desc_vendor_kev_count"}


def columns_for(groups: list[str]) -> list[str]:
    return [c for g in groups for c in FEATURE_GROUPS[g]]


# ---------------------------------------------------------------- models
def fit_lgbm(Xtr, ytr, seed=SEED, n_rounds=N_ROUNDS):
    pos = max(1, int(ytr.sum()))
    params = {**PARAMS, "scale_pos_weight": float(np.sqrt((len(ytr) - pos) / pos)), "seed": seed}
    return lgb.train(params, lgb.Dataset(Xtr, ytr), num_boost_round=n_rounds)


def lr_frame(d: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    X = d[cols].astype(float).copy()
    for c in cols:
        if c in LOG_COLS:
            X[c] = np.log1p(X[c].clip(lower=0))
    return X


def make_compact_lr():
    return make_pipeline(
        SimpleImputer(strategy="median"), StandardScaler(),
        LogisticRegression(C=0.1, max_iter=5000, class_weight="balanced", random_state=SEED),
    )


def rank_pct(s) -> np.ndarray:
    return pd.Series(np.asarray(s, dtype=float)).rank(pct=True, na_option="bottom").to_numpy()


def score_lgbm(tr, ytr, te, cols) -> np.ndarray:
    return np.mean([rank_pct(fit_lgbm(tr[cols], ytr, seed=SEED + s).predict(te[cols])) for s in range(N_SEEDS)], axis=0)


def score_lr(tr, ytr, te, cols) -> np.ndarray:
    m = make_compact_lr().fit(lr_frame(tr, cols), ytr)
    return m.decision_function(lr_frame(te, cols))


# ---------------------------------------------------------------- ranking strategies
def final_order(score, flagged, itw, k_flag: int | None, itw_first: bool, k: int = TOP_K) -> np.ndarray:
    """Return a ranking score (higher = earlier). Optional: ITW rows first, then a top-k split with
    k_flag slots for rows with exploit code and k - k_flag for rows without, rest by score."""
    s = rank_pct(score)
    out = s.copy()
    n = len(s)
    flagged = np.asarray(flagged, dtype=bool)
    itw = np.asarray(itw, dtype=bool) if itw_first else np.zeros(n, dtype=bool)
    chosen = np.zeros(n, dtype=bool)
    chosen |= itw
    if k_flag is not None:
        room = k - chosen.sum()
        kf = min(k_flag, room)
        f_idx = np.where(flagged & ~chosen)[0]
        f_idx = f_idx[np.argsort(-s[f_idx], kind="stable")][:kf]
        chosen[f_idx] = True
        u_idx = np.where(~flagged & ~chosen)[0]
        u_idx = u_idx[np.argsort(-s[u_idx], kind="stable")][: k - chosen.sum()]
        chosen[u_idx] = True
    out = s + np.where(chosen, 2.0, 0.0) + np.where(itw, 1.0, 0.0)
    return out


def plateau_k(per_k: dict[int, int]) -> int:
    """Centre of the best plateau: maximise the 3-point moving average of fold-summed hits."""
    ks = sorted(per_k)
    smooth = {k: np.mean([per_k[j] for j in ks if abs(j - k) <= 50]) for k in ks}
    best = max(smooth.values())
    cands = [k for k in ks if smooth[k] >= best - 1e-9]
    return cands[len(cands) // 2]


# ---------------------------------------------------------------- validation
def load_fold(name: str):
    tr_name, va_name = FOLDS[name]
    tr = pd.read_parquet(PROCESSED_DIR / f"features_{tr_name}.parquet")
    va = pd.read_parquet(PROCESSED_DIR / f"features_{va_name}.parquet")
    return tr, tr["label"].astype(int).to_numpy(), va, va["label"].astype(int).to_numpy()


def run_validation() -> None:
    folds = {f: load_fold(f) for f in FOLDS}
    for f, (tr, ytr, va, yva) in folds.items():
        print(f"fold {f}: train {tr.shape} pos={ytr.sum()} | valid {va.shape} pos={yva.sum()}")

    # 1) raw scores per candidate per fold
    cand: dict[str, dict] = {}
    for name, groups in LGBM_EXPERIMENTS.items():
        cols = columns_for(groups)
        cand[name] = {"type": "lgbm", "features": cols, "groups": groups,
                      "scores": {f: score_lgbm(tr, ytr, va, cols) for f, (tr, ytr, va, _) in folds.items()}}
    for name, cols in LR_EXPERIMENTS.items():
        cand[name] = {"type": "lr", "features": cols,
                      "scores": {f: score_lr(tr, ytr, va, cols) for f, (tr, ytr, va, _) in folds.items()}}

    def fold_sum(scores: dict, k_flag=None, itw_first=False) -> tuple[int, dict]:
        reps = {}
        for f, (_, _, va, yva) in folds.items():
            s = final_order(scores[f], va["n_exploit_flags"] > 0, va["desc_itw_phrase"] == 1, k_flag, itw_first)
            reps[f] = ranking_report(yva, s)
        return sum(r["hits@500"] for r in reps.values()), reps

    # 2) strategies: plain, segmented (k_flag from plateau), segmented + ITW-first
    rows = []

    def evaluate(name: str, c: dict) -> None:
        for strat in ("plain", "segmented", "segmented+itw"):
            itw_first = strat == "segmented+itw"
            k_flag = None
            if strat != "plain":
                per_k = {k: fold_sum(c["scores"], k, itw_first)[0] for k in K_GRID}
                k_flag = plateau_k(per_k)
            total, reps = fold_sum(c["scores"], k_flag, itw_first)
            row = {"experiment": name, "type": c["type"], "strategy": strat, "k_flag": k_flag, "fold_sum@500": total}
            for f, r in reps.items():
                _, _, va, yva = folds[f]
                s = final_order(c["scores"][f], va["n_exploit_flags"] > 0, va["desc_itw_phrase"] == 1, k_flag, itw_first)
                lo, hi = bootstrap_ci(yva, s)
                row.update({f"{f}_hits@100": r["hits@100"], f"{f}_hits@500": r["hits@500"],
                            f"{f}_hits@1000": r["hits@1000"], f"{f}_pr_auc": r["pr_auc"], f"{f}_ci95": f"{lo}-{hi}"})
            row["selectable"] = name not in REPORT_ONLY
            rows.append(row)

    for name, c in cand.items():
        evaluate(name, c)
    # best selectable LGBM + best LR (by their best strategy) -> rank blend candidate
    tmp = pd.DataFrame(rows)
    tmp = tmp[tmp["selectable"]].groupby("experiment")["fold_sum@500"].max()
    best_l = max((n for n in tmp.index if cand[n]["type"] == "lgbm"), key=lambda n: tmp[n])
    best_c = max((n for n in tmp.index if cand[n]["type"] == "lr"), key=lambda n: tmp[n])
    cand["B1_blend"] = {"type": "blend", "components": [best_l, best_c],
                        "scores": {f: (rank_pct(cand[best_l]["scores"][f]) + rank_pct(cand[best_c]["scores"][f])) / 2
                                   for f in folds}}
    evaluate("B1_blend", cand["B1_blend"])
    print(f"blend components: {best_l} + {best_c}")
    res = pd.DataFrame(rows)
    res.to_csv(OUTPUT_DIR / "experiments.csv", index=False)
    with pd.option_context("display.width", 250, "display.max_rows", 200):
        print(res[["experiment", "strategy", "k_flag", "A_hits@500", "A_ci95", "B_hits@500", "B_ci95",
                   "fold_sum@500", "A_hits@1000", "B_hits@1000"]].to_string(index=False))

    # Ablation table in the CLAUDE.md format (plain LightGBM rows, fold A = valid).
    abl = res[(res["type"] == "lgbm") & (res["strategy"] == "plain")]
    abl.to_csv(OUTPUT_DIR / "ablation.csv", index=False)

    # 3) selection: highest fold_sum; ties -> simpler strategy, then higher hits@1000 sum.
    order = {"plain": 0, "segmented": 1, "segmented+itw": 2}
    res["_simpl"] = res["strategy"].map(order)
    res["_h1000"] = res["A_hits@1000"] + res["B_hits@1000"]
    best = res[res["selectable"]].sort_values(["fold_sum@500", "_simpl", "_h1000"], ascending=[False, True, False]).iloc[0]
    c = cand[best["experiment"]]
    components = ([{"name": n, "type": cand[n]["type"], "features": cand[n]["features"]} for n in c["components"]]
                  if c["type"] == "blend" else [{"name": best["experiment"], "type": c["type"], "features": c["features"]}])
    sel = {
        "experiment": best["experiment"], "strategy": best["strategy"],
        "k_flag": None if pd.isna(best["k_flag"]) else int(best["k_flag"]),
        "itw_first": best["strategy"] == "segmented+itw", "components": components,
        "fold_sum@500": int(best["fold_sum@500"]), "A_hits@500": int(best["A_hits@500"]),
        "B_hits@500": int(best["B_hits@500"]),
        "reference_v2_plain_L4": res.query("experiment == 'L4_core(+cluster)' and strategy == 'plain'")[
            ["A_hits@500", "B_hits@500"]].iloc[0].astype(int).tolist(),
    }
    SELECTION_PATH.write_text(json.dumps(sel, indent=2))
    print("\nselection:", json.dumps(sel, indent=1))

    # valid (fold A) scores for evaluate.py
    vs = pd.DataFrame({"cve_id": folds["A"][2]["cve_id"]})
    for n, cc in cand.items():
        vs[f"score_{n}"] = cc["scores"]["A"]
    _, _, va, _ = folds["A"]
    vs["score_model_selected"] = final_order(c["scores"]["A"], va["n_exploit_flags"] > 0, va["desc_itw_phrase"] == 1,
                                             sel["k_flag"], sel["itw_first"])
    vs.to_parquet(OUTPUT_DIR / "valid_scores.parquet", index=False)


# ---------------------------------------------------------------- final
def run_final() -> None:
    sel = json.loads(SELECTION_PATH.read_text())
    tr = pd.read_parquet(PROCESSED_DIR / "features_train_final.parquet")
    y = tr["label"].astype(int).to_numpy()
    print(f"train_final {tr.shape} pos={y.sum()} | selected {sel['experiment']} / {sel['strategy']} k_flag={sel['k_flag']}")
    for comp in sel["components"]:
        cols = comp["features"]
        if comp["type"] == "lgbm":
            for s in range(N_SEEDS):
                m = fit_lgbm(tr[cols], y, seed=SEED + s)
                m.save_model(str(MODEL_DIR / f"{comp['name']}_{s}.txt"))
            imp = pd.Series(m.feature_importance("gain"), index=cols).sort_values(ascending=False)
            imp.to_csv(OUTPUT_DIR / "feature_importance.csv", header=["gain"])
            print(imp.head(15).to_string())
        else:
            m = make_compact_lr().fit(lr_frame(tr, cols), y)
            joblib.dump(m, MODEL_DIR / f"{comp['name']}.joblib")
            coef = pd.Series(m[-1].coef_[0], index=cols).sort_values(ascending=False)
            coef.to_csv(OUTPUT_DIR / "lr_coefficients.csv", header=["coef_std"])
            print(coef.to_string())
    (MODEL_DIR / "final_meta.json").write_text(json.dumps({**sel, "n_models": N_SEEDS, "n_rounds": N_ROUNDS}, indent=2))


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
