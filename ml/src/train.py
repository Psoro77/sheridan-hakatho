"""Model selection on two DISJOINT validation periods at scoreboard depth, then the final model.

python -m src.train --split train_A --eval valid      # experiments (V1 + V2), writes outputs/experiments.csv
python -m src.train --split train_final               # final model for the scoreboard

Evaluation protocol (fixed after review, see docs/findings.md):
- V1 = train_A (2024, labels to 2024-12-31) -> validV1 (2025-01..04, 25 positives)
  V2 = trainV2 (2024-01..2025-04, labels to 2025-04-30) -> validV2 (2025-05..09, 27 positives)
  The validation periods don't overlap, so each exploited CVE is counted once (52 total).
- Depth: the scoreboard top 500 is 0.69% of its 72,670 rows, so each fold is scored at
  k = 500 * n_rows / 72,670 (V1: 110, V2: 133). Slot quotas are fractions of k.
- Training rows with < 31 days of label horizon are dropped (guaranteed negatives, pure noise).
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

from .config import MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, SCOREBOARD_ROWS, SEED, TOP_K, seed_everything
from .features import FEATURE_GROUPS
from .metrics import bootstrap_ci, hits_at_k

FOLDS = {"V1": ("train_A", "validV1"), "V2": ("trainV2", "validV2")}
MIN_TRAIN_HORIZON = 31
N_SEEDS = 5
SELECTION_PATH = OUTPUT_DIR / "selected_features.json"
FRAC_GRID = [round(x, 1) for x in np.arange(0.0, 1.01, 0.1)]

# Heavily regularized: only ~40 to 70 train positives (fixed rounds, sqrt class weight, depth 2, bagging).
PARAMS = dict(
    objective="binary", learning_rate=0.02, num_leaves=4, max_depth=2, min_child_samples=20,
    min_sum_hessian_in_leaf=1e-3, feature_fraction=0.7, bagging_fraction=0.8, bagging_freq=1,
    lambda_l2=10.0, verbose=-1,
)
N_ROUNDS = 300

CORE = ["exploit", "vendor_kw", "text", "cluster"]
LGBM_EXPERIMENTS = {
    "L4_core": CORE,
    "L7_core+prior+sibling": CORE + ["prior", "sibling"],
    "L8_core+prior+sibling+caution": CORE + ["prior", "sibling", "caution"],
}
COMPACT_V2 = [
    "epss_pct", "exploitdb", "metasploit", "nuclei", "poc_github", "days_before_snapshot", "days_to_label_cutoff",
    "assigner_kev_rate", "desc_vendor_kev_rate", "desc_product_kev_rate", "vendor_kev_count",
    "desc_product_kev_count", "kev_vendor_kev_12m", "desc_product_kev_12m",
    "text_lr_score", "prior_lr_score", "kev_sim_max", "cluster_kev_rate", "kw_unauth", "kw_rce",
    "desc_itw_phrase", "sib_batch_size", "sib_max_text_lr", "sib_any_flag", "sib_any_itw",
]
COMPACT_V3 = COMPACT_V2 + ["prior_gbm_score", "kev_vendor_kev_rate"]
# v4: one feature per concept (no collinear twins such as count vs 12-month count, vendor vs assigner
# rate), Exploit-DB/Metasploit merged into one "exploit archive" flag, no label-horizon feature
# (its scoreboard range 35-277 days lies outside train_final's 92-700). Every feature is chosen so a
# higher value should mean higher risk, which keeps the LR explanations faithful.
COMPACT_V4 = [
    "epss_pct", "nuclei", "poc_github", "exploit_archive", "days_before_snapshot",
    "kev_vendor_kev_rate", "kev_vendor_kev_12m", "desc_product_kev_rate", "desc_product_kev_12m",
    "text_lr_score", "prior_lr_score", "prior_gbm_score", "kev_sim_max",
    "kw_unauth", "kw_rce", "kw_auth_bypass", "kw_path_traversal",
    "desc_itw_phrase", "sib_any_flag", "sib_any_itw", "sib_max_text_lr",
]
COMPACT_V4H = COMPACT_V4 + ["days_to_label_cutoff"]
LR_EXPERIMENTS = {"C2_compact_v2": COMPACT_V2, "C3_compact_v3": COMPACT_V3,
                  "C4_compact_v4": COMPACT_V4, "C4h_compact_v4+horizon": COMPACT_V4H}
# Reported but never selectable: CVSS/CWE gains come from NIST's post-attack analysis.
REPORT_ONLY = {"L8_core+prior+sibling+caution"}
LOG_COLS = {"vendor_kev_count", "desc_product_kev_count", "kev_vendor_kev_12m", "desc_product_kev_12m",
            "sib_batch_size", "assigner_kev_count", "desc_vendor_kev_count"}
DERIVED = {"exploit_archive": lambda d: d[["exploitdb", "metasploit"]].max(axis=1)}


def columns_for(groups: list[str]) -> list[str]:
    return [c for g in groups for c in FEATURE_GROUPS[g]]


def depth(n_rows: int) -> int:
    return max(1, round(TOP_K * n_rows / SCOREBOARD_ROWS))


# ---------------------------------------------------------------- models
def fit_lgbm(Xtr, ytr, seed=SEED, n_rounds=N_ROUNDS):
    pos = max(1, int(ytr.sum()))
    params = {**PARAMS, "scale_pos_weight": float(np.sqrt((len(ytr) - pos) / pos)), "seed": seed}
    return lgb.train(params, lgb.Dataset(Xtr, ytr), num_boost_round=n_rounds)


def lr_frame(d: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    X = pd.DataFrame(index=d.index)
    for c in cols:
        X[c] = (DERIVED[c](d) if c in DERIVED else d[c]).astype(float)
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
    """Ranking score (higher = earlier): optional ITW rows first, then (if k_flag is set) a top-k with
    k_flag slots for rows with exploit code and k - k_flag for rows without, then the rest by score."""
    s = rank_pct(score)
    n = len(s)
    flagged = np.asarray(flagged, dtype=bool)
    itw = np.asarray(itw, dtype=bool) if itw_first else np.zeros(n, dtype=bool)
    chosen = itw.copy()
    if k_flag is not None:
        room = max(0, k - chosen.sum())
        f_idx = np.where(flagged & ~chosen)[0]
        f_idx = f_idx[np.argsort(-s[f_idx], kind="stable")][: min(k_flag, room)]
        chosen[f_idx] = True
        u_idx = np.where(~flagged & ~chosen)[0]
        u_idx = u_idx[np.argsort(-s[u_idx], kind="stable")][: max(0, k - chosen.sum())]
        chosen[u_idx] = True
    return s + np.where(chosen, 2.0, 0.0) + np.where(itw, 1.0, 0.0)


def plateau(per_frac: dict[float, int]) -> float:
    """Centre of the best plateau: maximise the 3-point moving average of fold-summed hits."""
    fs = sorted(per_frac)
    smooth = {f: np.mean([per_frac[g] for g in fs if abs(g - f) <= 0.1 + 1e-9]) for f in fs}
    best = max(smooth.values())
    cands = [f for f in fs if smooth[f] >= best - 1e-9]
    return cands[len(cands) // 2]


# ---------------------------------------------------------------- validation
def load_fold(name: str):
    tr_name, va_name = FOLDS[name]
    tr = pd.read_parquet(PROCESSED_DIR / f"features_{tr_name}.parquet")
    tr = tr[tr["days_to_label_cutoff"] >= MIN_TRAIN_HORIZON].reset_index(drop=True)
    va = pd.read_parquet(PROCESSED_DIR / f"features_{va_name}.parquet")
    return tr, tr["label"].astype(int).to_numpy(), va, va["label"].astype(int).to_numpy()


def run_validation() -> None:
    folds = {f: load_fold(f) for f in FOLDS}
    ks = {f: depth(len(va)) for f, (_, _, va, _) in folds.items()}
    for f, (tr, ytr, va, yva) in folds.items():
        print(f"fold {f}: train {tr.shape} pos={ytr.sum()} | valid {va.shape} pos={yva.sum()} | depth k={ks[f]}")

    cand: dict[str, dict] = {}
    for name, groups in LGBM_EXPERIMENTS.items():
        cols = columns_for(groups)
        cand[name] = {"type": "lgbm", "features": cols,
                      "scores": {f: score_lgbm(tr, ytr, va, cols) for f, (tr, ytr, va, _) in folds.items()}}
    for name, cols in LR_EXPERIMENTS.items():
        cand[name] = {"type": "lr", "features": cols,
                      "scores": {f: score_lr(tr, ytr, va, cols) for f, (tr, ytr, va, _) in folds.items()}}

    def order(scores, f, frac, itw_first, k):
        _, _, va, _ = folds[f]
        k_flag = None if frac is None else round(frac * k)
        return final_order(scores[f], va["n_exploit_flags"] > 0, va["desc_itw_phrase"] == 1, k_flag, itw_first, k)

    def fold_hits(scores, frac, itw_first, mult=1) -> dict[str, int]:
        return {f: hits_at_k(folds[f][3], order(scores, f, frac, itw_first, ks[f] * mult), ks[f] * mult) for f in folds}

    rows = []

    def evaluate(name: str, c: dict) -> None:
        for strat in ("plain", "itw_first", "segmented+itw"):
            itw_first = strat != "plain"
            frac = None
            if strat == "segmented+itw":
                frac = plateau({fr: sum(fold_hits(c["scores"], fr, True).values()) for fr in FRAC_GRID})
            h, h2 = fold_hits(c["scores"], frac, itw_first), fold_hits(c["scores"], frac, itw_first, mult=2)
            row = {"experiment": name, "type": c["type"], "strategy": strat, "flag_frac": frac,
                   "sum@depth": sum(h.values()), "sum@2xdepth": sum(h2.values()), "selectable": name not in REPORT_ONLY}
            for f in folds:
                lo, hi = bootstrap_ci(folds[f][3], order(c["scores"], f, frac, itw_first, ks[f]), k=ks[f])
                row.update({f"{f}@depth": h[f], f"{f}_ci95": f"{lo}-{hi}", f"{f}@2x": h2[f]})
            rows.append(row)

    for name, c in cand.items():
        evaluate(name, c)

    res = pd.DataFrame(rows)
    res["recall@depth"] = (res["sum@depth"] / sum(int(y.sum()) for *_, y in folds.values())).round(3)
    res.to_csv(OUTPUT_DIR / "experiments.csv", index=False)
    base = {f: hits_at_k(y, va["n_exploit_flags"].clip(upper=1) + va["epss_pct"].fillna(0), ks[f])
            for f, (_, _, va, y) in folds.items()}
    print(f"baseline exploit-then-EPSS @depth: {base} (sum {sum(base.values())})")
    with pd.option_context("display.width", 250, "display.max_rows", 200):
        print(res[["experiment", "strategy", "flag_frac", "V1@depth", "V1_ci95", "V2@depth", "V2_ci95",
                   "sum@depth", "recall@depth", "sum@2xdepth", "selectable"]].to_string(index=False))
    res[res["type"] == "lgbm"].to_csv(OUTPUT_DIR / "ablation.csv", index=False)

    # Selection: best sum@depth among selectable; ties -> simpler strategy, then sum@2xdepth.
    simpl = {"plain": 0, "itw_first": 1, "segmented+itw": 2}
    best = (res[res["selectable"]].assign(_s=res["strategy"].map(simpl))
            .sort_values(["sum@depth", "_s", "sum@2xdepth"], ascending=[False, True, False]).iloc[0])
    c = cand[best["experiment"]]
    sel = {
        "experiment": best["experiment"], "strategy": best["strategy"],
        "flag_frac": None if pd.isna(best["flag_frac"]) else float(best["flag_frac"]),
        "itw_first": best["strategy"] != "plain",
        "components": [{"name": best["experiment"], "type": c["type"], "features": c["features"]}],
        "sum@depth": int(best["sum@depth"]), "recall@depth": float(best["recall@depth"]),
        "V1@depth": int(best["V1@depth"]), "V2@depth": int(best["V2@depth"]), "depth": ks,
        "baseline_exploit_then_epss@depth": base,
    }
    SELECTION_PATH.write_text(json.dumps(sel, indent=2))
    print("\nselection:", json.dumps({k: v for k, v in sel.items() if k != "components"}, indent=1))

    # Out-of-time scores for the whole valid period (V1 + V2) for evaluate.py: within-fold percentile.
    parts = []
    for f, (_, _, va, _) in folds.items():
        p = pd.DataFrame({"cve_id": va["cve_id"]})
        for n, cc in cand.items():
            p[f"score_{n}"] = rank_pct(cc["scores"][f])
        p["score_model_selected"] = rank_pct(order(c["scores"], f, sel["flag_frac"], sel["itw_first"], ks[f]))
        parts.append(p)
    pd.concat(parts, ignore_index=True).to_parquet(OUTPUT_DIR / "valid_scores.parquet", index=False)


# ---------------------------------------------------------------- final
def run_final() -> None:
    sel = json.loads(SELECTION_PATH.read_text())
    tr = pd.read_parquet(PROCESSED_DIR / "features_train_final.parquet")
    tr = tr[tr["days_to_label_cutoff"] >= MIN_TRAIN_HORIZON].reset_index(drop=True)
    y = tr["label"].astype(int).to_numpy()
    print(f"train_final {tr.shape} pos={y.sum()} | selected {sel['experiment']} / {sel['strategy']} flag_frac={sel['flag_frac']}")
    for comp in sel["components"]:
        cols = comp["features"]
        if comp["type"] == "lgbm":
            boosters = [fit_lgbm(tr[cols], y, seed=SEED + s) for s in range(N_SEEDS)]
            for s, m in enumerate(boosters):
                m.save_model(str(MODEL_DIR / f"{comp['name']}_{s}.txt"))
            imp = pd.Series(np.mean([m.feature_importance("gain") for m in boosters], axis=0), index=cols)
            imp.sort_values(ascending=False).to_csv(OUTPUT_DIR / "feature_importance.csv", header=["gain_mean_over_seeds"])
            print(imp.sort_values(ascending=False).head(15).to_string())
        else:
            m = make_compact_lr().fit(lr_frame(tr, cols), y)
            joblib.dump(m, MODEL_DIR / f"{comp['name']}.joblib")
            coef = pd.Series(m[-1].coef_[0], index=cols).sort_values(ascending=False)
            coef.to_csv(OUTPUT_DIR / "lr_coefficients.csv", header=["coef_std"])
            print(coef.round(3).to_string())
    (MODEL_DIR / "final_meta.json").write_text(json.dumps(
        {**sel, "n_models": N_SEEDS, "n_rounds": N_ROUNDS, "train_pos_rate": float(y.mean())}, indent=2))


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
