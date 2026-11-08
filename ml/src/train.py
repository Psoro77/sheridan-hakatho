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
Round 5 additions:
- Fold V0 = trainV0 (2024-01..06, only 6 positives, so a noisy fold) -> validV0 (2024-07..12, 30 positives).
- Accept rule: a configuration replaces the reference (compact v4 + ITW first) only if it gains >= 2
  hits summed over V0+V1+V2 and loses nothing on any fold.
- Strategy "itw+capN": at most N top-k rows per (resolved vendor, snapshot month).
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

import os

# V0 (round 5): trainV0 (2024-01..06) -> validV0 (2024-07..12, labels to 2025-04-30). Third disjoint set.
FOLDS = {"V0": ("trainV0", "validV0"), "V1": ("train_A", "validV1"), "V2": ("trainV2", "validV2")}
USE_LIVE_KEV = os.environ.get("AEGIS_USE_LIVE_KEV") == "1"
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
# Round 5. v3 with the drifting raw batch count replaced by its within-month percentile.
COMPACT_V3B = [c for c in COMPACT_V3 if c != "sib_batch_size"] + ["sib_batch_pct"]
# v5 = v4 + batch percentile (per-CVE dilution in big releases, without the 2026 volume extrapolation).
COMPACT_V5 = COMPACT_V4 + ["sib_batch_pct"]
FRESH = ["kev_vendor_fresh", "assigner_kev_fresh", "sib_kev_fresh"]
# Embedding-free ablation of v5: what Granite actually adds to the selected family.
NO_EMB = {"text_lr_score", "prior_lr_score", "prior_gbm_score", "kev_sim_max", "sib_max_text_lr", "cluster_kev_rate"}
COMPACT_V5_NOEMB = [c for c in COMPACT_V5 if c not in NO_EMB]
LR_EXPERIMENTS = {"C2_compact_v2": COMPACT_V2, "C3_compact_v3": COMPACT_V3,
                  "C3b_v3_batchpct": COMPACT_V3B, "C4_compact_v4": COMPACT_V4,
                  "C4h_compact_v4+horizon": COMPACT_V4H, "C5_v4+batchpct": COMPACT_V5,
                  "C5n_v5_no_granite": COMPACT_V5_NOEMB, "C6_v5+fresh_kev": COMPACT_V5 + FRESH}
# Reported but never selectable: CVSS/CWE gains come from NIST's post-attack analysis; the no-Granite
# run is an ablation. Fresh-KEV needs the live 2026 KEV feed on the scoreboard (team opt-in only).
REPORT_ONLY = {"L8_core+prior+sibling+caution", "C5n_v5_no_granite"} | (set() if USE_LIVE_KEV else {"C6_v5+fresh_kev"})
# Reference for the accept rule = the round-4 selection (frozen before round 5). v4 ties it on every fold
# (3/9/15). Round 5 first used v4 as the reference ("simpler wins ties"); the 2026 post-hoc check then
# showed v4 = 11/60 vs v3 = 19/60, so the team kept the round-4 submission. That choice was influenced by
# the answer key and is disclosed in docs/findings.md (round 5).
REFERENCE = ("C3_compact_v3", "itw_first")
CAPS = [3, 5, 10]  # max rows per (resolved vendor, snapshot month) in the top k
LOG_COLS = {"vendor_kev_count", "desc_product_kev_count", "kev_vendor_kev_12m", "desc_product_kev_12m",
            "sib_batch_size", "assigner_kev_count", "desc_vendor_kev_count", *FRESH}
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
def vendor_groups(d: pd.DataFrame) -> np.ndarray:
    """Cap key = resolved KEV vendor x snapshot month (one vendor release). Rows whose vendor was not
    resolved (multi-vendor CNAs such as MITRE or GitHub) get no key and are never capped."""
    v = d["kev_vendor"]
    return np.where(v.notna(), v.astype(str) + "|" + d["snapshot_month"].astype(str), None)


def final_order(score, flagged, itw, k_flag: int | None, itw_first: bool, k: int = TOP_K,
                groups=None, cap: int | None = None) -> np.ndarray:
    """Ranking score (higher = earlier): optional ITW rows first, then (if k_flag is set) a top-k with
    k_flag slots for rows with exploit code and k - k_flag for rows without, or (if cap is set) the top-k
    by score with at most `cap` rows per vendor release; then the rest by score."""
    s = rank_pct(score)
    n = len(s)
    flagged = np.asarray(flagged, dtype=bool)
    itw = np.asarray(itw, dtype=bool) if itw_first else np.zeros(n, dtype=bool)
    chosen = itw.copy()
    if cap is not None and k_flag is None:
        g = np.asarray(groups, dtype=object)
        used: dict = {}
        for i in np.where(chosen)[0]:
            if g[i] is not None:
                used[g[i]] = used.get(g[i], 0) + 1
        for i in np.argsort(-s, kind="stable"):
            if chosen.sum() >= k:
                break
            if chosen[i]:
                continue
            if g[i] is not None:
                if used.get(g[i], 0) >= cap:
                    continue
                used[g[i]] = used.get(g[i], 0) + 1
            chosen[i] = True
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
        # Sign check on the largest fold's training set: a negative weight means "higher value = lower
        # risk", which usually signals a collinear twin and breaks the reason texts.
        tr2, y2, *_ = folds["V2"]
        coef = make_compact_lr().fit(lr_frame(tr2, cols), y2)[-1].coef_[0]
        cand[name]["neg_coefs"] = [c for c, w in zip(cols, coef) if w < -0.05]

    groups = {f: vendor_groups(va) for f, (_, _, va, _) in folds.items()}

    def order(scores, f, frac, itw_first, k, cap=None):
        _, _, va, _ = folds[f]
        k_flag = None if frac is None else round(frac * k)
        return final_order(scores[f], va["n_exploit_flags"] > 0, va["desc_itw_phrase"] == 1, k_flag, itw_first, k,
                           groups=groups[f], cap=cap)

    def fold_hits(scores, frac, itw_first, mult=1, cap=None) -> dict[str, int]:
        return {f: hits_at_k(folds[f][3], order(scores, f, frac, itw_first, ks[f] * mult, cap), ks[f] * mult)
                for f in folds}

    rows = []
    strategies = ["plain", "itw_first", "segmented+itw", *[f"itw+cap{c}" for c in CAPS]]

    def evaluate(name: str, c: dict) -> None:
        for strat in strategies:
            itw_first = strat != "plain"
            frac, cap = None, (int(strat.split("cap")[1]) if "cap" in strat else None)
            if strat == "segmented+itw":
                frac = plateau({fr: sum(fold_hits(c["scores"], fr, True).values()) for fr in FRAC_GRID})
            h, h2 = fold_hits(c["scores"], frac, itw_first, cap=cap), fold_hits(c["scores"], frac, itw_first, 2, cap)
            row = {"experiment": name, "type": c["type"], "strategy": strat, "flag_frac": frac, "cap": cap,
                   "sum@depth": sum(h.values()), "sumV1V2@depth": h["V1"] + h["V2"], "sum@2xdepth": sum(h2.values()),
                   "selectable": name not in REPORT_ONLY, "neg_coefs": ";".join(c.get("neg_coefs", []))}
            for f in folds:
                lo, hi = bootstrap_ci(folds[f][3], order(c["scores"], f, frac, itw_first, ks[f], cap), k=ks[f])
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
    with pd.option_context("display.width", 250, "display.max_rows", 300):
        print(res[["experiment", "strategy", "flag_frac", *[f"{f}@depth" for f in folds],
                   "sum@depth", "sumV1V2@depth", "sum@2xdepth", "selectable", "neg_coefs"]].to_string(index=False))
    res[res["type"] == "lgbm"].to_csv(OUTPUT_DIR / "ablation.csv", index=False)

    # Accept rule (round 5): start from the reference (simplest clean model). Another selectable
    # configuration replaces it only if it gains >= 2 hits summed over all folds AND loses nothing on
    # any fold. Among those, the highest sum wins; ties go to the simpler strategy, then fewer features.
    simpl = {s: i for i, s in enumerate(["plain", "itw_first", "itw+cap10", "itw+cap5", "itw+cap3", "segmented+itw"])}
    ref = res[(res["experiment"] == REFERENCE[0]) & (res["strategy"] == REFERENCE[1])].iloc[0]
    sel_pool = res[res["selectable"]].copy()
    ok = (sel_pool["sum@depth"] >= ref["sum@depth"] + 2)
    for f in folds:
        ok &= sel_pool[f"{f}@depth"] >= ref[f"{f}@depth"]
    accepted = sel_pool[ok].assign(_s=lambda d: d["strategy"].map(simpl),
                                   _n=lambda d: d["experiment"].map(lambda e: len(cand[e]["features"])))
    print(f"\nreference {REFERENCE}: {[int(ref[f'{f}@depth']) for f in folds]} sum {int(ref['sum@depth'])}; "
          f"{len(accepted)} configurations pass the accept rule")
    best = (accepted.sort_values(["sum@depth", "_s", "_n"], ascending=[False, True, True]).iloc[0]
            if len(accepted) else ref)
    c = cand[best["experiment"]]
    cap = None if pd.isna(best["cap"]) else int(best["cap"])
    sel = {
        "experiment": best["experiment"], "strategy": best["strategy"],
        "flag_frac": None if pd.isna(best["flag_frac"]) else float(best["flag_frac"]), "cap": cap,
        "itw_first": best["strategy"] != "plain",
        "components": [{"name": best["experiment"], "type": c["type"], "features": c["features"]}],
        "sum@depth": int(best["sum@depth"]), "recall@depth": float(best["recall@depth"]),
        **{f"{f}@depth": int(best[f"{f}@depth"]) for f in folds}, "depth": ks,
        "baseline_exploit_then_epss@depth": base, "accept_rule_reference": list(REFERENCE),
        "use_live_kev": USE_LIVE_KEV,
    }
    SELECTION_PATH.write_text(json.dumps(sel, indent=2))
    print("\nselection:", json.dumps({k: v for k, v in sel.items() if k != "components"}, indent=1))

    # Out-of-time scores for every fold for evaluate.py (within-fold percentile; report per fold).
    parts = []
    for f, (_, _, va, _) in folds.items():
        p = pd.DataFrame({"cve_id": va["cve_id"], "fold": f, "label": folds[f][3]})
        for n, cc in cand.items():
            p[f"score_{n}"] = rank_pct(cc["scores"][f])
        p["score_model_selected"] = rank_pct(order(c["scores"], f, sel["flag_frac"], sel["itw_first"], ks[f], cap))
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
            neg = coef[coef < -0.05]
            if len(neg):
                print(f"NOTE: negative weights (higher value = lower risk): {neg.round(3).to_dict()}")
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
