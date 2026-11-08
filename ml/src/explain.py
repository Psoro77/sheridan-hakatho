"""SHAP reasons, tiers and BOD 26-04 factors -> outputs/predictions.parquet (CLAUDE.md section 8).

python -m src.explain
"""
from __future__ import annotations

import json
import re

import numpy as np
import pandas as pd

from .config import MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, seed_everything
from .predict import load_meta
from .train import lr_frame

NOT_A_REASON = {"days_to_label_cutoff", "days_before_snapshot", "desc_len", "sib_max_epss_pct"}
RATE_COLS = ("assigner_kev_rate", "desc_vendor_kev_rate", "desc_product_kev_rate", "kev_vendor_kev_rate")
_PRIORS: dict = {}  # column -> typical (prior) value on the scoreboard, set in main()
KW_TEXT = {
    "kw_vpn": "VPN product", "kw_firewall": "Firewall product", "kw_gateway": "Gateway product",
    "kw_router": "Router", "kw_edge": "Edge device", "kw_appliance": "Network appliance",
    "kw_exchange": "Microsoft Exchange", "kw_sharepoint": "SharePoint", "kw_citrix": "Citrix / NetScaler",
    "kw_load_balancer": "Load balancer / ADC", "kw_file_transfer": "File transfer software",
    "kw_cms": "Content management system", "kw_plugin": "Plugin / WordPress", "kw_windows": "Windows component",
    "kw_browser": "Web browser engine", "kw_kernel": "OS kernel", "kw_iot_camera": "Camera / DVR / NAS device",
    "kw_unauth": "No authentication required", "kw_rce": "Remote code execution",
    "kw_cmd_injection": "Command injection", "kw_auth_bypass": "Authentication bypass",
    "kw_deserialization": "Unsafe deserialization", "kw_path_traversal": "Path traversal",
    "kw_sqli": "SQL injection", "kw_privesc": "Privilege escalation",
    "kw_memory_corruption": "Memory corruption bug", "kw_xss": "Cross-site scripting",
    "kw_ssrf": "Server-side request forgery", "kw_file_upload": "Arbitrary file upload",
    "kw_dos": "Denial of service",
}
FLAG_TEXT = {"exploitdb": "Exploit published on Exploit-DB", "metasploit": "Metasploit module available",
             "nuclei": "Nuclei scanner template exists", "poc_github": "Proof-of-concept code on GitHub"}
EXPLOIT_AUTOMATION = {"epss_pct", "exploitdb", "metasploit", "nuclei", "poc_github", "n_exploit_flags"}


# Evidence for binary reasons: KEV rate of 2024-25 CVEs with the same trait (train_final rows, labels known
# by 2025-12-31, i.e. all before the scoreboard). Filled in main().
_BIN: dict = {}
BIN_FEATS = [*KW_TEXT, *FLAG_TEXT, "exploit_archive", "desc_itw_phrase", "sib_any_flag", "sib_any_itw"]


def hist_rate(feat: str) -> str:
    if feat not in _BIN:
        return ""
    hits, n, lift = _BIN[feat]
    return f" ({hits} of {n:,} such 2024-25 CVEs were exploited, {lift:.0f}x average)"


def top_pct(v) -> str:
    """'top X%' for the upper half, 'bottom X%' for the lower half (v is a 0-1 percentile)."""
    v = float(v)
    if v < 0.5:
        return f"bottom {max(0.1, round(v * 100, 1)):g}%"
    return f"top {max(0.1, round((1 - v) * 100, 1)):g}%"


STRONG = 0.8  # percentile-model reasons are only stated when the CVE is in the top 20% on that model


def nearest_text(r: pd.Series) -> str:
    return f"{r['nearest_kev_cve']}, {r['nearest_kev_product']}, similarity {r['nearest_kev_sim']:.2f}"


def reason_text(feat: str, r: pd.Series) -> str | None:
    v = r.get(feat)
    if feat in NOT_A_REASON:
        return None
    if feat in KW_TEXT:
        return KW_TEXT[feat] + hist_rate(feat) if v == 1 else None
    if feat in FLAG_TEXT:
        return FLAG_TEXT[feat] + hist_rate(feat) if v == 1 else None
    if feat == "exploit_archive":
        return ("Exploit published on Exploit-DB or Metasploit" + hist_rate(feat)
                if (r.get("exploitdb") == 1 or r.get("metasploit") == 1) else None)
    if feat == "n_exploit_flags":
        return (f"{int(v)} public exploit source" + ("s" if v > 1 else "")) if v and v > 0 else None
    if feat == "epss_pct":
        return f"EPSS in top {max(1, round((1 - v) * 100))}% of its month" if pd.notna(v) else None
    if feat in ("vendor_kev_count", "desc_vendor_kev_count", "assigner_kev_count", "kev_vendor_kev_count"):
        return f"Vendor {r['vendor']} attacked {int(v)} times before (KEV)" if v and v > 0 else None
    if feat in ("assigner_kev_rate", "desc_vendor_kev_rate", "assigner_n_hist"):
        rate = max(r.get("assigner_kev_rate") or 0, r.get("desc_vendor_kev_rate") or 0)
        prior = _PRIORS.get("assigner_kev_rate", 0)
        return (f"{rate:.1%} of past {r['vendor']} CVEs were exploited ({rate / prior:.0f}x typical)"
                if prior and rate >= 3 * prior else None)
    if feat == "desc_product_kev_count":
        return f"{r['desc_product']} attacked {int(v)} times before (KEV)" if v and v > 0 else None
    if feat == "desc_product_kev_rate":
        prior = _PRIORS.get(feat, 0)
        return (f"{v:.1%} of past {r['desc_product']} CVEs were exploited ({v / prior:.0f}x typical)"
                if prior and v and v >= 3 * prior and isinstance(r.get("desc_product"), str) else None)
    if feat == "kev_vendor_kev_12m":
        return f"{r['vendor']} had {int(v)} KEV additions in the past year (active campaigns)" if v and v > 0 else None
    if feat == "desc_product_kev_12m":
        return f"{r['desc_product']} had {int(v)} KEV additions in the past year" if v and v > 0 else None
    if feat == "prior_lr_score":
        return (f"Vendor, product and wording rank in the {top_pct(v)} for resemblance to past exploited CVEs; "
                f"closest is {nearest_text(r)}") if pd.notna(v) and v >= STRONG else None
    if feat == "prior_gbm_score":
        return (f"Attack-pattern model (vendor + attack type + product) ranks it in the {top_pct(v)}"
                if pd.notna(v) and v >= STRONG else None)
    if feat == "kev_vendor_kev_rate":
        prior = _PRIORS.get(feat, 0)
        return (f"{v:.1%} of past {r['vendor']} CVEs were exploited ({v / prior:.0f}x typical)"
                if prior and v and v >= 3 * prior else None)
    if feat == "sib_any_flag":
        return "A same-week CVE from this vendor already has exploit code" + hist_rate(feat) if v == 1 else None
    if feat == "sib_any_itw":
        return "A same-week CVE from this vendor is reported exploited" + hist_rate(feat) if v == 1 else None
    if feat == "kev_vendor_fresh":
        return f"{r['vendor']} had {int(v)} KEV additions this year before this CVE's snapshot" if v and v > 0 else None
    if feat == "assigner_kev_fresh":
        return f"Same CNA had {int(v)} CVEs added to KEV this year before the snapshot" if v and v > 0 else None
    if feat == "sib_kev_fresh":
        return "A same-week CVE from this vendor is already in KEV" if v and v > 0 else None
    if feat == "sib_batch_pct":
        return None
    if feat == "sib_batch_size":
        return f"Part of a {int(v) + 1}-CVE vendor release (often chained bugs)" if v and v > 0 else None
    if feat == "sib_max_text_lr":
        return (f"A same-week CVE from this vendor reads like past exploited ones ({top_pct(v)})"
                if pd.notna(v) and v >= STRONG else None)
    if feat in ("kev_sim_max", "kev_sim_mean_top5"):
        return f"Closest past exploited CVE: {nearest_text(r)}" if pd.notna(r.get("nearest_kev_sim")) else None
    if feat == "text_lr_score":
        return f"Description reads like past exploited vulnerabilities ({top_pct(v)})" if pd.notna(v) and v >= STRONG else None
    if feat == "cluster_kev_rate":
        name = str(r.get("cluster_name", ""))[:60]
        return (f"In vulnerability family \"{name}\": {v:.1%} of its 2022-25 CVEs were exploited"
                if pd.notna(v) and r.get("cluster_id", -1) >= 0 else None)
    if feat == "desc_itw_phrase":
        return "Vendor reports exploitation in the wild" + hist_rate(feat) if v == 1 else None
    if feat == "cwe_kev_rate":
        return "Weakness type often seen in KEV"
    if feat.startswith("cvss_") or feat.startswith("cvss"):
        return "Severe CVSS characteristics"
    if feat.startswith("cwe_"):
        return f"Weakness CWE-{feat[4:]}" if v == 1 else None
    return None


def binary_rates() -> dict:
    """(hits, n, lift) for each binary reason trait among train_final CVEs (published 2024-01..2025-09,
    labels known by 2025-12-31: all before the scoreboard)."""
    tr = pd.read_parquet(PROCESSED_DIR / "features_train_final.parquet")
    tr["exploit_archive"] = tr[["exploitdb", "metasploit"]].max(axis=1)
    base = tr["label"].mean()
    out = {}
    for c in BIN_FEATS:
        if c in tr:
            m = tr[c] == 1
            if m.sum():
                out[c] = (int(tr.loc[m, "label"].sum()), int(m.sum()), float(tr.loc[m, "label"].mean() / base))
    return out


def nearest_kev(f: pd.DataFrame) -> pd.DataFrame:
    """Closest past exploited CVE by Granite embedding (cosine), among KEV entries added by each row's
    history cutoff (2025-12-31 for the scoreboard). This is the concrete 'looks like' evidence."""
    from . import data_io
    from .embed import load_embeddings

    emb, idx = load_embeddings()
    kev = data_io.load_kev()
    out = pd.DataFrame(index=f.index, columns=["nearest_kev_cve", "nearest_kev_product", "nearest_kev_sim"])
    for cutoff, ix in f.groupby("history_cutoff").groups.items():
        k = kev[(kev["date_added"] <= cutoff) & kev["cve_id"].isin(idx.index)].reset_index(drop=True)
        K = emb[idx.loc[k["cve_id"]].to_numpy()].astype(np.float32)
        rows = f.loc[ix, "cve_id"].map(idx)
        ok = rows.notna().to_numpy()
        X = emb[rows[ok].astype(int).to_numpy()].astype(np.float32)
        best, sim = np.empty(len(X), dtype=int), np.empty(len(X))
        for s in range(0, len(X), 8192):
            S = X[s : s + 8192] @ K.T
            best[s : s + 8192], sim[s : s + 8192] = S.argmax(axis=1), S.max(axis=1)
        sub = np.asarray(ix)[ok]
        out.loc[sub, "nearest_kev_cve"] = k.loc[best, "cve_id"].to_numpy()
        out.loc[sub, "nearest_kev_product"] = (k.loc[best, "vendor"].fillna("") + " " + k.loc[best, "product"].fillna("")).str.strip().to_numpy()
        out.loc[sub, "nearest_kev_sim"] = sim.round(3)
    out["nearest_kev_sim"] = out["nearest_kev_sim"].astype(float)
    return out


# Rank bands (top-k on the 72,670-row scoreboard) and how often 2025 validation CVEs ranked in the same
# share of their fold were later exploited (folds V1 + V2, out-of-time, selected model and strategy).
BANDS = [(100, "top 100"), (500, "top 500"), (1500, "top 1,500"), (7267, "top 10%"), (None, "rest")]


def band_stats(n_rows: int) -> pd.DataFrame:
    vs = pd.read_parquet(OUTPUT_DIR / "valid_scores.parquet")
    vs = vs[vs["fold"].isin(["V1", "V2"])]
    parts = []
    for _, g in vs.groupby("fold"):
        r = g["score_model_selected"].rank(ascending=False, method="first") / len(g)
        parts.append(pd.DataFrame({"frac": r.to_numpy(), "label": g["label"].to_numpy()}))
    v = pd.concat(parts)
    rows, lo = [], 0.0
    base = v["label"].mean()
    for k, name in BANDS:
        hi = 1.0 if k is None else k / n_rows
        m = (v["frac"] > lo) & (v["frac"] <= hi)
        hits, n = int(v.loc[m, "label"].sum()), int(m.sum())
        rows.append({"band": name, "lo": lo, "hi": hi, "valid_hits": hits, "valid_n": n,
                     "valid_rate": hits / n if n else 0.0, "lift": (hits / n / base) if n else 0.0})
        lo = hi
    return pd.DataFrame(rows)


def fact_reasons(r: pd.Series) -> list[str]:
    """Numeric facts used to fill a CVE's reasons when fewer than 3 model drivers apply (mostly
    low-ranked CVEs). They justify the rank either way."""
    out = []
    if pd.notna(r.get("epss_pct")):
        out.append(f"EPSS in the {top_pct(r['epss_pct'])} of its month")
    nf = int(r.get("n_exploit_flags", 0) or 0)
    out.append(f"Public exploit code at snapshot: {nf} of 4 sources")
    if pd.notna(r.get("nearest_kev_sim")):
        out.append(f"Closest past exploited CVE: {nearest_text(r)}")
    vk = r.get("vendor_kev_count")
    out.append(f"Vendor {r['vendor']}: {int(vk or 0)} past KEV entries")
    return out


def impact_score(raw: pd.DataFrame, f: pd.DataFrame) -> pd.Series:
    """Technical impact in [0,1] for the app (not used by the ranking model)."""
    kw = np.select(
        [f["kw_rce"].eq(1) | f["kw_cmd_injection"].eq(1) | f["kw_auth_bypass"].eq(1),
         f["kw_privesc"].eq(1) | f["kw_sqli"].eq(1) | f["kw_deserialization"].eq(1) | f["kw_path_traversal"].eq(1)
         | f["kw_file_upload"].eq(1) | f["kw_memory_corruption"].eq(1)],
        [0.9, 0.7], default=0.4,
    )
    cvss = raw["cvss3_score"].fillna(raw["cvss4_score"]) / 10
    return pd.Series(np.fmax(cvss.fillna(0).to_numpy(), kw), index=f.index).round(3)


def contributions(f: pd.DataFrame, meta: dict) -> pd.DataFrame:
    """Per-row feature contributions to the score. LightGBM: SHAP (TreeExplainer, averaged over
    seeds). LR: coef x standardized value (relative to the training mean). Blends: each component
    normalized by its row-wise absolute sum, then averaged."""
    import joblib
    import lightgbm as lgb
    import shap

    parts = []
    for comp in meta["components"]:
        cols = comp["features"]
        if comp["type"] == "lgbm":
            ms = [lgb.Booster(model_file=str(MODEL_DIR / f"{comp['name']}_{s}.txt")) for s in range(meta["n_models"])]
            sv = np.mean([np.asarray(shap.TreeExplainer(m).shap_values(f[cols])) for m in ms], axis=0)
            if sv.ndim == 3:
                sv = sv[1]
        else:
            m = joblib.load(MODEL_DIR / f"{comp['name']}.joblib")
            Z = m[:-1].transform(lr_frame(f, cols))
            coef = m[-1].coef_[0]
            # Sign-aware: only features whose HIGHER values raise risk (coef > 0) can become reasons.
            # A negative-coef feature with a below-average value also pushes the score up, but its
            # reason text ("attacked N times", "part of a big batch") would state the opposite.
            sv = Z * np.where(coef > 0, coef, 0.0)
        c = pd.DataFrame(sv, columns=cols, index=f.index)
        if len(meta["components"]) > 1:
            c = c.div(c.abs().sum(axis=1).replace(0, 1), axis=0)
        parts.append(c)
    return pd.concat(parts, axis=1).T.groupby(level=0).mean().T


def main() -> None:
    seed_everything()
    meta = load_meta()
    cols = sorted({c for comp in meta["components"] for c in comp["features"]})
    f = pd.read_parquet(PROCESSED_DIR / "features_predict.parquet")
    for c in RATE_COLS:
        _PRIORS[c] = float(f[c].median())
    raw = pd.read_parquet(PROCESSED_DIR / "predict.parquet")[["cve_id", "cvss3_score", "cvss4_score"]]
    raw = f[["cve_id"]].merge(raw, on="cve_id", how="left")
    scores = pd.read_parquet(OUTPUT_DIR / "scores_predict.parquet")
    f = f.merge(scores, on="cve_id", how="left")

    names = {}
    cpath = OUTPUT_DIR / "clusters.csv"
    if cpath.exists():
        names = pd.read_csv(cpath).set_index("cluster_id")["name"].to_dict()
    f["cluster_name"] = f["cluster_id"].map(names).fillna("unclustered")

    sv = contributions(f, meta)[cols]
    _BIN.update(binary_rates())
    f = pd.concat([f, nearest_kev(f)], axis=1)
    bands = band_stats(len(f))
    bands.to_csv(OUTPUT_DIR / "rank_bands.csv", index=False)
    print(bands.to_string(index=False))
    frac = f["rank"] / len(f)
    bi = np.searchsorted(bands["hi"].to_numpy(), frac.to_numpy(), side="left")
    b = bands.iloc[bi].reset_index(drop=True)
    b.index = f.index
    f["rank_band"] = b["band"]
    f["band_valid_rate"] = b["valid_rate"].round(4)
    confidence = [
        (f"Ranked #{int(r['rank']):,} of {len(f):,} ({r['rank_band']}). In 2025 validation, {int(bb['valid_hits'])} of "
         f"{int(bb['valid_n']):,} CVEs ranked in this band ({bb['valid_rate']:.2%}) were later exploited, "
         f"{bb['lift']:.{0 if bb['lift'] >= 10 else 1}f}x the average.")
        for (_, r), (_, bb) in zip(f[["rank", "rank_band"]].iterrows(), b.iterrows())
    ]

    reasons, shap_top = [], []
    for i in f.index:
        row, s = f.loc[i], sv.loc[i].sort_values(ascending=False)
        rs, top = [], {}
        if meta.get("itw_first") and row.get("desc_itw_phrase") == 1:
            rs.append("Vendor reports exploitation in the wild" + hist_rate("desc_itw_phrase"))
            top["desc_itw_phrase"] = round(float(sv.loc[i].get("desc_itw_phrase", 0)), 4)
        for feat, val in s.items():
            if val <= 0 or len(rs) == 3:
                break
            t = reason_text(feat, row)
            if t and t not in rs and not any(str(row["nearest_kev_cve"]) in x for x in rs if "Closest" in t):
                rs.append(t)
                top[feat] = round(float(val), 4)
        for t in fact_reasons(row):  # fill to 3 with numeric facts (never repeats the nearest-CVE evidence)
            if len(rs) == 3:
                break
            if t not in rs and not (t.startswith("Closest") and any(row["nearest_kev_cve"] in x for x in rs)):
                rs.append(t)
        reasons.append(json.dumps(rs))
        shap_top.append(json.dumps(top))
    bad = [r for r in reasons if len(json.loads(r)) < 3 or not all(re.search(r"\d", x) for x in json.loads(r))]
    assert not bad, f"{len(bad)} rows lack 3 numeric reasons, e.g. {bad[:2]}"

    n = len(f)
    tier = np.where(f["rank"] <= 100, "Fix now", np.where(f["rank"] <= 500, "This week", "Monitor"))
    flags = f[["exploitdb", "metasploit", "nuclei", "poc_github"]]
    exploit_flags = flags.apply(lambda r: json.dumps([k for k, v in r.items() if v == 1]), axis=1)
    ea_cols = [c for c in cols if c in EXPLOIT_AUTOMATION]
    pred = pd.DataFrame({
        "cve_id": f["cve_id"], "published": f["published"], "snapshot_month": f["snapshot_month"],
        "vendor": f["vendor"], "p_exploit": f["p_exploit"].round(6), "rank": f["rank"], "tier": tier,
        "epss_pct": f["epss_pct"].round(4), "exploit_flags": exploit_flags,
        "impact_score": impact_score(raw, f), "cluster_id": f["cluster_id"], "cluster_name": f["cluster_name"],
        "reasons": reasons, "shap_top": shap_top,
        # Evidence (round 5): the closest past exploited CVE and the validation hit rate of the rank band.
        "nearest_kev_cve": f["nearest_kev_cve"], "nearest_kev_product": f["nearest_kev_product"],
        "nearest_kev_sim": f["nearest_kev_sim"], "rank_band": f["rank_band"],
        "band_valid_rate": f["band_valid_rate"], "confidence": confidence,
        # BOD 26-04 factor mapping for the UI (asset_exposure comes from the app's inventory).
        "kev_likelihood": f["p_exploit"].rank(pct=True).round(4),
        "exploit_automation": sv[ea_cols].sum(axis=1).round(4),
        "technical_impact": impact_score(raw, f),
    }).sort_values("rank")
    pred.to_parquet(OUTPUT_DIR / "predictions.parquet", index=False)
    print(f"predictions.parquet: {pred.shape}, tiers: {pd.Series(tier).value_counts().to_dict()}")
    print(pred.head(10)[["cve_id", "vendor", "p_exploit", "tier", "reasons"]].to_string(index=False))
    imp = sv.abs().mean().sort_values(ascending=False)
    imp.to_csv(OUTPUT_DIR / "shap_importance.csv", header=["mean_abs_shap"])
    assert n == pred["cve_id"].nunique()


if __name__ == "__main__":
    main()
