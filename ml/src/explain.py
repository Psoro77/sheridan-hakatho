"""SHAP reasons, tiers and BOD 26-04 factors -> outputs/predictions.parquet (CLAUDE.md section 8).

python -m src.explain
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from .config import MODEL_DIR, OUTPUT_DIR, PROCESSED_DIR, seed_everything
from .predict import load_meta
from .train import lr_frame

NOT_A_REASON = {"days_to_label_cutoff", "days_before_snapshot", "desc_len", "sib_max_epss_pct"}
RATE_COLS = ("assigner_kev_rate", "desc_vendor_kev_rate", "desc_product_kev_rate")
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


def reason_text(feat: str, r: pd.Series) -> str | None:
    v = r.get(feat)
    if feat in NOT_A_REASON:
        return None
    if feat in KW_TEXT:
        return KW_TEXT[feat] if v == 1 else None
    if feat in FLAG_TEXT:
        return FLAG_TEXT[feat] if v == 1 else None
    if feat == "n_exploit_flags":
        return (f"{int(v)} public exploit source" + ("s" if v > 1 else "")) if v and v > 0 else None
    if feat == "epss_pct":
        return f"EPSS in top {max(1, round((1 - v) * 100))}% of its month" if pd.notna(v) else None
    if feat in ("vendor_kev_count", "desc_vendor_kev_count", "assigner_kev_count", "kev_vendor_kev_count"):
        return f"Vendor {r['vendor']} attacked {int(v)} times before (KEV)" if v and v > 0 else None
    if feat in ("assigner_kev_rate", "desc_vendor_kev_rate", "assigner_n_hist"):
        rate = max(r.get("assigner_kev_rate") or 0, r.get("desc_vendor_kev_rate") or 0)
        prior = _PRIORS.get("assigner_kev_rate", 0)
        return (f"{rate:.1%} of past {r['vendor']} CVEs were exploited ({rate / prior:.0f}x average)"
                if prior and rate >= 3 * prior else None)
    if feat == "desc_product_kev_count":
        return f"{r['desc_product']} attacked {int(v)} times before (KEV)" if v and v > 0 else None
    if feat == "desc_product_kev_rate":
        prior = _PRIORS.get(feat, 0)
        return (f"{v:.1%} of past {r['desc_product']} CVEs were exploited ({v / prior:.0f}x average)"
                if prior and v and v >= 3 * prior and isinstance(r.get("desc_product"), str) else None)
    if feat == "kev_vendor_kev_12m":
        return f"{r['vendor']} had {int(v)} KEV additions in the past year (active campaigns)" if v and v > 0 else None
    if feat == "desc_product_kev_12m":
        return f"{r['desc_product']} had {int(v)} KEV additions in the past year" if v and v > 0 else None
    if feat == "prior_lr_score":
        return "Vendor, product and description resemble past exploited CVEs"
    if feat == "sib_any_flag":
        return "A same-day CVE from this vendor already has exploit code" if v == 1 else None
    if feat == "sib_any_itw":
        return "A same-day CVE from this vendor is reported exploited" if v == 1 else None
    if feat == "sib_batch_size":
        return f"Part of a {int(v) + 1}-CVE vendor release (often chained bugs)" if v and v > 0 else None
    if feat == "sib_max_text_lr":
        return "A same-day sibling CVE reads like past exploited ones"
    if feat in ("kev_sim_max", "kev_sim_mean_top5"):
        return f"Similar to past KEV entries ({r['kev_sim_max']:.2f})" if pd.notna(r.get("kev_sim_max")) else None
    if feat == "text_lr_score":
        return "Description reads like past exploited vulnerabilities"
    if feat == "cluster_kev_rate":
        return f"In a vulnerability family with a high attack rate ({r.get('cluster_name', '')})"
    if feat == "desc_itw_phrase":
        return "Vendor reports exploitation in the wild" if v == 1 else None
    if feat == "cwe_kev_rate":
        return "Weakness type often seen in KEV"
    if feat.startswith("cvss_") or feat.startswith("cvss"):
        return "Severe CVSS characteristics"
    if feat.startswith("cwe_"):
        return f"Weakness CWE-{feat[4:]}" if v == 1 else None
    return feat


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
            sv = Z * m[-1].coef_[0]
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

    reasons, shap_top = [], []
    for i in f.index:
        row, s = f.loc[i], sv.loc[i].sort_values(ascending=False)
        rs, top = [], {}
        if meta.get("itw_first") and row.get("desc_itw_phrase") == 1:
            rs.append("Vendor reports exploitation in the wild")
            top["desc_itw_phrase"] = round(float(sv.loc[i].get("desc_itw_phrase", 0)), 4)
        for feat, val in s.items():
            if val <= 0 or len(rs) == 3:
                break
            t = reason_text(feat, row)
            if t and t not in rs:
                rs.append(t)
                top[feat] = round(float(val), 4)
        reasons.append(json.dumps(rs))
        shap_top.append(json.dumps(top))

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
