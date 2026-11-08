"""SHAP reasons, tiers and BOD 26-04 factors -> outputs/predictions.parquet (CLAUDE.md section 8).

python -m src.explain
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from .config import OUTPUT_DIR, PROCESSED_DIR, seed_everything
from .predict import load_models, prepare

NOT_A_REASON = {"days_to_label_cutoff", "days_before_snapshot", "desc_len"}
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
    if feat in ("vendor_kev_count", "desc_vendor_kev_count", "assigner_kev_count"):
        return f"Vendor {r['vendor']} attacked {int(v)} times before" if v and v > 0 else None
    if feat in ("assigner_kev_rate", "desc_vendor_kev_rate", "assigner_n_hist"):
        rate = max(r.get("assigner_kev_rate") or 0, r.get("desc_vendor_kev_rate") or 0)
        return f"{rate:.1%} of past {r['vendor']} CVEs were exploited (KEV)"
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


def main() -> None:
    import shap

    seed_everything()
    models, meta = load_models()
    cols = meta["features"]
    f = pd.read_parquet(PROCESSED_DIR / "features_predict.parquet")
    raw = pd.read_parquet(PROCESSED_DIR / "predict.parquet")[["cve_id", "cvss3_score", "cvss4_score"]]
    raw = f[["cve_id"]].merge(raw, on="cve_id", how="left")
    scores = pd.read_parquet(OUTPUT_DIR / "scores_predict.parquet")
    f = f.merge(scores, on="cve_id", how="left")

    names = {}
    cpath = OUTPUT_DIR / "clusters.csv"
    if cpath.exists():
        names = pd.read_csv(cpath).set_index("cluster_id")["name"].to_dict()
    f["cluster_name"] = f["cluster_id"].map(names).fillna("unclustered")

    X = prepare(f, meta)
    sv = np.mean([shap.TreeExplainer(m).shap_values(X) for m in models], axis=0)
    if isinstance(sv, list):
        sv = sv[1]
    sv = pd.DataFrame(sv, columns=cols, index=f.index)

    reasons, shap_top = [], []
    for i in f.index:
        row, s = f.loc[i], sv.loc[i].sort_values(ascending=False)
        rs, top = [], {}
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
