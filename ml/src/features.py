"""Feature engineering (CLAUDE.md section 6). Re-read section 4 (leakage) before editing.

Every history-based feature for a row uses only KEV entries with date_added <= the row's
history_cutoff (Dec 31 of the year before publication) and only CVEs published by then.

python -m src.features
"""
from __future__ import annotations

import re
import warnings

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from . import data_io
from .config import (
    ATTACK_KEYWORDS, HISTORY_START, ITW_PATTERN, OUTPUT_DIR, PROCESSED_DIR,
    PRODUCT_KEYWORDS, SEED, SMOOTH_M, seed_everything,
)

warnings.filterwarnings("ignore", "This pattern is interpreted as a regular expression")

FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]
TOP_CWES = [
    "CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-787", "CWE-416", "CWE-20", "CWE-287", "CWE-502",
    "CWE-77", "CWE-94", "CWE-862", "CWE-352", "CWE-434", "CWE-125", "CWE-918", "CWE-306", "CWE-843",
    "CWE-288", "CWE-119",
]
CVSS_ORD = {
    "attack_vector": {"PHYSICAL": 0, "LOCAL": 1, "ADJACENT_NETWORK": 2, "ADJACENT": 2, "NETWORK": 3},
    "attack_complexity": {"HIGH": 0, "LOW": 1},
    "privileges_required": {"HIGH": 0, "LOW": 1, "NONE": 2},
    "user_interaction": {"REQUIRED": 0, "NONE": 1},
    "scope": {"UNCHANGED": 0, "CHANGED": 1},
    "confidentiality_impact": {"NONE": 0, "LOW": 1, "HIGH": 2},
    "integrity_impact": {"NONE": 0, "LOW": 1, "HIGH": 2},
    "availability_impact": {"NONE": 0, "LOW": 1, "HIGH": 2},
}
VENDOR_STOP = {"multiple", "multiple vendors", "unknown", "n/a", "the", "open source"}

FEATURE_GROUPS = {
    "exploit": ["epss_pct", *FLAGS, "n_exploit_flags", "days_to_label_cutoff"],
    "vendor_kw": [
        "assigner_kev_count", "assigner_kev_rate", "assigner_n_hist",
        "desc_vendor_kev_count", "desc_vendor_kev_rate", "vendor_kev_count",
        *PRODUCT_KEYWORDS, *ATTACK_KEYWORDS, "desc_len",
    ],
    "text": ["kev_sim_max", "kev_sim_mean_top5", "text_lr_score"],
    "cluster": ["cluster_kev_rate"],
    "caution": [
        *[f"cvss_{c}" for c in CVSS_ORD], "cvss3_score", "cvss4_score", "cwe_kev_rate",
        *[f"cwe_{c.split('-')[1]}" for c in TOP_CWES],
    ],
    "itw": ["desc_itw_phrase"],
}


# ---------------------------------------------------------------- helpers
def smoothed_rate(hits: pd.Series, n: pd.Series, prior: float, m: int = SMOOTH_M) -> pd.Series:
    return (hits + m * prior) / (n + m)


def assigner_org(a: str | float) -> str:
    if not isinstance(a, str) or not a:
        return "unknown"
    a = a.strip().lower()
    if "@" not in a:
        return a  # CNA UUID: keep as its own key
    parts = a.split("@", 1)[1].split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "ac", "gov", "net", "or", "ne"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def build_vendor_regex(kev: pd.DataFrame) -> re.Pattern:
    names = sorted(
        {v.strip() for v in kev["vendor"].dropna() if len(v.strip()) >= 3 and v.strip().lower() not in VENDOR_STOP},
        key=len, reverse=True,
    )
    # Case-sensitive on CISA's spelling to avoid matching common words ("Progress", "Craft").
    return re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")


def first_match(texts: pd.Series, rx: re.Pattern) -> pd.Series:
    return texts.fillna("").map(lambda t: (m.group(1) if (m := rx.search(t)) else None))


def primary_cwe(cwe_ids: pd.Series) -> pd.Series:
    first = cwe_ids.fillna("").str.split(";").str[0].str.strip()
    return first.where(first.str.startswith("CWE-"), None)


def rate_table(hist: pd.DataFrame, key: str, cutoff: pd.Timestamp) -> tuple[pd.DataFrame, float]:
    """Per-key smoothed KEV rate using CVEs published in [HISTORY_START, cutoff] and KEV <= cutoff."""
    h = hist[(hist["published"] >= HISTORY_START) & (hist["published"] <= cutoff) & hist[key].notna()]
    hit = (h["date_added"] <= cutoff).astype(int)
    g = h.assign(hit=hit).groupby(key)["hit"].agg(["sum", "count"])
    prior = float(hit.mean()) if len(h) else 0.0
    g["rate"] = smoothed_rate(g["sum"], g["count"], prior)
    return g, prior


# ---------------------------------------------------------------- feature blocks
def history_features(df: pd.DataFrame, hist: pd.DataFrame, kev: pd.DataFrame, vendor_rx: re.Pattern) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    df = df.assign(assigner_org=df["assigner"].map(assigner_org), desc_vendor=first_match(df["description"], vendor_rx),
                   cwe_primary=primary_cwe(df["cwe_ids"]))
    for col in ("assigner_kev_count", "assigner_kev_rate", "assigner_n_hist", "desc_vendor_kev_count",
                "desc_vendor_kev_rate", "cwe_kev_rate"):
        out[col] = np.nan
    for cutoff, idx in df.groupby("history_cutoff").groups.items():
        sub = df.loc[idx]
        kev_past = kev[kev["date_added"] <= cutoff]
        # assigner
        g, prior = rate_table(hist, "assigner_org", cutoff)
        out.loc[idx, "assigner_kev_rate"] = sub["assigner_org"].map(g["rate"]).fillna(prior).to_numpy()
        out.loc[idx, "assigner_n_hist"] = sub["assigner_org"].map(g["count"]).fillna(0).to_numpy()
        out.loc[idx, "assigner_kev_count"] = sub["assigner_org"].map(g["sum"]).fillna(0).to_numpy()
        # vendor mentioned in description (CISA vendor names); count = all past KEV entries for that vendor
        g, prior = rate_table(hist, "desc_vendor", cutoff)
        out.loc[idx, "desc_vendor_kev_rate"] = sub["desc_vendor"].map(g["rate"]).fillna(prior).to_numpy()
        kev_counts = kev_past["vendor"].value_counts()
        out.loc[idx, "desc_vendor_kev_count"] = sub["desc_vendor"].map(kev_counts).fillna(0).to_numpy()
        # CWE (caution group)
        g, prior = rate_table(hist, "cwe_primary", cutoff)
        out.loc[idx, "cwe_kev_rate"] = sub["cwe_primary"].map(g["rate"]).fillna(prior).to_numpy()
    out["vendor_kev_count"] = np.where(df["desc_vendor"].notna(), out["desc_vendor_kev_count"], out["assigner_kev_count"])
    # Display name only (not a model feature): UUID CNAs get the vendor their descriptions name most.
    out["vendor"] = df["desc_vendor"].fillna(df["assigner_org"].map(assigner_display_names(hist)).fillna(df["assigner_org"]))
    return out


_DISPLAY: dict = {}


def assigner_display_names(hist: pd.DataFrame) -> dict:
    if not _DISPLAY:
        is_uuid = hist["assigner_org"].str.fullmatch(r"[0-9a-f\-]{36}", na=False)
        h = hist[is_uuid].dropna(subset=["desc_vendor"])
        top = h.groupby("assigner_org")["desc_vendor"].agg(lambda s: s.value_counts().index[0])
        _DISPLAY.update(top.to_dict())
        for a in hist.loc[is_uuid, "assigner_org"].unique():
            _DISPLAY.setdefault(a, f"CNA {a[:8]}")
        # Email-domain orgs: capitalize ("fortinet" -> "Fortinet").
        for a in hist.loc[~is_uuid, "assigner_org"].dropna().unique():
            _DISPLAY[a] = a.capitalize()
    return _DISPLAY


def text_keyword_features(df: pd.DataFrame) -> pd.DataFrame:
    desc = df["description"].fillna("").str.lower()
    out = pd.DataFrame(index=df.index)
    for name, pat in {**PRODUCT_KEYWORDS, **ATTACK_KEYWORDS}.items():
        out[name] = desc.str.contains(pat, regex=True).astype("int8")
    out["desc_itw_phrase"] = desc.str.contains(ITW_PATTERN, regex=True).astype("int8")
    out["desc_len"] = desc.str.len()
    return out


def caution_features(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    for col, mapping in CVSS_ORD.items():
        out[f"cvss_{col}"] = df[col].map(mapping).astype(float)
    out["cvss3_score"] = df["cvss3_score"]
    out["cvss4_score"] = df["cvss4_score"]
    cwes = df["cwe_ids"].fillna("")
    for c in TOP_CWES:
        out[f"cwe_{c.split('-')[1]}"] = cwes.str.contains(rf"(?:^|;){c}(?:;|$)", regex=True).astype("int8")
    return out


def embedding_features(df: pd.DataFrame, emb: np.ndarray, idx: pd.Series, kev: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index, columns=["kev_sim_max", "kev_sim_mean_top5"], dtype=float)
    rows = df["cve_id"].map(idx)
    for cutoff, ix in df.groupby("history_cutoff").groups.items():
        kev_ids = kev.loc[kev["date_added"] <= cutoff, "cve_id"]
        kr = kev_ids.map(idx).dropna().astype(int).to_numpy()
        K = emb[kr].astype(np.float32)
        kev_set = set(kev_ids)
        r = rows.loc[ix]
        ok = r.notna().to_numpy()
        sub_ix = np.asarray(ix)[ok]
        X = emb[r[ok].astype(int).to_numpy()].astype(np.float32)
        mx, top5 = np.empty(len(X)), np.empty(len(X))
        for s in range(0, len(X), 8192):
            S = X[s : s + 8192] @ K.T
            part = np.sort(S, axis=1)[:, -5:]
            mx[s : s + 8192], top5[s : s + 8192] = part[:, -1], part.mean(axis=1)
        out.loc[sub_ix, "kev_sim_max"] = mx
        out.loc[sub_ix, "kev_sim_mean_top5"] = top5
        assert not df.loc[sub_ix, "cve_id"].isin(kev_set).any(), "row already in past KEV"
    return out


_TEXT_LR_CACHE: dict = {}


def _emb_matrix(ids: pd.Series, emb: np.ndarray, idx: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    r = ids.map(idx)
    ok = r.notna().to_numpy()
    return emb[r[ok].astype(int).to_numpy()].astype(np.float32), ok


def text_lr_features(df: pd.DataFrame, hist: pd.DataFrame, emb: np.ndarray, idx: pd.Series) -> pd.Series:
    """Past-only text model: for history cutoff H, fit LR(embedding) on CVEs published in
    [EMBED_START, H] with label = in KEV by H. Rows being scored are all published after H, so no
    row ever scores itself and no OOF is needed. Far more positives than the split itself."""
    from .embed import EMBED_START

    out = pd.Series(np.nan, index=df.index)
    for cutoff, ix in df.groupby("history_cutoff").groups.items():
        if cutoff not in _TEXT_LR_CACHE:
            h = hist[(hist["published"] >= EMBED_START) & (hist["published"] <= cutoff)]
            X, ok = _emb_matrix(h["cve_id"], emb, idx)
            y = (h["date_added"] <= cutoff).to_numpy()[ok].astype(int)
            m = LogisticRegression(C=0.5, max_iter=3000, class_weight="balanced", random_state=SEED).fit(X, y)
            _TEXT_LR_CACHE[cutoff] = m
            print(f"  text_lr fit for cutoff {cutoff.date()}: n={len(y):,} positives={y.sum()}")
        X, ok = _emb_matrix(df.loc[ix, "cve_id"], emb, idx)
        vals = np.full(len(ix), np.nan)
        vals[ok] = _TEXT_LR_CACHE[cutoff].decision_function(X)
        out.loc[ix] = vals
    return out


def cluster_features(df: pd.DataFrame, hist: pd.DataFrame) -> pd.DataFrame:
    path = PROCESSED_DIR / "clusters.parquet"
    out = pd.DataFrame(index=df.index)
    if not path.exists():
        print("  clusters.parquet missing; cluster features = NaN (run src.cluster)")
        out["cluster_id"], out["cluster_kev_rate"] = -1, np.nan
        return out
    cl = pd.read_parquet(path).set_index("cve_id")["cluster_id"]
    out["cluster_id"] = df["cve_id"].map(cl).fillna(-1).astype(int)
    h = hist.assign(cluster_id=hist["cve_id"].map(cl))
    h["cluster_id"] = h["cluster_id"].where(h["cluster_id"] >= 0)  # noise -> NaN -> prior
    out["cluster_kev_rate"] = np.nan
    for cutoff, ix in df.groupby("history_cutoff").groups.items():
        g, prior = rate_table(h, "cluster_id", cutoff)
        cid = out.loc[ix, "cluster_id"]
        out.loc[ix, "cluster_kev_rate"] = cid.map(g["rate"]).where(cid >= 0).fillna(prior).to_numpy()
    return out


# ---------------------------------------------------------------- main
def main() -> None:
    seed_everything()
    kev = data_io.load_kev()
    hist = data_io.load_vulns(["cve_id", "published", "assigner", "description", "cwe_ids"])
    hist = hist[hist["published"] >= HISTORY_START].merge(kev[["cve_id", "date_added"]], on="cve_id", how="left")
    vendor_rx = build_vendor_regex(kev)
    hist["assigner_org"] = hist["assigner"].map(assigner_org)
    hist["desc_vendor"] = first_match(hist["description"], vendor_rx)
    hist["cwe_primary"] = primary_cwe(hist["cwe_ids"])

    try:
        from .embed import load_embeddings

        emb, idx = load_embeddings()
    except FileNotFoundError:
        print("embeddings missing; text features = NaN (run src.embed)")
        emb, idx = None, None

    splits = {n: pd.read_parquet(PROCESSED_DIR / f"{n}.parquet") for n in ("train_A", "valid", "train_final", "predict")}
    feats = {}
    for name, df in splits.items():
        parts = [
            df[["cve_id", "published", "snapshot_month", "label", "epss", "epss_pct", *FLAGS, "n_exploit_flags",
                "days_to_label_cutoff", "history_cutoff"]],
            history_features(df, hist, kev, vendor_rx),
            text_keyword_features(df),
            caution_features(df),
            cluster_features(df, hist),
        ]
        if emb is not None:
            parts.append(embedding_features(df, emb, idx, kev))
            parts.append(text_lr_features(df, hist, emb, idx).rename("text_lr_score"))
        f = pd.concat(parts, axis=1)
        for c in ("kev_sim_max", "kev_sim_mean_top5", "text_lr_score"):
            if c not in f:
                f[c] = np.nan
        feats[name] = f
        print(f"{name:12s} {f.shape} positives={f['label'].sum() if name != 'predict' else 'n/a'}")

    for name, f in feats.items():
        f.to_parquet(PROCESSED_DIR / f"features_{name}.parquet", index=False)

    # Quick univariate look at the itw phrase for docs/findings.
    v = feats["valid"]
    print("desc_itw_phrase on valid:", v.groupby("desc_itw_phrase")["label"].agg(["count", "sum", "mean"]).to_dict())
    print("desc_itw_phrase on predict count:", int(feats["predict"]["desc_itw_phrase"].sum()))
    (OUTPUT_DIR / "feature_groups.txt").write_text("\n".join(f"{k}: {v}" for k, v in FEATURE_GROUPS.items()))


if __name__ == "__main__":
    main()
