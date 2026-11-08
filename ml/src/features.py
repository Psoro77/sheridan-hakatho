"""Feature engineering (CLAUDE.md section 6). Re-read section 4 (leakage) before editing.

Every history-based feature for a row uses only KEV entries with date_added <= the row's
history_cutoff (Dec 31 of the year before publication) and only CVEs published by then.

python -m src.features
"""
from __future__ import annotations

import os
import re
import warnings

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from . import data_io
from .config import (
    ATTACK_KEYWORDS, HISTORY_START, ITW_PATTERN, OUTPUT_DIR, PROCESSED_DIR,
    PRODUCT_KEYWORDS, REPO_DIR, SEED, SMOOTH_M, seed_everything,
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
STACKED = ("text_lr_score", "prior_lr_score", "prior_gbm_score")
PRODUCT_STOP = {
    "Kernel", "Framework", "Server", "Software", "Devices", "Products", "Office", "Word", "Webmail",
    "HTTP Server", "Mobile Devices", "Multiple", "Firmware", "Application", "Platform", "Client", "Router",
    "Routers", "Gateway", "Agent", "Manager", "Console", "Portal", "Suite", "System", "Service", "Driver",
    "Excel", "Edge", "Pixel", "Windows Server", "Plugin", "Appliance", "Firewall",
}

FEATURE_GROUPS = {
    "exploit": ["epss_pct", *FLAGS, "n_exploit_flags", "days_to_label_cutoff", "days_before_snapshot"],
    "vendor_kw": [
        "assigner_kev_count", "assigner_kev_rate", "assigner_n_hist",
        "desc_vendor_kev_count", "desc_vendor_kev_rate", "vendor_kev_count",
        "desc_product_kev_count", "desc_product_kev_rate", "desc_product_kev_12m", "kev_vendor_kev_12m", "kev_vendor_kev_rate",
        *PRODUCT_KEYWORDS, *ATTACK_KEYWORDS, "desc_len",
    ],
    "text": ["kev_sim_max", "kev_sim_mean_top5", "text_lr_score"],
    "prior": ["prior_lr_score", "prior_gbm_score"],
    "sibling": ["sib_batch_size", "sib_max_text_lr", "sib_any_flag", "sib_any_itw", "sib_max_epss_pct"],
    # Batch size as a percentile within the snapshot month: 2026 CVE volume doubled (Microsoft went from
    # ~100 to 470-998 CVEs a month), so the raw count extrapolates far outside the training range.
    "sibling_rel": ["sib_batch_pct"],
    # Point-in-time KEV (round 5): KEV additions between the annual history cutoff and the END of the
    # row's snapshot month. Known at snapshot time. For training/validation the provided KEV file covers
    # it; for the scoreboard it needs the live KEV feed, so these are OFF for predict unless
    # BREACHLIGHT_USE_LIVE_KEV=1 (team decision, see docs/columns_used.md).
    "fresh": ["kev_vendor_fresh", "assigner_kev_fresh", "sib_kev_fresh"],
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


def product_tokens(kev: pd.DataFrame) -> pd.DataFrame:
    """Split CISA product names ("iOS, iPadOS, and macOS") into matchable tokens with their vendor."""
    rows = []
    for vendor, prod, added in kev[["vendor", "product", "date_added"]].itertuples(index=False):
        if not isinstance(prod, str):
            continue
        parts = {prod.strip(), *(p.strip() for p in re.split(r",\s*|\s+and\s+|/|\(|\)", prod))}
        for p in parts:
            if len(p) >= 3 and len(p) <= 40 and p not in PRODUCT_STOP and not p.startswith("Multiple"):
                rows.append((p, vendor, added))
    return pd.DataFrame(rows, columns=["token", "vendor", "date_added"]).drop_duplicates()


class Matcher:
    """Vendor/product vocabulary built ONLY from KEV entries known at a history cutoff."""

    def __init__(self, kev: pd.DataFrame, cutoff: pd.Timestamp):
        k = kev[kev["date_added"] <= cutoff]
        self.cutoff = cutoff
        self.kev = k
        self.vendor_rx = build_vendor_regex(k)
        self.tokens = product_tokens(k)
        names = sorted(self.tokens["token"].unique(), key=len, reverse=True)
        self.product_rx = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")
        self.token_vendor = self.tokens.groupby("token")["vendor"].agg(lambda s: s.value_counts().index[0])

    def match(self, desc: pd.Series) -> pd.DataFrame:
        clean = strip_itw(desc)
        v = first_match(clean, self.vendor_rx)
        p = first_match(clean, self.product_rx)
        kv = v.fillna(p.map(self.token_vendor))
        return pd.DataFrame({"desc_vendor": v, "desc_product": p, "kev_vendor": kv}, index=desc.index)


_SENT = re.compile(r"(?<=[.!?])\s+")
_ITW_RX = re.compile(ITW_PATTERN, re.IGNORECASE)


def strip_itw(desc: pd.Series) -> pd.Series:
    """Drop sentences stating exploitation before vendor matching (fixes 'Apple is aware...' in a
    WhatsApp CVE being matched as vendor Apple)."""
    def f(t: str) -> str:
        if not t or not _ITW_RX.search(t):
            return t
        return " ".join(s for s in _SENT.split(t) if not _ITW_RX.search(s))
    return desc.fillna("").map(f)


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
_MATCHERS: dict = {}
_HIST_H: dict = {}
_ASSIGNER_VENDOR: dict = {}


def matcher_for(kev: pd.DataFrame, cutoff: pd.Timestamp) -> Matcher:
    if cutoff not in _MATCHERS:
        _MATCHERS[cutoff] = Matcher(kev, cutoff)
    return _MATCHERS[cutoff]


def hist_as_of(hist: pd.DataFrame, kev: pd.DataFrame, cutoff: pd.Timestamp) -> pd.DataFrame:
    """History CVEs published by `cutoff`, matched with the cutoff's own vocabulary."""
    if cutoff not in _HIST_H:
        h = hist[hist["published"] <= cutoff].copy()
        h[["desc_vendor", "desc_product", "kev_vendor"]] = matcher_for(kev, cutoff).match(h["description"])
        # Assigner -> KEV vendor (e.g. psirt@sonicwall.com -> SonicWall), from past KEV CVEs only.
        kh = h[h["date_added"] <= cutoff][["cve_id", "assigner_org"]].merge(kev[["cve_id", "vendor"]], on="cve_id")
        amap = {}
        for org, s in kh.groupby("assigner_org")["vendor"]:
            vc = s.value_counts()
            if vc.iloc[0] >= 3 and vc.iloc[0] / len(s) >= 0.5:
                amap[org] = vc.index[0]
        _ASSIGNER_VENDOR[cutoff] = amap
        h["kev_vendor"] = h["kev_vendor"].fillna(h["assigner_org"].map(amap))
        _HIST_H[cutoff] = h
        print(f"  history as of {cutoff.date()}: {len(h):,} CVEs, vendor matched {h['kev_vendor'].notna().mean():.1%}")
    return _HIST_H[cutoff]


def history_features(df: pd.DataFrame, hist: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    df = df.assign(assigner_org=df["assigner"].map(assigner_org), cwe_primary=primary_cwe(df["cwe_ids"]))
    cols = ("assigner_kev_count", "assigner_kev_rate", "assigner_n_hist", "desc_vendor_kev_count",
            "desc_vendor_kev_rate", "cwe_kev_rate", "desc_product_kev_count", "desc_product_kev_rate",
            "desc_product_kev_12m", "kev_vendor_kev_12m", "kev_vendor_kev_count", "kev_vendor_kev_rate")
    for col in cols:
        out[col] = np.nan
    for c in ("desc_vendor", "desc_product", "kev_vendor"):
        out[c] = None
    for cutoff, idx in df.groupby("history_cutoff").groups.items():
        m = matcher_for(kev, cutoff)
        h = hist_as_of(hist, kev, cutoff)
        sub = pd.concat([df.loc[idx], m.match(df.loc[idx, "description"])], axis=1)
        sub["kev_vendor"] = sub["kev_vendor"].fillna(sub["assigner_org"].map(_ASSIGNER_VENDOR[cutoff]))
        for c in ("desc_vendor", "desc_product", "kev_vendor"):
            out.loc[idx, c] = sub[c].to_numpy()
        kev_past = m.kev
        recent = kev_past[kev_past["date_added"] > cutoff - pd.Timedelta(days=365)]
        # assigner
        g, prior = rate_table(h, "assigner_org", cutoff)
        out.loc[idx, "assigner_kev_rate"] = sub["assigner_org"].map(g["rate"]).fillna(prior).to_numpy()
        out.loc[idx, "assigner_n_hist"] = sub["assigner_org"].map(g["count"]).fillna(0).to_numpy()
        out.loc[idx, "assigner_kev_count"] = sub["assigner_org"].map(g["sum"]).fillna(0).to_numpy()
        # vendor named in description (CISA vendor names)
        g, prior = rate_table(h, "desc_vendor", cutoff)
        out.loc[idx, "desc_vendor_kev_rate"] = sub["desc_vendor"].map(g["rate"]).fillna(prior).to_numpy()
        out.loc[idx, "desc_vendor_kev_count"] = sub["desc_vendor"].map(kev_past["vendor"].value_counts()).fillna(0).to_numpy()
        # product named in description (CISA product tokens) and the product's vendor
        g, prior = rate_table(h, "desc_product", cutoff)
        out.loc[idx, "desc_product_kev_rate"] = sub["desc_product"].map(g["rate"]).fillna(prior).to_numpy()
        tok_all = m.tokens["token"].value_counts()
        tok_recent = m.tokens.loc[m.tokens["date_added"] > cutoff - pd.Timedelta(days=365), "token"].value_counts()
        out.loc[idx, "desc_product_kev_count"] = sub["desc_product"].map(tok_all).fillna(0).to_numpy()
        out.loc[idx, "desc_product_kev_12m"] = sub["desc_product"].map(tok_recent).fillna(0).to_numpy()
        out.loc[idx, "kev_vendor_kev_count"] = sub["kev_vendor"].map(kev_past["vendor"].value_counts()).fillna(0).to_numpy()
        out.loc[idx, "kev_vendor_kev_12m"] = sub["kev_vendor"].map(recent["vendor"].value_counts()).fillna(0).to_numpy()
        g, prior = rate_table(h, "kev_vendor", cutoff)
        out.loc[idx, "kev_vendor_kev_rate"] = sub["kev_vendor"].map(g["rate"]).fillna(prior).to_numpy()
        # CWE (caution group)
        g, prior = rate_table(h, "cwe_primary", cutoff)
        out.loc[idx, "cwe_kev_rate"] = sub["cwe_primary"].map(g["rate"]).fillna(prior).to_numpy()
    out["vendor_kev_count"] = np.where(out["kev_vendor"].notna(), out["kev_vendor_kev_count"], out["assigner_kev_count"])
    # Display name only (not a model feature): UUID CNAs get the vendor their descriptions name most.
    disp = df["assigner_org"].map(assigner_display_names(hist_as_of(hist, kev, df["history_cutoff"].max())))
    raw_org = df["assigner_org"].map(lambda a: f"CNA {a[:8]}" if re.fullmatch(r"[0-9a-f\-]{36}", a or "") else str(a).capitalize())
    out["vendor"] = out["kev_vendor"].fillna(disp).fillna(raw_org)
    return out.drop(columns=["desc_vendor"])


_DISPLAY: dict = {}


def assigner_display_names(hist: pd.DataFrame) -> dict:
    if not _DISPLAY:
        is_uuid = hist["assigner_org"].str.fullmatch(r"[0-9a-f\-]{36}", na=False)
        h = hist[is_uuid].dropna(subset=["kev_vendor"])
        top = h.groupby("assigner_org")["kev_vendor"].agg(lambda s: s.value_counts().index[0])
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


def embedding_features(df: pd.DataFrame, emb: np.ndarray, idx: pd.Series, kev: pd.DataFrame,
                       history_rows: bool = False) -> pd.DataFrame:
    """history_rows=True (prior-model training rows only): a row already in past KEV would match
    itself, so its similarity is set to NaN instead of asserting."""
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
        self_hit = df.loc[sub_ix, "cve_id"].isin(kev_set).to_numpy()
        if history_rows:
            out.loc[sub_ix[self_hit], ["kev_sim_max", "kev_sim_mean_top5"]] = np.nan
        else:
            assert not self_hit.any(), "row already in past KEV"
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


_PRIOR_CACHE: dict = {}
KW_COLS = [*PRODUCT_KEYWORDS, *ATTACK_KEYWORDS, "desc_itw_phrase"]


def _prior_design(d: pd.DataFrame, kw: pd.DataFrame, emb, idx, vocab: dict | None):
    """Sparse design: [embedding | keyword flags | one-hot vendor / product / assigner]."""
    from scipy import sparse

    r = d["cve_id"].map(idx)
    ok = r.notna().to_numpy()
    E = np.zeros((len(d), emb.shape[1]), dtype=np.float32)
    E[ok] = emb[r[ok].astype(int).to_numpy()]
    keys = {"v": d["kev_vendor"], "p": d["desc_product"], "a": d["assigner_org"]}
    if vocab is None:
        vocab, j = {}, 0
        for pfx, s in keys.items():
            vc = s.value_counts()
            for k in vc[vc >= 10].index:
                vocab[(pfx, k)] = j
                j += 1
    rows, cols = [], []
    for pfx, s in keys.items():
        codes = [vocab.get((pfx, k), -1) for k in s.to_numpy()]
        for i, c in enumerate(codes):
            if c >= 0:
                rows.append(i)
                cols.append(c)
    OH = sparse.csr_matrix((np.ones(len(rows), dtype=np.float32), (rows, cols)), shape=(len(d), max(1, len(vocab))))
    X = sparse.hstack([sparse.csr_matrix(E), sparse.csr_matrix(kw[KW_COLS].to_numpy(np.float32)), OH]).tocsr()
    return X, vocab


def prior_lr_features(df: pd.DataFrame, f: pd.DataFrame, hist: pd.DataFrame, kev, emb, idx) -> pd.Series:
    """Past-only 'prior' model (H6): like text_lr, but adds keyword flags and one-hot vendor, product
    and assigner. For cutoff H, fit on CVEs published 2022..H (label = in KEV by H); rows scored are
    all published after H."""
    from .embed import EMBED_START

    out = pd.Series(np.nan, index=df.index)
    for cutoff, ix in df.groupby("history_cutoff").groups.items():
        if cutoff not in _PRIOR_CACHE:
            h = hist_as_of(hist, kev, cutoff)
            h = h[h["published"] >= EMBED_START]
            X, vocab = _prior_design(h, text_keyword_features(h), emb, idx, None)
            y = (h["date_added"] <= cutoff).to_numpy().astype(int)
            m = LogisticRegression(C=0.3, max_iter=4000, class_weight="balanced", random_state=SEED).fit(X, y)
            _PRIOR_CACHE[cutoff] = (m, vocab)
            print(f"  prior_lr fit for cutoff {cutoff.date()}: n={len(y):,} positives={y.sum()} one-hot={len(vocab)}")
        m, vocab = _PRIOR_CACHE[cutoff]
        d = pd.DataFrame({"cve_id": df.loc[ix, "cve_id"], "kev_vendor": f.loc[ix, "kev_vendor"],
                          "desc_product": f.loc[ix, "desc_product"],
                          "assigner_org": df.loc[ix, "assigner"].map(assigner_org)})
        X, _ = _prior_design(d, f.loc[ix], emb, idx, vocab)
        out.loc[ix] = m.decision_function(X)
    return out


# Tabular features the tree prior uses; for history rows each is computed as of the end of the
# year BEFORE that row's publication (same rule as scored rows), so no row sees its own label.
PRIOR_GBM_COLS = [
    *KW_COLS, "desc_len", "assigner_kev_rate", "assigner_n_hist", "desc_vendor_kev_rate",
    "desc_product_kev_rate", "desc_product_kev_count", "desc_product_kev_12m",
    "kev_vendor_kev_count", "kev_vendor_kev_12m", "kev_vendor_kev_rate",
    "kev_sim_max", "kev_sim_mean_top5", "cluster_kev_rate",
]
_PRIOR_GBM: dict = {}
_HIST_FEATS: dict = {}


def history_row_features(hist: pd.DataFrame, kev: pd.DataFrame, emb, idx) -> pd.DataFrame:
    """PRIOR_GBM_COLS for every history CVE published 2022..2025, each as of Dec 31 of the year
    before its publication. Cached (computed once)."""
    from .embed import EMBED_START

    if "f" not in _HIST_FEATS:
        h = hist[(hist["published"] >= EMBED_START) & (hist["published"] <= "2025-12-31")].copy()
        h["history_cutoff"] = pd.to_datetime((h["published"].dt.year - 1).astype(str) + "-12-31")
        parts = [h[["cve_id", "published", "date_added"]], history_features(h, hist, kev), text_keyword_features(h),
                 embedding_features(h, emb, idx, kev, history_rows=True), cluster_features(h, hist)]
        _HIST_FEATS["f"] = pd.concat(parts, axis=1)
        print(f"  history-row features (as-of prior year): {_HIST_FEATS['f'].shape}")
    return _HIST_FEATS["f"]


def prior_gbm_features(df: pd.DataFrame, f: pd.DataFrame, hist: pd.DataFrame, kev, emb, idx) -> pd.Series:
    """Tree prior (no EPSS/flags): shallow LightGBM on history CVEs published 2022..H, label = added to
    KEV within 365 days of publication and by H. Learns interactions the linear prior can't (hot
    vendor x auth bypass x network product). Rows scored are all published after H."""
    import lightgbm as lgb

    hf = history_row_features(hist, kev, emb, idx)
    out = pd.Series(np.nan, index=df.index)
    params = dict(objective="binary", learning_rate=0.03, num_leaves=8, max_depth=3, min_child_samples=30,
                  feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1, lambda_l2=10.0, verbose=-1)
    for cutoff, ix in df.groupby("history_cutoff").groups.items():
        if cutoff not in _PRIOR_GBM:
            h = hf[hf["published"] <= cutoff]
            y = ((h["date_added"] <= cutoff) & (h["date_added"] <= h["published"] + pd.Timedelta(days=365))).astype(int)
            pos = int(y.sum())
            p = {**params, "scale_pos_weight": float(np.sqrt((len(y) - pos) / max(pos, 1)))}
            models = [lgb.train({**p, "seed": SEED + s}, lgb.Dataset(h[PRIOR_GBM_COLS].astype(float), y), 400)
                      for s in range(3)]
            _PRIOR_GBM[cutoff] = models
            print(f"  prior_gbm fit for cutoff {cutoff.date()}: n={len(y):,} positives={pos}")
        X = f.loc[ix, PRIOR_GBM_COLS].astype(float)
        out.loc[ix] = np.mean([m.predict(X, raw_score=True) for m in _PRIOR_GBM[cutoff]], axis=0)
    return out


def sibling_features(f: pd.DataFrame, df: pd.DataFrame, window_days: int = 3) -> pd.DataFrame:
    """Same-assigner CVEs in the same snapshot month published within +-window days (H5).
    Uses only snapshot-time values of the siblings (no sibling labels)."""
    d = pd.DataFrame({
        "org": df["assigner"].map(assigner_org).to_numpy(), "snap": f["snapshot_month"].to_numpy(),
        "t": (f["published"] - pd.Timestamp("2020-01-01")).dt.days.to_numpy(),
        "lr": f["text_lr_score"].fillna(-99).to_numpy(), "flag": (f["n_exploit_flags"] > 0).to_numpy(),
        "itw": f["desc_itw_phrase"].to_numpy() == 1, "epss": f["epss_pct"].fillna(0).to_numpy(),
    }, index=f.index)
    res = np.zeros((len(d), 5))
    pos = {k: i for i, k in enumerate(d.index)}
    for _, g in d.groupby(["org", "snap"], sort=False):
        g = g.sort_values("t")
        t = g["t"].to_numpy()
        lo = np.searchsorted(t, t - window_days, side="left")
        hi = np.searchsorted(t, t + window_days, side="right")
        lr, fl, it, ep = g["lr"].to_numpy(), g["flag"].to_numpy(), g["itw"].to_numpy(), g["epss"].to_numpy()
        for j, gi in enumerate(g.index):
            sl = np.r_[lo[j]:j, j + 1:hi[j]]
            if len(sl) == 0:
                res[pos[gi]] = (0, np.nan, 0, 0, np.nan)
            else:
                res[pos[gi]] = (len(sl), lr[sl].max(), fl[sl].any(), it[sl].any(), ep[sl].max())
    out = pd.DataFrame(res, index=f.index, columns=FEATURE_GROUPS["sibling"])
    out.loc[out["sib_max_text_lr"] <= -98, "sib_max_text_lr"] = np.nan
    return out


USE_LIVE_KEV = os.environ.get("BREACHLIGHT_USE_LIVE_KEV") == "1"
LIVE_KEV_PATH = REPO_DIR / "IBM" / "data" / "external" / "kev_live" / "kev_full_2026-11-06.csv"


def point_in_time_kev(kev: pd.DataFrame, split: str) -> pd.DataFrame:
    """KEV table for the 'fresh' features. Training/validation splits: the provided file (ends
    2025-12-31, which is after every training snapshot). Scoreboard: the provided file only, unless the
    team opts in to the live feed; every use is still truncated per row at its snapshot end."""
    if split != "predict" or not USE_LIVE_KEV:
        return kev[["cve_id", "vendor", "date_added"]]
    live = pd.read_csv(LIVE_KEV_PATH, usecols=["cve_id", "vendor", "date_added"], dtype=str)
    live["date_added"] = pd.to_datetime(live["date_added"])
    live = live[live["date_added"] > kev["date_added"].max()]
    print(f"  [predict] BREACHLIGHT_USE_LIVE_KEV=1: {len(live)} live KEV entries after {kev['date_added'].max().date()}")
    return pd.concat([kev[["cve_id", "vendor", "date_added"]], live]).drop_duplicates("cve_id")


def _window_count(keys: pd.Series, lo: pd.Series, hi: pd.Series, ev_keys: pd.Series, ev_dates: pd.Series) -> np.ndarray:
    """For each row: number of events with the same key and lo < date <= hi."""
    out = np.zeros(len(keys))
    dates = {k: np.sort(g.to_numpy()) for k, g in ev_dates.groupby(ev_keys.to_numpy())}
    lo_v, hi_v = lo.to_numpy(), hi.to_numpy()
    for i, k in enumerate(keys.to_numpy()):
        d = dates.get(k)
        if d is not None and isinstance(k, str):
            out[i] = np.searchsorted(d, hi_v[i], side="right") - np.searchsorted(d, lo_v[i], side="right")
    return out


def fresh_kev_features(f: pd.DataFrame, df: pd.DataFrame, hist: pd.DataFrame, kev_pit: pd.DataFrame) -> pd.DataFrame:
    """KEV additions known at the end of the row's snapshot month but after its annual history cutoff.
    kev_vendor_fresh: same resolved vendor. assigner_kev_fresh: CVEs from the same CNA.
    sib_kev_fresh: same-CNA CVEs published within +-3 days that were already in KEV at snapshot end
    (chained bugs: one added at once, its sibling later)."""
    out = pd.DataFrame(index=f.index)
    hc = pd.to_datetime(f["history_cutoff"])
    se = pd.PeriodIndex(f["snapshot_month"], freq="M").to_timestamp(how="end").normalize()
    se = pd.Series(se, index=f.index)
    k = kev_pit.dropna(subset=["date_added"])
    out["kev_vendor_fresh"] = _window_count(f["kev_vendor"], hc, se, k["vendor"], k["date_added"])
    # CNA of each KEV CVE (from vulnerabilities.csv; KEV CVEs published before 2021 are irrelevant here).
    ka = k.merge(hist[["cve_id", "assigner_org", "published"]], on="cve_id", how="inner")
    org = df["assigner"].map(assigner_org)
    out["assigner_kev_fresh"] = _window_count(org, hc, se, ka["assigner_org"], ka["date_added"])
    rows = pd.DataFrame({"org": org.to_numpy(), "t": f["published"].to_numpy(), "se": se.to_numpy(),
                         "cve": f["cve_id"].to_numpy(), "i": np.arange(len(f))})
    kk = ka[ka["published"] >= rows["t"].min() - pd.Timedelta(days=3)][["cve_id", "assigner_org", "published", "date_added"]]
    m = rows.merge(kk, left_on="org", right_on="assigner_org")
    m = m[((m["published"] - m["t"]).abs() <= pd.Timedelta(days=3)) & (m["date_added"] <= m["se"]) & (m["cve_id"] != m["cve"])]
    out["sib_kev_fresh"] = np.bincount(m["i"].to_numpy(), minlength=len(f)).astype(float)
    # Leakage guard: no row may itself be in KEV by its snapshot end.
    own = f[["cve_id"]].merge(k[["cve_id", "date_added"]], on="cve_id", how="left")["date_added"].to_numpy()
    assert not (pd.notna(own) & (own <= se.to_numpy())).any(), "row already in KEV at snapshot end"
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
    from .embed import EMBED_START

    # Only CVEs that were embedded as a full population (published >= EMBED_START). Before 2022 only
    # KEV CVEs were embedded, so including them made every older cluster look 100% exploited.
    h = hist[hist["published"] >= EMBED_START]
    h = h.assign(cluster_id=h["cve_id"].map(cl))
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
    hist["assigner_org"] = hist["assigner"].map(assigner_org)
    hist["cwe_primary"] = primary_cwe(hist["cwe_ids"])

    try:
        from .embed import load_embeddings

        emb, idx = load_embeddings()
    except FileNotFoundError:
        print("embeddings missing; text features = NaN (run src.embed)")
        emb, idx = None, None

    splits = {n: pd.read_parquet(PROCESSED_DIR / f"{n}.parquet")
              for n in ("train_A", "valid", "train_final", "validV1", "trainV2", "validV2", "trainV0", "validV0", "predict")}
    feats = {}
    for name, df in splits.items():
        parts = [
            df[["cve_id", "published", "snapshot_month", "label", "epss", "epss_pct", *FLAGS, "n_exploit_flags",
                "days_to_label_cutoff", "days_before_snapshot", "history_cutoff"]],
            history_features(df, hist, kev),
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
        f["prior_lr_score"] = prior_lr_features(df, f, hist, kev, emb, idx) if emb is not None else np.nan
        f["prior_gbm_score"] = prior_gbm_features(df, f, hist, kev, emb, idx) if emb is not None else np.nan
        # Stacked scores come from a different model per history cutoff, so their raw scale shifts
        # (e.g. text_lr mean -2.3 in training vs -1.3 on predict). Use the percentile within each
        # cutoff group instead (same idea as epss_pct). Raw values kept for diagnostics only.
        for c in STACKED:
            f[f"{c}_raw"] = f[c]
            f[c] = f.groupby("history_cutoff")[c].rank(pct=True)
        f = pd.concat([f, sibling_features(f, df)], axis=1)
        f["sib_batch_pct"] = f.groupby("snapshot_month")["sib_batch_size"].rank(pct=True)
        f = pd.concat([f, fresh_kev_features(f, df, hist, point_in_time_kev(kev, name))], axis=1)
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
