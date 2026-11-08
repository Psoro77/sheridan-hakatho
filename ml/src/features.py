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
        "desc_product_kev_count", "desc_product_kev_rate", "desc_product_kev_12m", "kev_vendor_kev_12m",
        *PRODUCT_KEYWORDS, *ATTACK_KEYWORDS, "desc_len",
    ],
    "text": ["kev_sim_max", "kev_sim_mean_top5", "text_lr_score"],
    "prior": ["prior_lr_score"],
    "sibling": ["sib_batch_size", "sib_max_text_lr", "sib_any_flag", "sib_any_itw", "sib_max_epss_pct"],
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


def matcher_for(kev: pd.DataFrame, cutoff: pd.Timestamp) -> Matcher:
    if cutoff not in _MATCHERS:
        _MATCHERS[cutoff] = Matcher(kev, cutoff)
    return _MATCHERS[cutoff]


def hist_as_of(hist: pd.DataFrame, kev: pd.DataFrame, cutoff: pd.Timestamp) -> pd.DataFrame:
    """History CVEs published by `cutoff`, matched with the cutoff's own vocabulary."""
    if cutoff not in _HIST_H:
        h = hist[hist["published"] <= cutoff].copy()
        h[["desc_vendor", "desc_product", "kev_vendor"]] = matcher_for(kev, cutoff).match(h["description"])
        _HIST_H[cutoff] = h
        print(f"  history as of {cutoff.date()}: {len(h):,} CVEs, vendor matched {h['kev_vendor'].notna().mean():.1%}")
    return _HIST_H[cutoff]


def history_features(df: pd.DataFrame, hist: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    df = df.assign(assigner_org=df["assigner"].map(assigner_org), cwe_primary=primary_cwe(df["cwe_ids"]))
    cols = ("assigner_kev_count", "assigner_kev_rate", "assigner_n_hist", "desc_vendor_kev_count",
            "desc_vendor_kev_rate", "cwe_kev_rate", "desc_product_kev_count", "desc_product_kev_rate",
            "desc_product_kev_12m", "kev_vendor_kev_12m", "kev_vendor_kev_count")
    for col in cols:
        out[col] = np.nan
    for c in ("desc_vendor", "desc_product", "kev_vendor"):
        out[c] = None
    for cutoff, idx in df.groupby("history_cutoff").groups.items():
        m = matcher_for(kev, cutoff)
        h = hist_as_of(hist, kev, cutoff)
        sub = pd.concat([df.loc[idx], m.match(df.loc[idx, "description"])], axis=1)
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
        # CWE (caution group)
        g, prior = rate_table(h, "cwe_primary", cutoff)
        out.loc[idx, "cwe_kev_rate"] = sub["cwe_primary"].map(g["rate"]).fillna(prior).to_numpy()
    out["vendor_kev_count"] = np.where(out["kev_vendor"].notna(), out["kev_vendor_kev_count"], out["assigner_kev_count"])
    # Display name only (not a model feature): UUID CNAs get the vendor their descriptions name most.
    disp = df["assigner_org"].map(assigner_display_names(hist_as_of(hist, kev, df["history_cutoff"].max())))
    out["vendor"] = out["kev_vendor"].fillna(disp).fillna(df["assigner_org"])
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
    hist["assigner_org"] = hist["assigner"].map(assigner_org)
    hist["cwe_primary"] = primary_cwe(hist["cwe_ids"])

    try:
        from .embed import load_embeddings

        emb, idx = load_embeddings()
    except FileNotFoundError:
        print("embeddings missing; text features = NaN (run src.embed)")
        emb, idx = None, None

    splits = {n: pd.read_parquet(PROCESSED_DIR / f"{n}.parquet") for n in ("train_A", "valid", "train_final", "trainB", "validB", "predict")}
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
        f = pd.concat([f, sibling_features(f, df)], axis=1)
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
