"""Build train_A / valid / train_final / predict splits that mirror the scoreboard (CLAUDE.md section 5).

python -m src.build_dataset
"""
from __future__ import annotations

import pandas as pd

from . import data_io
from .config import PROCESSED_DIR, SPLITS, seed_everything

FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def month_end(month: pd.Series) -> pd.Series:
    return pd.PeriodIndex(month, freq="M").to_timestamp(how="end").normalize()


def history_cutoff(published: pd.Series) -> pd.Series:
    """KEV history allowed for a row = up to Dec 31 of the year before publication."""
    return pd.to_datetime((published.dt.year - 1).astype(str) + "-12-31")


def add_common(df: pd.DataFrame, kev: pd.DataFrame, label_cutoff: str | None) -> pd.DataFrame:
    df = df.merge(kev[["cve_id", "date_added"]], on="cve_id", how="left")
    df["snapshot_end"] = month_end(df["snapshot_month"])
    df["history_cutoff"] = history_cutoff(df["published"])
    # "Free time" before the snapshot: late-month CVEs often have no EPSS/flags yet. Capped at 30 so
    # scoreboard June CVEs (July snapshot, 31-60 days) map to the closest training case.
    df["days_before_snapshot"] = (df["snapshot_end"] - df["published"]).dt.days.clip(upper=30)
    if label_cutoff is not None:
        cutoff = pd.Timestamp(label_cutoff)
        df["label"] = ((df["date_added"] > df["snapshot_end"]) & (df["date_added"] <= cutoff)).astype("int8")
        df["days_to_label_cutoff"] = (cutoff - df["snapshot_end"]).dt.days
    # Within-month percentile: EPSS changed models in 2025-03 and 2026, raw values aren't comparable.
    df["epss_pct"] = df.groupby("snapshot_month")["epss"].rank(pct=True)
    df["n_exploit_flags"] = df[FLAGS].sum(axis=1).astype("int8")
    return df


def build_training_split(name: str, vulns: pd.DataFrame, kev: pd.DataFrame, signals: pd.DataFrame) -> pd.DataFrame:
    spec = SPLITS[name]
    df = vulns[(vulns["published"] >= spec["start"]) & (vulns["published"] <= spec["end"])].copy()
    sig_months = set(signals["month"].unique())
    pub_month = df["published"].dt.to_period("M")
    nxt = (pub_month + 1).astype(str)
    df["snapshot_month"] = pub_month.astype(str)
    missing = ~df["snapshot_month"].isin(sig_months)
    df.loc[missing, "snapshot_month"] = nxt[missing]
    if missing.any():
        print(f"  [{name}] {missing.sum()} rows moved to next month (signals month absent)")

    sig = signals[["month", "cve_id", "epss", "in_kev", *FLAGS]].rename(columns={"month": "snapshot_month"})
    df = df.merge(sig, on=["cve_id", "snapshot_month"], how="left")
    df[FLAGS] = df[FLAGS].fillna(0).astype("int8")
    df["in_kev"] = df["in_kev"].fillna(0).astype("int8")

    df = add_common(df, kev, spec["label_cutoff"])
    before = len(df)
    already = (df["date_added"] <= df["snapshot_end"]) | (df["in_kev"] == 1)
    df = df[~already].drop(columns=["in_kev"]).reset_index(drop=True)
    print(f"  [{name}] dropped {before - len(df)} rows already in KEV at snapshot")
    return df


def build_predict(vulns: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    sb = data_io.load_scoreboard()
    v = vulns.drop(columns=["published"])
    df = sb.merge(v, on="cve_id", how="left")
    n_missing = df["description"].isna().sum()
    print(f"  [predict] scoreboard rows without a vulnerabilities.csv match: {n_missing}")
    df["description"] = df["description"].fillna("")
    df = add_common(df, kev, label_cutoff=None)
    # KEV file ends 2025-12-31, so scoreboard labels are unknown (judges use KEV through 2026-11-04).
    n_kev = df["date_added"].notna().sum()
    print(f"  [predict] scoreboard rows already in KEV file (zero-day style, date before publish): {n_kev}")
    df["label"] = float("nan")
    df["days_to_label_cutoff"] = (pd.Timestamp(SPLITS["predict"]["label_cutoff"]) - df["snapshot_end"]).dt.days
    return df


def summarize(name: str, df: pd.DataFrame) -> None:
    pos = df["label"].sum() if df["label"].notna().any() else "n/a"
    print(
        f"{name:12s} rows={len(df):>7,} positives={pos} "
        f"published={df['published'].min().date()}..{df['published'].max().date()} "
        f"snapshots={df['snapshot_month'].min()}..{df['snapshot_month'].max()} "
        f"epss_missing={df['epss'].isna().mean():.1%}"
    )


def main() -> None:
    seed_everything()
    print("loading raw data ...")
    vulns = data_io.load_vulns()
    kev = data_io.load_kev()
    months = [f"{y}-{m:02d}" for y in (2024, 2025) for m in range(1, 13)]
    signals = data_io.load_signals(months)
    # Drop rejected IDs (in signals but not in vulnerabilities.csv).
    signals = signals[signals["cve_id"].isin(vulns["cve_id"])]
    print(f"vulns={len(vulns):,} kev={len(kev):,} signals={len(signals):,}")

    for name in ("train_A", "valid", "train_final", "validV1", "trainV2", "validV2", "trainV0", "validV0"):
        df = build_training_split(name, vulns, kev, signals)
        # Leakage asserts.
        pos = df[df["label"] == 1]
        assert (pos["date_added"] > pos["snapshot_end"]).all()
        assert (df["history_cutoff"] < df["published"]).all()
        summarize(name, df)
        df.to_parquet(PROCESSED_DIR / f"{name}.parquet", index=False)

    df = build_predict(vulns, kev)
    summarize("predict", df)
    df.to_parquet(PROCESSED_DIR / "predict.parquet", index=False)


if __name__ == "__main__":
    main()
