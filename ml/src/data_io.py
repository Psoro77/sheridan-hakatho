"""Column-selective loaders for the raw CSVs."""
from __future__ import annotations

import pandas as pd

from .config import RAW_DIR

_CSV_KW = dict(quotechar='"', escapechar=None, doublequote=True, low_memory=False)

VULN_COLS = [
    "cve_id", "published", "assigner", "description",
    "cvss3_score", "attack_vector", "attack_complexity", "privileges_required",
    "user_interaction", "scope", "confidentiality_impact", "integrity_impact",
    "availability_impact", "cvss3_impact_score", "cvss4_score", "cwe_ids",
]


def load_vulns(cols: list[str] | None = None) -> pd.DataFrame:
    cols = cols or VULN_COLS
    df = pd.read_csv(RAW_DIR / "vulnerabilities.csv", usecols=cols, dtype=str, **_CSV_KW)
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    for c in ("cvss3_score", "cvss3_impact_score", "cvss4_score"):
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def load_kev() -> pd.DataFrame:
    df = pd.read_csv(
        RAW_DIR / "known_exploited.csv",
        usecols=["cve_id", "vendor", "product", "date_added", "known_ransomware_use", "cwe_ids"],
        dtype=str, **_CSV_KW,
    )
    df["date_added"] = pd.to_datetime(df["date_added"])
    return df.drop_duplicates("cve_id")


def load_signals(months: list[str] | None = None) -> pd.DataFrame:
    """Monthly EPSS + exploit flags. Optionally filter to given YYYY-MM months."""
    parts = []
    for year in (2024, 2025):
        df = pd.read_csv(
            RAW_DIR / f"exploit_signals_{year}.csv",
            dtype={"month": str, "cve_id": str},
            **_CSV_KW,
        )
        if months is not None:
            df = df[df["month"].isin(months)]
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    for c in ("in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int8")
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    return df


def load_scoreboard() -> pd.DataFrame:
    df = pd.read_csv(RAW_DIR / "scoreboard_2026.csv", dtype={"cve_id": str, "snapshot_month": str}, **_CSV_KW)
    df["published"] = pd.to_datetime(df["published"])
    for c in ("exploitdb", "metasploit", "nuclei", "poc_github"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int8")
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    return df


def load_weakness_types() -> pd.DataFrame:
    return pd.read_csv(RAW_DIR / "weakness_types.csv", usecols=["cwe_id", "name"], dtype=str, **_CSV_KW)
