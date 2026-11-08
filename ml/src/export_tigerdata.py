"""Load outputs/predictions.parquet (and clusters.csv) into TigerData (Postgres).

Set TIGERDATA_URL, e.g. postgres://user:pass@host:port/tsdb?sslmode=require
python -m src.export_tigerdata
"""
from __future__ import annotations

import os
import sys

import pandas as pd

from .config import OUTPUT_DIR

DDL = """
CREATE TABLE IF NOT EXISTS cve_predictions (
    cve_id TEXT PRIMARY KEY,
    published DATE,
    snapshot_month TEXT,
    vendor TEXT,
    p_exploit DOUBLE PRECISION,
    rank INTEGER,
    tier TEXT,
    epss_pct DOUBLE PRECISION,
    exploit_flags JSONB,
    impact_score DOUBLE PRECISION,
    cluster_id INTEGER,
    cluster_name TEXT,
    reasons JSONB,
    shap_top JSONB,
    kev_likelihood DOUBLE PRECISION,
    exploit_automation DOUBLE PRECISION,
    technical_impact DOUBLE PRECISION
);
CREATE TABLE IF NOT EXISTS vuln_clusters (
    cluster_id INTEGER PRIMARY KEY,
    name TEXT,
    size INTEGER,
    kev_hits_train INTEGER,
    kev_rate_train DOUBLE PRECISION,
    n_scoreboard INTEGER,
    lift_vs_prior DOUBLE PRECISION,
    n_train INTEGER
);
"""


def copy_df(cur, table: str, df: pd.DataFrame) -> None:
    cur.execute(f"TRUNCATE {table}")
    cols = ", ".join(df.columns)
    with cur.copy(f"COPY {table} ({cols}) FROM STDIN") as cp:
        for row in df.itertuples(index=False):
            cp.write_row([None if (isinstance(v, float) and pd.isna(v)) else v for v in row])


def main() -> None:
    url = os.environ.get("TIGERDATA_URL")
    if not url:
        sys.exit("Set TIGERDATA_URL to the TigerData connection string.")
    import psycopg

    pred = pd.read_parquet(OUTPUT_DIR / "predictions.parquet")
    pred["published"] = pd.to_datetime(pred["published"]).dt.date
    clusters = pd.read_csv(OUTPUT_DIR / "clusters.csv") if (OUTPUT_DIR / "clusters.csv").exists() else None
    with psycopg.connect(url) as conn, conn.cursor() as cur:
        cur.execute(DDL)
        copy_df(cur, "cve_predictions", pred)
        if clusters is not None:
            copy_df(cur, "vuln_clusters", clusters)
        conn.commit()
    print(f"loaded {len(pred):,} predictions" + (f" and {len(clusters)} clusters" if clusters is not None else ""))


if __name__ == "__main__":
    main()
