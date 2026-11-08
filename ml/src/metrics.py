"""Ranking metrics. Never accuracy."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score


def hits_at_k(y: np.ndarray, score: np.ndarray, k: int) -> int:
    y = np.asarray(y)
    order = np.argsort(-np.asarray(score, dtype=float), kind="stable")
    return int(y[order[:k]].sum())


def ranking_report(y, score) -> dict:
    y = np.asarray(y).astype(int)
    s = np.nan_to_num(np.asarray(score, dtype=float), nan=-1e9)
    return {
        "hits@100": hits_at_k(y, s, 100),
        "hits@500": hits_at_k(y, s, 500),
        "hits@1000": hits_at_k(y, s, 1000),
        "pr_auc": round(float(average_precision_score(y, s)), 5) if y.sum() else None,
        "n": int(len(y)),
        "positives": int(y.sum()),
    }


def lexsort_score(df: pd.DataFrame, keys: list[str]) -> np.ndarray:
    """Turn a multi-key descending sort (NaN last) into a single rank-score (higher = better)."""
    tmp = df[keys].copy()
    for k in keys:
        tmp[k] = tmp[k].astype(float).fillna(-1e9)
    order = tmp.sort_values(keys, ascending=False, kind="mergesort").index
    score = pd.Series(np.arange(len(df), 0, -1, dtype=float), index=order)
    return score.reindex(df.index).to_numpy()


def baseline_scores(df: pd.DataFrame) -> dict[str, np.ndarray]:
    """The three track baselines. Ties broken by EPSS so they're deterministic."""
    flags = df[["exploitdb", "metasploit", "nuclei", "poc_github"]].sum(axis=1)
    tmp = df.assign(_any_flag=(flags > 0).astype(int))
    return {
        "cvss_first": lexsort_score(tmp, ["cvss3_score", "epss"]),
        "epss_first": lexsort_score(tmp, ["epss"]),
        "exploit_then_epss": lexsort_score(tmp, ["_any_flag", "epss"]),
    }
