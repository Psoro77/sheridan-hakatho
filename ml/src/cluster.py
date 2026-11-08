"""Vulnerability clusters: Granite embeddings -> UMAP(15d) -> HDBSCAN (CLAUDE.md section 6).

Unsupervised and text-only, so fitting on all descriptions (incl. 2026) is allowed. KEV rates
computed here are for the Discovery slide only (as of 2025-12-31); model features recompute them
per history cutoff in features.py.

HDBSCAN has no predict(), so we fit UMAP + HDBSCAN on a SAMPLE and assign every CVE by
k-nearest-neighbour vote in UMAP space.

python -m src.cluster
"""
from __future__ import annotations

import json
import time

import numpy as np
import pandas as pd
from sklearn.cluster import HDBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import KNeighborsClassifier

from . import data_io
from .config import OUTPUT_DIR, PROCESSED_DIR, SEED, SMOOTH_M, seed_everything
from .embed import load_embeddings

SAMPLE = 40_000
MIN_CLUSTER = 50
OUT = PROCESSED_DIR / "clusters.parquet"


def name_clusters(desc: pd.Series, labels: np.ndarray, top: int = 5) -> dict[int, str]:
    """c-TF-IDF: treat each cluster's concatenated descriptions as one document."""
    df = pd.DataFrame({"d": desc.fillna("").to_numpy(), "c": labels})
    df = df[df["c"] >= 0]
    docs = df.groupby("c")["d"].apply(lambda s: " ".join(s.sample(min(len(s), 400), random_state=SEED)))
    vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=2, max_df=0.5,
                          token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]{2,}\b", sublinear_tf=True)
    M = vec.fit_transform(docs.to_numpy())
    terms = np.array(vec.get_feature_names_out())
    names = {}
    for i, c in enumerate(docs.index):
        row = M[i].toarray().ravel()
        names[int(c)] = ", ".join(terms[np.argsort(-row)[:top]])
    return names


def main() -> None:
    seed_everything()
    if OUT.exists():
        print(f"cluster cache exists: {OUT} (delete to refit); rebuilding the Discovery table only")
        discovery_table(pd.read_parquet(OUT))
        return
    import umap

    emb, idx = load_embeddings()
    ids = pd.Series(idx.index, index=idx.to_numpy()).sort_index()
    X = emb.astype(np.float32)
    rng = np.random.default_rng(SEED)
    sample = np.sort(rng.choice(len(X), size=min(SAMPLE, len(X)), replace=False))

    t0 = time.time()
    reducer = umap.UMAP(n_components=15, n_neighbors=30, min_dist=0.0, metric="cosine", random_state=SEED)
    Zs = reducer.fit_transform(X[sample])
    print(f"UMAP fit on {len(sample):,} in {time.time() - t0:.0f}s", flush=True)
    Z = reducer.transform(X)
    print(f"UMAP transform all {len(X):,} in {time.time() - t0:.0f}s", flush=True)

    hdb = HDBSCAN(min_cluster_size=MIN_CLUSTER, min_samples=10)
    ls = hdb.fit_predict(Zs)
    print(f"HDBSCAN: {ls.max() + 1} clusters, noise {np.mean(ls == -1):.1%} ({time.time() - t0:.0f}s)", flush=True)

    knn = KNeighborsClassifier(n_neighbors=15).fit(Zs, ls)
    labels = knn.predict(Z)
    labels[sample] = ls
    cl = pd.DataFrame({"cve_id": ids.to_numpy(), "cluster_id": labels.astype(int)})
    cl.to_parquet(OUT, index=False)
    np.save(PROCESSED_DIR / "umap15.npy", Z.astype(np.float32))
    discovery_table(cl)


def discovery_table(cl: pd.DataFrame) -> None:
    """Cluster KEV rates for the Discovery slide. Only CVEs published 2022..2025: before 2022 only KEV
    CVEs were embedded (no negatives), which made old KEV favourites look like the top clusters."""
    from .embed import EMBED_START

    v = data_io.load_vulns(["cve_id", "published", "description"])
    kev = data_io.load_kev()
    sb = set(data_io.load_scoreboard()["cve_id"])
    d = cl.merge(v, on="cve_id", how="left").merge(kev[["cve_id", "date_added"]], on="cve_id", how="left")
    d = d[d["published"] >= EMBED_START]
    names = name_clusters(d["description"], d["cluster_id"].to_numpy())
    cutoff = pd.Timestamp("2025-12-31")
    hist = d[(d["published"] <= cutoff)]
    hit = (hist["date_added"] <= cutoff).astype(int)
    prior = hit.mean()
    g = hist.assign(hit=hit).groupby("cluster_id")["hit"].agg(["sum", "count"])
    table = pd.DataFrame({
        "cluster_id": g.index,
        "name": [names.get(int(c), "noise / unclustered") for c in g.index],
        "size": d.groupby("cluster_id").size().reindex(g.index).to_numpy(),
        "kev_hits_train": g["sum"].to_numpy(),
        "kev_rate_train": ((g["sum"] + SMOOTH_M * prior) / (g["count"] + SMOOTH_M)).round(5).to_numpy(),
        "n_scoreboard": d[d["cve_id"].isin(sb)].groupby("cluster_id").size().reindex(g.index).fillna(0).astype(int).to_numpy(),
    })
    table["lift_vs_prior"] = (table["kev_rate_train"] / prior).round(2)
    table["n_train"] = g["count"].to_numpy()
    table = table.sort_values("kev_rate_train", ascending=False)
    table.to_csv(OUTPUT_DIR / "clusters.csv", index=False)

    # 10 sample descriptions per cluster for optional LLM naming.
    samples = {
        int(c): grp["description"].dropna().sample(min(10, len(grp)), random_state=SEED).str.slice(0, 300).tolist()
        for c, grp in d[d["cluster_id"] >= 0].groupby("cluster_id")
    }
    (OUTPUT_DIR / "cluster_samples.json").write_text(json.dumps(samples, indent=1))
    print(f"global prior {prior:.5f}")
    print(table.head(15).to_string(index=False))


if __name__ == "__main__":
    main()
