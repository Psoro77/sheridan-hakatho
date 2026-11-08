"""Data for the app's story visuals: breachlight-app/public/data/story.json

- map: 2-D UMAP (from the cached 15-D UMAP) of a sample of CVEs + all past KEV + the top 500
- groups: clusters with readable names (duplicates merged), past KEV rate, lift
- needles: rank of each 2026 KEV positive under each ordering, read from outputs/check_2026.json
  (REPORT ONLY output of src/check_2026.py; this script never reads the live labels itself)

python -m src.story_export
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from .config import OUTPUT_DIR, PROCESSED_DIR, REPO_DIR, SEED
from .data_io import load_kev

OUT = REPO_DIR / "breachlight-app" / "public" / "data" / "story.json"
N_SAMPLE = 14000
M = 20  # smoothing, same as the features

# Hand names from each cluster's c-TF-IDF keywords + samples (display only).
NAMES = {
    19: "Google Chrome", 21: "Google Chrome", 18: "Google Chrome", 97: "Microsoft Edge",
    100: "Windows use-after-free", 102: "Windows elevation of privilege", 106: "Windows heap overflow",
    63: "Microsoft remote code execution", 65: "Microsoft Office", 51: "Ivanti Connect Secure",
    23: "Apple iOS / iPadOS", 24: "Apple iOS / iPadOS", 44: "Telerik deserialization",
    1: "Oracle WebLogic / Fusion", 11: "Oracle products", 48: "FortiOS / FortiProxy",
    126: "Cisco ASA / FTD", 127: "Cisco web management", 89: "PHP CMS frameworks", 53: "Joomla extensions",
    68: "AI agent platforms (MCP)", 67: "Flowise LLM apps", 69: "Open WebUI", 43: "XML external entity",
    134: "Router command injection", 136: "Wavlink / Linksys routers", 137: "D-Link routers",
    46: "CRM software", 28: "NVIDIA drivers", 66: "Juniper Junos", 123: "Tar archive extraction",
    42: "Qualcomm memory corruption", 30: "F5 BIG-IP", 124: "OS command injection", 8: "JetBrains TeamCity",
    110: "PHP file upload", 115: "Path traversal (PHP)", 72: "File inclusion (LFI)", 108: "DLL hijacking",
    -1: "Unclustered",
}


def fallback(name: str) -> str:
    parts = [p.strip() for p in str(name).split(",")][:2]
    return " / ".join(p[:1].upper() + p[1:] for p in parts)


def main() -> None:
    rng = np.random.default_rng(SEED)
    ids = pd.read_parquet(PROCESSED_DIR / "embedding_ids.parquet")
    clus = pd.read_parquet(PROCESSED_DIR / "clusters.parquet")
    assert (clus["cve_id"].to_numpy() == ids["cve_id"].to_numpy()).all()
    Z = np.load(PROCESSED_DIR / "umap15.npy")
    pred = pd.read_parquet(OUTPUT_DIR / "predictions.parquet", columns=["cve_id", "rank"])
    top = set(pred.loc[pred["rank"] <= 500, "cve_id"])
    kev = set(load_kev().query("date_added <= '2025-12-31'")["cve_id"])

    cid = clus["cve_id"].to_numpy()
    is_top, is_kev = np.isin(cid, list(top)), np.isin(cid, list(kev))
    keep = is_top | is_kev
    keep[rng.choice(np.flatnonzero(~keep), N_SAMPLE, replace=False)] = True
    idx = np.flatnonzero(keep)
    print(f"map points {len(idx):,} (top500 {is_top.sum()}, past KEV {is_kev.sum()})")

    import umap
    xy = umap.UMAP(n_components=2, n_neighbors=25, min_dist=0.6, spread=1.5, metric="euclidean",
                   random_state=SEED).fit_transform(Z[idx])
    xy = (xy - xy.min(0)) / (xy.max(0) - xy.min(0))
    xy = np.round(xy * 1000).astype(int)

    # groups: merge clusters that share a display name
    c = pd.read_csv(OUTPUT_DIR / "clusters.csv")
    c["display"] = [NAMES.get(i, fallback(n)) for i, n in zip(c["cluster_id"], c["name"])]
    prior = float((c["kev_rate_train"] / c["lift_vs_prior"]).median())
    top_by_cluster = clus[np.isin(cid, list(top))]["cluster_id"].value_counts()
    c["n_top500"] = c["cluster_id"].map(top_by_cluster).fillna(0).astype(int)
    g = (c.groupby("display").agg(ids=("cluster_id", list), size=("size", "sum"), hits=("kev_hits_train", "sum"),
                                  n=("n_train", "sum"), scoreboard=("n_scoreboard", "sum"), top500=("n_top500", "sum"))
         .reset_index())
    g["lift"] = ((g["hits"] + M * prior) / (g["n"] + M)) / prior
    g.loc[g["display"] == "Unclustered", "lift"] = 1.0
    g = g.sort_values("lift", ascending=False).reset_index(drop=True)
    gidx = {cl: i for i, row in g.iterrows() for cl in row["ids"]}

    pg = np.array([gidx.get(int(x), -1) for x in clus["cluster_id"].to_numpy()[idx]])
    kind = is_top[idx].astype(int) * 2 + is_kev[idx].astype(int)  # 0 other, 1 past KEV, 2 top500, 3 both
    groups = []
    for i, row in g.iterrows():
        pts = xy[pg == i]
        cx, cy = (np.median(pts, 0).astype(int).tolist() if len(pts) else [None, None])
        groups.append({"name": row["display"], "size": int(row["size"]), "kevHits": int(row["hits"]),
                       "lift": round(float(row["lift"]), 2), "scoreboard": int(row["scoreboard"]),
                       "top500": int(row["top500"]), "cx": cx, "cy": cy})

    top_ids = pred.loc[pred["rank"] <= 500, "cve_id"]
    cl_of = clus.set_index("cve_id")["cluster_id"]
    group_of = {i: gidx.get(int(cl_of.get(i, -1)), -1) for i in top_ids}

    check = json.loads((OUTPUT_DIR / "check_2026.json").read_text())
    story = {
        "map": {"x": xy[:, 0].tolist(), "y": xy[:, 1].tolist(), "g": pg.tolist(), "k": kind.tolist()},
        "groups": groups,
        "groupOf": group_of,
        "needles": {"universe": 72670, "cutoff": "2026-11-04", "ranks": check["positive_ranks"]},
    }
    OUT.write_text(json.dumps(story, separators=(",", ":")))
    print(f"wrote {OUT} ({OUT.stat().st_size / 1e6:.2f} MB), {len(groups)} groups")
    print(g.head(15)[["display", "size", "hits", "lift", "top500"]].to_string())


if __name__ == "__main__":
    main()
