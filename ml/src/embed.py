"""Granite embeddings for CVE descriptions (cached, resumable).

Embeds every CVE published since EMBED_START (needed for train, valid, predict and for
past-only history rates) plus every KEV CVE. Output:
  data/processed/embeddings.npy       float16 [n, dim], L2-normalized
  data/processed/embedding_ids.parquet  cve_id, row

python -m src.embed
"""
from __future__ import annotations

import sys
import time

import numpy as np
import pandas as pd

from . import data_io
from .config import EMBED_BATCH, EMBED_MAX_LEN, EMBED_MODEL, PROCESSED_DIR, seed_everything

EMBED_START = "2022-01-01"
CHUNK = 4096
EMB_PATH = PROCESSED_DIR / "embeddings.npy"
IDS_PATH = PROCESSED_DIR / "embedding_ids.parquet"
CHUNK_DIR = PROCESSED_DIR / "emb_chunks"


def load_embeddings() -> tuple[np.ndarray, pd.Series]:
    """Return (matrix, Series mapping cve_id -> row)."""
    emb = np.load(EMB_PATH)
    ids = pd.read_parquet(IDS_PATH)
    return emb, pd.Series(ids["row"].to_numpy(), index=ids["cve_id"].to_numpy())


def texts_to_embed() -> pd.DataFrame:
    v = data_io.load_vulns(["cve_id", "published", "description"])
    kev_ids = set(data_io.load_kev()["cve_id"])
    keep = (v["published"] >= EMBED_START) | v["cve_id"].isin(kev_ids)
    v = v[keep].copy()
    v["description"] = v["description"].fillna("").str.slice(0, 4000)
    # Newest first so the scoreboard and valid rows are done earliest.
    return v.sort_values(["published", "cve_id"], ascending=[False, True]).reset_index(drop=True)


def main() -> None:
    if EMB_PATH.exists() and IDS_PATH.exists():
        print(f"cache exists: {EMB_PATH}; delete it to recompute")
        return
    seed_everything()
    import torch
    from sentence_transformers import SentenceTransformer

    torch.set_num_threads(max(1, torch.get_num_threads()))
    df = texts_to_embed()
    print(f"texts to embed: {len(df):,}")
    model = SentenceTransformer(
        EMBED_MODEL, device="cuda" if torch.cuda.is_available() else "cpu",
        model_kwargs={"dtype": torch.float32},  # bf16 default is very slow on CPU
    )
    model.max_seq_length = EMBED_MAX_LEN
    CHUNK_DIR.mkdir(exist_ok=True)

    n_chunks = (len(df) + CHUNK - 1) // CHUNK
    t0 = time.time()
    for i in range(n_chunks):
        path = CHUNK_DIR / f"chunk_{i:04d}.npy"
        if path.exists():
            continue
        texts = df["description"].iloc[i * CHUNK : (i + 1) * CHUNK].tolist()
        e = model.encode(texts, batch_size=EMBED_BATCH, normalize_embeddings=True, show_progress_bar=False)
        np.save(path, e.astype(np.float16))
        el = time.time() - t0
        print(f"chunk {i + 1}/{n_chunks} done, {el / 60:.1f} min elapsed", flush=True)
        sys.stdout.flush()

    emb = np.concatenate([np.load(CHUNK_DIR / f"chunk_{i:04d}.npy") for i in range(n_chunks)])
    assert len(emb) == len(df)
    np.save(EMB_PATH, emb)
    pd.DataFrame({"cve_id": df["cve_id"], "row": np.arange(len(df))}).to_parquet(IDS_PATH, index=False)
    print(f"saved {emb.shape} to {EMB_PATH}")


if __name__ == "__main__":
    main()
