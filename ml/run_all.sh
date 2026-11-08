#!/usr/bin/env bash
# Full pipeline, one command (each step is idempotent; embeddings and clusters are cached).
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-../.venv/Scripts/python}
$PY -m src.build_dataset
$PY -m src.embed
$PY -m src.cluster
$PY -m src.features
$PY -m src.train --split train_A --eval valid
$PY -m src.evaluate
$PY -m src.train --split train_final
$PY -m src.predict
$PY -m src.explain
# $PY -m src.export_tigerdata   # needs TIGERDATA_URL
