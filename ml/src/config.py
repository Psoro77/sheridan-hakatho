"""Central configuration: paths, splits, constants. See CLAUDE.md sections 5 to 7."""
from __future__ import annotations

import os
import random
from pathlib import Path

import numpy as np

SEED = 42

ML_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = ML_DIR.parent
# Raw data lives in IBM/data/data by default; override with AEGIS_RAW_DIR (e.g. ml/data/raw).
RAW_DIR = Path(os.environ.get("AEGIS_RAW_DIR", REPO_DIR / "IBM" / "data" / "data"))
PROCESSED_DIR = ML_DIR / "data" / "processed"
OUTPUT_DIR = ML_DIR / "outputs"
MODEL_DIR = ML_DIR / "models"
DOCS_DIR = ML_DIR / "docs"
for _d in (PROCESSED_DIR, OUTPUT_DIR, MODEL_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# Split definitions (CLAUDE.md section 5).
# History cutoff is per row = Dec 31 of the year before the row's publish year (see history_cutoff()).
SPLITS = {
    "train_A": {"start": "2024-01-01", "end": "2024-12-31", "label_cutoff": "2024-12-31"},
    "valid": {"start": "2025-01-01", "end": "2025-09-30", "label_cutoff": "2025-12-31"},
    "train_final": {"start": "2024-01-01", "end": "2025-09-30", "label_cutoff": "2025-12-31"},
    # Two DISJOINT validation periods (each exploited CVE counted once):
    #   V1: train_A (2024, labels to 2024-12-31) -> validV1 (2025-01..04)
    #   V2: trainV2 (2024-01..2025-04, labels to 2025-04-30) -> validV2 (2025-05..09)
    "validV1": {"start": "2025-01-01", "end": "2025-04-30", "label_cutoff": "2025-12-31"},
    "trainV2": {"start": "2024-01-01", "end": "2025-04-30", "label_cutoff": "2025-04-30"},
    "validV2": {"start": "2025-05-01", "end": "2025-09-30", "label_cutoff": "2025-12-31"},
    #   V0: trainV0 (2024-01..06, labels to 2024-06-30) -> validV0 (2024-07..12, labels to 2025-04-30).
    #   Horizons 120-273 days mirror the scoreboard's 35-277; adds a third disjoint set of positives.
    "trainV0": {"start": "2024-01-01", "end": "2024-06-30", "label_cutoff": "2024-06-30"},
    "validV0": {"start": "2024-07-01", "end": "2024-12-31", "label_cutoff": "2025-04-30"},
    # predict comes from scoreboard_2026.csv; judges count KEV through 2026-11-04.
    "predict": {"start": "2026-01-01", "end": "2026-09-30", "label_cutoff": "2026-11-04"},
}

# Earliest publish date used to build history denominators (vendor / CWE / cluster rates).
HISTORY_START = "2021-01-01"

SMOOTH_M = 20
TOP_K = 500
SCOREBOARD_ROWS = 72_670  # validation depth is scaled: k = TOP_K * n_rows / SCOREBOARD_ROWS

# Granite R2-small (ModernBERT) ran at 12 texts/s on our CPU (~5.5 h for 235k texts); Granite
# 30m-english (R1) at 128 tokens runs 63 texts/s (~1 h). Both are IBM Granite; see docs/columns_used.md.
EMBED_MODEL = "ibm-granite/granite-embedding-30m-english"
EMBED_MAX_LEN = 128
EMBED_BATCH = 32

PRODUCT_KEYWORDS = {
    "kw_vpn": r"\bvpn\b|ssl[- ]vpn|globalprotect|anyconnect",
    "kw_firewall": r"firewall|fortigate|pan-os|asa\b",
    "kw_gateway": r"gateway",
    "kw_router": r"router|routers",
    "kw_edge": r"\bedge device|\bedge\b",
    "kw_appliance": r"appliance",
    "kw_exchange": r"exchange server|microsoft exchange",
    "kw_sharepoint": r"sharepoint",
    "kw_citrix": r"citrix|netscaler",
    "kw_load_balancer": r"load balancer|big-ip|application delivery controller",
    "kw_file_transfer": r"file transfer|moveit|goanywhere|\bmft\b|\bsftp\b|crushftp|cleo",
    "kw_cms": r"\bcms\b|content management|drupal|joomla",
    "kw_plugin": r"plugin|plug-in|wordpress",
    "kw_windows": r"\bwindows\b",
    "kw_browser": r"chrome|chromium|webkit|safari|firefox|v8\b",
    "kw_kernel": r"\bkernel\b",
    "kw_iot_camera": r"camera|\bdvr\b|\bnvr\b|\bnas\b",
}
ATTACK_KEYWORDS = {
    "kw_unauth": r"unauthenticated|without authentication|remote attacker(s)? (?:can|could|to)|no authentication",
    "kw_rce": r"remote code execution|execute arbitrary code|arbitrary code execution|execute arbitrary commands",
    "kw_cmd_injection": r"command injection|os command|inject(ion of)? arbitrary commands",
    "kw_auth_bypass": r"authentication bypass|bypass authentication|bypass the authentication",
    "kw_deserialization": r"deseriali[sz]",
    "kw_path_traversal": r"path traversal|directory traversal|\.\./",
    "kw_sqli": r"sql injection",
    "kw_privesc": r"privilege escalation|escalate privileges|elevation of privilege|gain (root|elevated|system) privileges",
    "kw_memory_corruption": r"use[- ]after[- ]free|out[- ]of[- ]bounds write|heap overflow|buffer overflow|type confusion",
    "kw_xss": r"cross[- ]site scripting|\bxss\b",
    "kw_ssrf": r"server[- ]side request forgery|\bssrf\b",
    "kw_file_upload": r"file upload|upload arbitrary files",
    "kw_dos": r"denial of service",
}
# Caution group (CLAUDE.md section 4): phrases stating exploitation.
ITW_PATTERN = (
    r"exploited in the wild|aware of a report|aware of reports|actively exploited|"
    r"has been exploited|may have been exploited|being exploited|known to be exploited|limited, targeted"
)


def seed_everything(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import torch

        torch.manual_seed(seed)
    except ImportError:
        pass
