"""
preprocess.py — Build the labeled training dataset from raw feeds.

Steps:
  1. Load each feed → assign label
  2. Normalize URLs (lowercase, strip scheme for dedup key)
  3. Deduplicate
  4. Cap per-class size (config.py)
  5. Stratified train/val/test split
  6. Save to data/processed/{train,val,test}.parquet

Usage:
    python data/preprocess.py

Output files:
    data/processed/train.parquet
    data/processed/val.parquet
    data/processed/test.parquet
    data/processed/stats.txt
"""

import sys
import re
import random
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    RAW_DIR, PROCESSED_DIR,
    LABEL2ID, TRAIN_RATIO, VAL_RATIO, TEST_RATIO, SEED,
    MAX_SAFE_SAMPLES, MAX_DANGEROUS_SAMPLES, MAX_SUSPICIOUS_SAMPLES,
)

random.seed(SEED)
np.random.seed(SEED)


# ── Normalization ──────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Lowercase, strip whitespace. Keep scheme for the model."""
    url = url.strip().lower()
    # Remove trailing slash from root path
    if url.endswith("/") and url.count("/") <= 3:
        url = url.rstrip("/")
    return url


def dedup_key(url: str) -> str:
    """Key for deduplication: strip scheme so http/https variants collapse."""
    url = url.lower().strip()
    for prefix in ("https://", "http://", "ftp://"):
        if url.startswith(prefix):
            return url[len(prefix):]
    return url


def is_valid_url(url: str) -> bool:
    """Basic sanity check — must have a parseable hostname."""
    if not url or len(url) < 8 or len(url) > 2000:
        return False
    try:
        u = urlparse(url if "://" in url else "http://" + url)
        return bool(u.hostname) and len(u.hostname) > 1
    except Exception:
        return False


# ── Loaders ────────────────────────────────────────────────────────────────────

def load_urlhaus() -> pd.DataFrame:
    """URLhaus text feed — one URL per line, lines starting with # are comments."""
    path = RAW_DIR / "urlhaus.txt"
    if not path.exists():
        print("  ⚠  URLhaus file not found — run collect.py first")
        return pd.DataFrame(columns=["url", "label"])

    urls = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    df = pd.DataFrame({"url": urls, "label": "dangerous"})
    print(f"  URLhaus: {len(df):,} URLs")
    return df


def load_openphish() -> pd.DataFrame:
    """OpenPhish text feed — one URL per line."""
    path = RAW_DIR / "openphish.txt"
    if not path.exists():
        print("  ⚠  OpenPhish file not found — run collect.py first")
        return pd.DataFrame(columns=["url", "label"])

    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    df = pd.DataFrame({"url": urls, "label": "dangerous"})
    print(f"  OpenPhish: {len(df):,} URLs")
    return df


def load_threatfox() -> pd.DataFrame:
    """ThreatFox — plain text file produced by collect.py from bulk CSV."""
    path = RAW_DIR / "threatfox.txt"
    if not path.exists():
        print("  ⚠  ThreatFox file not found — run collect.py first")
        return pd.DataFrame(columns=["url", "label"])

    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [l.strip() for l in f if l.strip()]

    df = pd.DataFrame({"url": urls, "label": "dangerous"})
    print(f"  ThreatFox: {len(df):,} URLs/domains")
    return df


def load_phishing_database() -> pd.DataFrame:
    """mitchellkrogza/Phishing.Database — one URL per line, plain text."""
    path = RAW_DIR / "phishing_database.txt"
    if not path.exists():
        print("  ⚠  Phishing.Database file not found — run collect.py first")
        return pd.DataFrame(columns=["url", "label"])

    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    df = pd.DataFrame({"url": urls, "label": "dangerous"})
    print(f"  Phishing.Database: {len(df):,} URLs")
    return df


def load_tranco() -> pd.DataFrame:
    """
    Tranco top-1M CSV — rank,domain (no scheme).
    We prefix with https:// and treat as safe.
    We use only a subset for balance (configured via MAX_SAFE_SAMPLES).
    """
    path = RAW_DIR / "tranco_top1m.csv"
    if not path.exists():
        print("  ⚠  Tranco file not found — run collect.py first")
        return pd.DataFrame(columns=["url", "label"])

    domains = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domains.append("https://" + parts[1].strip())

    df = pd.DataFrame({"url": domains, "label": "safe"})
    print(f"  Tranco top-1M: {len(df):,} domains")
    return df


# ── Main pipeline ──────────────────────────────────────────────────────────────

def main():
    print("\n=== LinkGuard — Data Preprocessing ===\n")

    print("[1/5] Loading feeds...")
    frames = [
        load_urlhaus(),
        load_openphish(),
        load_threatfox(),
        load_phishing_database(),
        load_tranco(),
    ]
    df = pd.concat([f for f in frames if not f.empty], ignore_index=True)
    print(f"\n  Total raw: {len(df):,} URLs")

    print("\n[2/5] Normalizing and filtering...")
    df["url"] = df["url"].astype(str).apply(normalize_url)
    before = len(df)
    df = df[df["url"].apply(is_valid_url)].copy()
    print(f"  Valid URLs: {len(df):,} (dropped {before - len(df):,} invalid)")

    print("\n[3/5] Deduplicating...")
    df["_key"] = df["url"].apply(dedup_key)
    # When same URL appears in multiple feeds, 'dangerous' beats 'safe'
    priority = {"dangerous": 0, "suspicious": 1, "safe": 2}
    df["_prio"] = df["label"].map(priority)
    df = df.sort_values("_prio").drop_duplicates(subset="_key", keep="first")
    df = df.drop(columns=["_key", "_prio"])
    print(f"  After dedup: {len(df):,} URLs")

    print("\n[4/5] Balancing classes...")

    # Cap dangerous first, then set safe cap dynamically to 2× dangerous
    # so class ratio never exceeds 1:2 regardless of source failures.
    dangerous_subset = df[df["label"] == "dangerous"]
    if MAX_DANGEROUS_SAMPLES and len(dangerous_subset) > MAX_DANGEROUS_SAMPLES:
        dangerous_subset = dangerous_subset.sample(MAX_DANGEROUS_SAMPLES, random_state=SEED)

    dynamic_safe_cap = min(len(dangerous_subset) * 2,
                           MAX_SAFE_SAMPLES if MAX_SAFE_SAMPLES else 10_000_000)
    safe_subset = df[df["label"] == "safe"]
    if len(safe_subset) > dynamic_safe_cap:
        safe_subset = safe_subset.sample(dynamic_safe_cap, random_state=SEED)

    suspicious_subset = df[df["label"] == "suspicious"]
    if MAX_SUSPICIOUS_SAMPLES and len(suspicious_subset) > MAX_SUSPICIOUS_SAMPLES:
        suspicious_subset = suspicious_subset.sample(MAX_SUSPICIOUS_SAMPLES, random_state=SEED)

    for label, subset in [("dangerous", dangerous_subset),
                           ("safe", safe_subset),
                           ("suspicious", suspicious_subset)]:
        print(f"  {label:12s}: {len(subset):>8,}")

    parts = [dangerous_subset, safe_subset, suspicious_subset]

    df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=SEED)
    df["label_id"] = df["label"].map({"safe": 0, "suspicious": 1, "dangerous": 2})
    print(f"\n  Total for training: {len(df):,} URLs")

    print("\n[5/5] Splitting train/val/test...")
    # Stratified split
    train_df, temp_df = train_test_split(
        df, test_size=(VAL_RATIO + TEST_RATIO),
        stratify=df["label_id"], random_state=SEED
    )
    relative_test = TEST_RATIO / (VAL_RATIO + TEST_RATIO)
    val_df, test_df = train_test_split(
        temp_df, test_size=relative_test,
        stratify=temp_df["label_id"], random_state=SEED
    )

    for split_name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
        out = PROCESSED_DIR / f"{split_name}.parquet"
        split_df[["url", "label", "label_id"]].to_parquet(out, index=False)
        counts = split_df["label"].value_counts().to_dict()
        print(f"  {split_name:6s}: {len(split_df):>7,}  {counts}")

    # Write stats
    stats_path = PROCESSED_DIR / "stats.txt"
    with open(stats_path, "w") as f:
        f.write(f"Total: {len(df)}\n")
        f.write(f"Train: {len(train_df)}\n")
        f.write(f"Val:   {len(val_df)}\n")
        f.write(f"Test:  {len(test_df)}\n")
        f.write("\nClass distribution (full):\n")
        f.write(df["label"].value_counts().to_string())

    print(f"\n✓ Done. Files saved to {PROCESSED_DIR}/")
    print("  Next: python train/train.py\n")


if __name__ == "__main__":
    main()
