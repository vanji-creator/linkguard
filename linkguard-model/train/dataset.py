"""
dataset.py — PyTorch Dataset for hybrid URL classification.

Each item contains:
  • input_ids       (LongTensor)  — tokenized URL
  • attention_mask  (LongTensor)
  • url_features    (FloatTensor) — 50-dim hand-crafted features
  • label           (LongTensor)  — 0=safe, 1=suspicious, 2=dangerous
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import BASE_MODEL, MAX_SEQ_LEN, NUM_URL_FEATURES
from serve.features import extract as extract_features


class URLDataset(Dataset):
    def __init__(self, parquet_path: str | Path, tokenizer: AutoTokenizer,
                 max_len: int = MAX_SEQ_LEN, precompute_features: bool = True):
        """
        Args:
            parquet_path:        Path to a processed .parquet file.
            tokenizer:           HuggingFace tokenizer.
            max_len:             Max token sequence length.
            precompute_features: Extract all URL features upfront (faster training).
        """
        df = pd.read_parquet(parquet_path)
        self.urls    = df["url"].tolist()
        self.labels  = df["label_id"].tolist()
        self.tokenizer = tokenizer
        self.max_len   = max_len

        if precompute_features:
            print(f"  Pre-computing URL features for {len(self.urls):,} samples...")
            self.features = np.stack([
                extract_features(u) for u in tqdm(self.urls, leave=False)
            ])  # shape: (N, 50)
        else:
            self.features = None

    def __len__(self) -> int:
        return len(self.urls)

    def __getitem__(self, idx: int) -> dict:
        url   = self.urls[idx]
        label = self.labels[idx]

        encoding = self.tokenizer(
            url,
            max_length=self.max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        feats = (
            torch.from_numpy(self.features[idx])
            if self.features is not None
            else torch.from_numpy(extract_features(url))
        )

        return {
            "input_ids":      encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "url_features":   feats,
            "label":          torch.tensor(label, dtype=torch.long),
        }
