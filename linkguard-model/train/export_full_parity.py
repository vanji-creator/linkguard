"""
export_full_parity.py
---------------------
Write the FULL differential-test file: every URL from the final honest
test split (the exact same domain-grouped split train_final.py graded
the model on), each with the exact probability Python computes.

The JS engine must then reproduce ALL of these — not a 100-URL sample.
This is exhaustive differential testing: the strongest proof available
that two implementations of one model agree.

Input : data/dataset_large.csv + train/model_final.joblib
Output: deploy/full_parity_vectors.json  (one entry per test URL)

Run   : cd linkguard-model && .venv/bin/python train/export_full_parity.py
"""

import csv
import json
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit

DATASET_CSV   = "data/dataset_large.csv"
MODEL_FILE    = "train/model_final.joblib"
OUTPUT_FILE   = "deploy/full_parity_vectors.json"
RANDOM_SEED   = 42          # same seed as train_final.py -> exact same split
TEST_FRACTION = 0.20


def strip_scheme(url):
    return url.split("://", 1)[1] if "://" in url else url


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def main():
    raw_urls, texts, labels, groups = [], [], [], []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            raw_urls.append(row["url"])
            texts.append(strip_scheme(row["url"]))
            labels.append(int(row["label"]))
            groups.append(host_of(row["url"]))

    # rebuild the EXACT same honest split train_final.py was graded on
    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_FRACTION,
                                 random_state=RANDOM_SEED)
    _, test_idx = next(splitter.split(texts, labels, groups))

    pipeline = joblib.load(MODEL_FILE)

    # score the whole test set in ONE batch (fast) with full precision
    test_texts = [texts[i] for i in test_idx]
    probabilities = pipeline.predict_proba(test_texts)[:, 1]

    vectors = []
    for position, i in enumerate(test_idx):
        vectors.append({
            "url":   raw_urls[i],
            "text":  texts[i],
            "label": labels[i],                      # 0 safe / 1 dangerous
            "p":     float(probabilities[position]), # Python's exact answer
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        json.dump(vectors, out, ensure_ascii=False, separators=(",", ":"))

    safe_count = sum(1 for v in vectors if v["label"] == 0)
    print(f"wrote {len(vectors)} test vectors -> {OUTPUT_FILE}")
    print(f"  safe: {safe_count}   dangerous: {len(vectors) - safe_count}")


if __name__ == "__main__":
    main()
