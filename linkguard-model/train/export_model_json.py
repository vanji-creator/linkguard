"""
export_model_json.py
--------------------
Turn the trained sklearn model into a plain JSON file that JavaScript can read.

A trained model is just numbers:
  - a list of chunks (character n-grams) the vectorizer knows,
  - one idf value per chunk  (how rare the chunk is -> how much it counts),
  - one weight per chunk     (how dangerous the chunk is, + or -),
  - one intercept            (the model's starting bias before any evidence).

We write those numbers into model/linkguard_model_v1.json (extension root).
We ALSO write golden_vectors.json: ~100 URLs with the exact probability the
Python model gives them. The JavaScript engine must reproduce these to within
0.000001 — that's how we PROVE the two implementations agree.

Run from linkguard-model/:  .venv/bin/python train/export_model_json.py
"""

import csv
import hashlib
import json
import random
import joblib
from urllib.parse import urlparse

MODEL_FILE       = "train/model_final.joblib"
DATASET_CSV      = "data/dataset_large.csv"
MODEL_JSON_OUT   = "../model/linkguard_model_v1.json"     # extension root
GOLDEN_OUT       = "../model/golden_vectors.json"
RANDOM_SEED      = 42
DECIMALS         = 7        # 7 decimal places keeps probability error < 0.000001


def strip_scheme(url):
    return url.split("://", 1)[1] if "://" in url else url


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def assert_expected_params(vectorizer, classifier):
    """Fail LOUDLY if a future retrain changed any setting the JS engine
    hard-codes. Silent divergence is the enemy — a crash here is a feature."""
    assert vectorizer.analyzer == "char_wb",           "analyzer changed!"
    assert vectorizer.ngram_range == (3, 5),           "ngram_range changed!"
    assert vectorizer.lowercase is True,               "lowercase changed!"
    assert vectorizer.strip_accents is None,           "strip_accents changed!"
    assert vectorizer.binary is False,                 "binary changed!"
    assert vectorizer.sublinear_tf is False,           "sublinear_tf changed!"
    assert vectorizer.norm == "l2",                    "norm changed!"
    assert vectorizer.use_idf is True,                 "use_idf changed!"
    assert vectorizer.smooth_idf is True,              "smooth_idf changed!"
    assert list(classifier.classes_) == [0, 1],        "class order changed!"
    print("all fitted-parameter asserts passed")


def build_ngram_table(vectorizer, classifier):
    """One JSON entry per chunk:  chunk -> [idf, weight]  (rounded to 7dp)."""
    idf_values   = vectorizer.idf_
    coef_values  = classifier.coef_[0]
    table = {}
    for gram, column_index in vectorizer.vocabulary_.items():
        table[gram] = [round(float(idf_values[column_index]),  DECIMALS),
                       round(float(coef_values[column_index]), DECIMALS)]
    return table


def make_golden_urls():
    """80 real dataset URLs (40 safe / 40 dangerous, one per domain)
    + ~20 handcrafted edge cases that poke every parity trap."""
    random.seed(RANDOM_SEED)

    safe_pool, dangerous_pool = [], []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            (safe_pool if row["label"] == "0" else dangerous_pool).append(row["url"])
    random.shuffle(safe_pool)
    random.shuffle(dangerous_pool)

    def take_one_per_domain(pool, how_many):
        chosen, seen_domains = [], set()
        for url in pool:
            domain = host_of(url)
            if domain not in seen_domains:
                seen_domains.add(domain)
                chosen.append(url)
            if len(chosen) == how_many:
                break
        return chosen

    sampled = take_one_per_domain(safe_pool, 40) + take_one_per_domain(dangerous_pool, 40)

    handcrafted = [
        "google.com",                                        # bare domain, no scheme
        "https://google.com",                                # scheme must be stripped
        "HTTPS://GOOGLE.COM/SEARCH?Q=TEST",                  # uppercase -> lowercase
        "https://example.com/file%20name%20here.pdf",        # percent-encoded spaces
        "https://example.com/a b/c",                         # literal single space
        "https://example.com/a  b/c",                        # double space (collapses)
        "https://example.com/كرة/القدم",                     # Arabic (real vocab grams)
        "https://gооgle.com/login",                          # Cyrillic homoglyph 'о'
        "https://example.com/İstanbul/ŞEHİR",                # Turkish İ special lowercase
        "https://example.com/ΟΔΟΣ/ΝΙΚΟΣ",                    # Greek final-sigma lowercase
        "https://example.com/straße/gross",                  # German sharp s
        "https://example.com/💰/free-money",                 # emoji: code-point slicing test
        "https://example.com/" + "a" * 1200,                 # very long URL
        "https://" + "xq" * 3 + ".zzqxj/" + "qxzjv" * 3,     # gibberish -> mostly OOV
        "☃☄★",                                # pure OOV -> sigmoid(intercept)
        "https://",                                          # empty after strip
        "http://192.168.1.1/admin",                          # raw IP
        "https://github.com/user/repo/releases/download/free-robux/setup.exe",
        "https://sbi-verify-kyc.xyz/update-account",
        "https://www.dropbox.com/scl/fi/abc/invoice.vbs?rlkey=x",
    ]
    return sampled + handcrafted


def main():
    pipeline   = joblib.load(MODEL_FILE)
    vectorizer = pipeline.named_steps["chunks"]
    classifier = pipeline.named_steps["model"]

    assert_expected_params(vectorizer, classifier)

    ngram_table = build_ngram_table(vectorizer, classifier)

    # sha256 of the table (sorted, compact) — a fingerprint of the weights,
    # so any two copies of the file can be checked for byte-identical numbers
    canonical = json.dumps(ngram_table, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    fingerprint = hashlib.sha256(canonical).hexdigest()

    model_artifact = {
        "meta": {
            "format":     "linkguard-tfidf-logreg-v1",
            "version":    "1.0.0",
            "created":    "2026-07-15",
            "sklearn":    "1.9.0",
            "source":     "train/model_final.joblib",
            "vocab_size": len(ngram_table),
            "metrics":    {"grouped_split_accuracy": 0.986,
                           "false_alarm_rate": 0.003,
                           "miss_rate": 0.025},
            "sha256":     fingerprint,
        },
        "config": {
            "analyzer":     "char_wb",
            "ngram_min":    3,
            "ngram_max":    5,
            "lowercase":    True,
            "strip_scheme": True,
            "thresholds":   {"safe_below": 0.30, "dangerous_above": 0.70},
            "confidence_threshold": 0.90,
        },
        "intercept": float(classifier.intercept_[0]),   # full precision
        "ngrams":    ngram_table,
    }

    with open(MODEL_JSON_OUT, "w", encoding="utf-8") as model_file:
        json.dump(model_artifact, model_file, ensure_ascii=False,
                  separators=(",", ":"))
    print(f"wrote model -> {MODEL_JSON_OUT}  ({len(ngram_table)} chunks)")

    # golden vectors: URL + stripped text + EXACT Python probability
    golden = []
    for url in make_golden_urls():
        text = strip_scheme(url)
        probability = float(pipeline.predict_proba([text])[0][1])
        golden.append({"url": url, "text": text, "p": probability})

    with open(GOLDEN_OUT, "w", encoding="utf-8") as golden_file:
        json.dump(golden, golden_file, ensure_ascii=False, indent=1)
    print(f"wrote {len(golden)} golden vectors -> {GOLDEN_OUT}")


if __name__ == "__main__":
    main()
