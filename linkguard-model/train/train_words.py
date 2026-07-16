"""
train_words.py
--------------
Upgrade: let the model READ the URL, not just measure its shape.

We turn each URL into thousands of CHUNK columns using TF-IDF over character
n-grams, then train the same Logistic Regression on them.

Why CHARACTER chunks (not whole words):
  malware mutates words ("r0bux", "robuxx"). Whole-word columns miss those.
  Chopping into 3-5 character chunks means a mutated word still shares chunks
  with known-bad ones, so it still lights up danger columns.

Why TF-IDF:
  some chunks ("com", "www") appear in nearly every URL and mean nothing.
  TF-IDF gives rare, telling chunks a big value and boring chunks a tiny one.

We STILL strip the scheme first (http/https is our collection artifact, not
a real danger signal).

Input : data/dataset.csv        (url,label)
Output: train/model_words.joblib   (vectorizer + model saved together)
"""

import csv
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

DATASET_CSV   = "data/dataset.csv"
MODEL_OUT     = "train/model_words.joblib"
RANDOM_SEED   = 42            # same split as before -> fair comparison
TEST_FRACTION = 0.20


def strip_scheme(url):
    """Remove http:// or https:// so the scheme artifact can't leak in."""
    if "://" in url:
        return url.split("://", 1)[1]
    return url


def load_data(path):
    """Read raw URL text and labels (we featurize from the text itself now)."""
    urls, labels = [], []
    with open(path, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            urls.append(strip_scheme(row["url"]))   # keep the TEXT, minus scheme
            labels.append(int(row["label"]))
    return urls, labels


def main():
    urls, labels = load_data(DATASET_CSV)
    urls_train, urls_test, y_train, y_test = train_test_split(
        urls, labels, test_size=TEST_FRACTION, random_state=RANDOM_SEED, stratify=labels,
    )

    # A Pipeline glues the featurizer and the model into ONE object, so at
    # prediction time the exact same chunking is reused. No drift possible.
    pipeline = Pipeline([
        # char_wb = character chunks that respect word edges; 3 to 5 chars long.
        # min_df=5 = ignore chunks seen in fewer than 5 URLs (drop rare noise).
        ("chunks", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5)),
        ("model",  LogisticRegression(max_iter=1000)),
    ])
    pipeline.fit(urls_train, y_train)                 # featurize + train in one call

    predictions = pipeline.predict(urls_test)
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    print("CONFUSION MATRIX (test set) — WORD/CHUNK model")
    print("                     model:SAFE   model:DANGEROUS")
    print(f"  truth SAFE       :   {matrix[0][0]:6d}        {matrix[0][1]:6d}   <- false alarms")
    print(f"  truth DANGEROUS  :   {matrix[1][0]:6d}        {matrix[1][1]:6d}   <- misses")
    print()
    print(classification_report(y_test, predictions,
                                target_names=["safe (0)", "dangerous (1)"], digits=3))

    vocab_size = len(pipeline.named_steps["chunks"].vocabulary_)
    print(f"learned {vocab_size} chunk-columns")

    joblib.dump(pipeline, MODEL_OUT)
    print(f"saved -> {MODEL_OUT}")


if __name__ == "__main__":
    main()
