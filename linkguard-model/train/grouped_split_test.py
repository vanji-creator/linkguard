"""
grouped_split_test.py
---------------------
Measure the HONEST accuracy of the word/chunk model.

Our normal split cuts by URL, so a domain like raw.githubusercontent.com
(23% of the dangerous class) lands in BOTH train and test — the model
memorises the domain and gets free correct answers on the test. That puffs
up the score.

Here we split by DOMAIN instead (GroupShuffleSplit): every domain goes
entirely into train OR test, never both. Now the test set is made of
domains the model has NEVER seen. The accuracy this reports is the real one.

Input: data/dataset.csv
"""

import csv
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix, classification_report

DATASET_CSV   = "data/dataset.csv"
RANDOM_SEED   = 42
TEST_FRACTION = 0.20


def strip_scheme(url):
    return url.split("://", 1)[1] if "://" in url else url


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def main():
    urls, labels, groups = [], [], []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            urls.append(strip_scheme(row["url"]))
            labels.append(int(row["label"]))
            groups.append(host_of(row["url"]))     # the DOMAIN is the group

    # Split so no group (domain) is shared between train and test.
    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_FRACTION,
                                 random_state=RANDOM_SEED)
    train_idx, test_idx = next(splitter.split(urls, labels, groups))

    urls_train = [urls[i] for i in train_idx]
    urls_test  = [urls[i] for i in test_idx]
    y_train    = [labels[i] for i in train_idx]
    y_test     = [labels[i] for i in test_idx]

    # PROVE the split is clean: zero domains shared between train and test.
    train_domains = {groups[i] for i in train_idx}
    test_domains  = {groups[i] for i in test_idx}
    print(f"train rows: {len(urls_train)}   test rows: {len(urls_test)}")
    print(f"shared domains between train & test: {len(train_domains & test_domains)}")
    print(f"test class balance: safe={y_test.count(0)}  dangerous={y_test.count(1)}")

    pipeline = Pipeline([
        ("chunks", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5)),
        ("model",  LogisticRegression(max_iter=1000)),
    ])
    pipeline.fit(urls_train, y_train)
    predictions = pipeline.predict(urls_test)

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    print("\nCONFUSION MATRIX — DOMAIN-grouped split (honest)")
    print("                     model:SAFE   model:DANGEROUS")
    print(f"  truth SAFE       :   {matrix[0][0]:6d}        {matrix[0][1]:6d}   <- false alarms")
    print(f"  truth DANGEROUS  :   {matrix[1][0]:6d}        {matrix[1][1]:6d}   <- misses")
    print()
    print(classification_report(y_test, predictions,
                                target_names=["safe (0)", "dangerous (1)"], digits=3))


if __name__ == "__main__":
    main()
