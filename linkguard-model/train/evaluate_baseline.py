"""
evaluate_baseline.py
--------------------
Grade the trained model HONESTLY on the unseen test set, and look at the
mistakes by hand.

Accuracy is one number and it hides which class we fail on. So instead we
print the CONFUSION MATRIX (all four outcomes) plus recall/precision, and
we print the actual URLs the model got wrong so we can eyeball them.

  recall (on dangerous) = caught dangerous / all dangerous   <- our priority
  precision (dangerous) = truly dangerous / everything flagged dangerous

We rebuild the SAME train/test split (same seed) as training, so the test
rows here are exactly the ones the model never learned from.

Input: data/features.csv, data/dataset.csv, train/model.joblib
"""

import csv
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

FEATURES_CSV  = "data/features.csv"
DATASET_CSV   = "data/dataset.csv"     # to recover the URL text of each row
MODEL_IN      = "train/model.joblib"
RANDOM_SEED   = 42                     # MUST match train_baseline.py
TEST_FRACTION = 0.20                   # MUST match train_baseline.py


def load_everything():
    """Load feature rows, labels, AND the original URL text, all row-aligned."""
    feature_rows, labels, feature_names = [], [], None
    with open(FEATURES_CSV, "r", encoding="utf-8") as features_file:
        reader = csv.DictReader(features_file)
        feature_names = [name for name in reader.fieldnames if name != "label"]
        for row in reader:
            feature_rows.append([float(row[name]) for name in feature_names])
            labels.append(int(row["label"]))

    urls = []                                          # the URL for each row
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            urls.append(row["url"])
    return feature_rows, labels, urls


def main():
    X, y, urls = load_everything()
    model = joblib.load(MODEL_IN)                      # the model we trained

    # Rebuild the identical split. We pass urls alongside so they stay aligned
    # with the test rows (train_test_split splits every array the same way).
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls,
        test_size=TEST_FRACTION,
        random_state=RANDOM_SEED,
        stratify=y,
    )

    predictions = model.predict(X_test)               # what the model guesses

    # Confusion matrix. labels=[0,1] fixes the order: row/col 0=safe, 1=dangerous.
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    true_safe_safe, safe_flagged   = matrix[0][0], matrix[0][1]
    missed_dangerous, caught_dang  = matrix[1][0], matrix[1][1]

    print("CONFUSION MATRIX (test set)")
    print("                     model:SAFE   model:DANGEROUS")
    print(f"  truth SAFE       :   {true_safe_safe:6d}        {safe_flagged:6d}   <- false alarms")
    print(f"  truth DANGEROUS  :   {missed_dangerous:6d}        {caught_dang:6d}   <- misses on the left")
    print()
    print(classification_report(y_test, predictions,
                                target_names=["safe (0)", "dangerous (1)"],
                                digits=3))

    # Eyeball the MISSES: dangerous URLs the model wrongly called safe.
    print("\n--- MISSES (truth dangerous, model said safe) ---")
    shown = 0
    for url, truth, guess in zip(urls_test, y_test, predictions):
        if truth == 1 and guess == 0:                 # a miss
            print("  ", url[:90])
            shown += 1
            if shown >= 8:
                break

    # Eyeball the FALSE ALARMS: safe URLs the model wrongly called dangerous.
    print("\n--- FALSE ALARMS (truth safe, model said dangerous) ---")
    shown = 0
    for url, truth, guess in zip(urls_test, y_test, predictions):
        if truth == 0 and guess == 1:                 # a false alarm
            print("  ", url[:90])
            shown += 1
            if shown >= 8:
                break


if __name__ == "__main__":
    main()
