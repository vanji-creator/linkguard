"""
train_baseline.py
-----------------
Teach a simple model to tell safe (0) from dangerous (1) using the number
rows we built in build_features.py.

THE GOLDEN RULE we follow here: split the data first.
  - TRAIN set: the model learns ONLY from these rows.
  - TEST  set: the model never sees these while learning. We grade on them.
This is the only honest way to know it LEARNED danger instead of MEMORISING.

Model: Logistic Regression. It learns one weight per feature (how strongly
that feature pushes toward "dangerous"), and outputs a probability 0..1.

Input : data/features.csv           (feature columns + label)
Output: train/model.joblib          (the trained model, saved to disk)
        train/feature_order.txt     (the exact column order it expects)
"""

import csv
import joblib                                   # saves/loads the trained model
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

FEATURES_CSV      = "data/features.csv"
MODEL_OUT         = "train/model.joblib"
FEATURE_ORDER_OUT = "train/feature_order.txt"
RANDOM_SEED       = 42                           # same split every run = reproducible
TEST_FRACTION     = 0.20                         # hold back 20% for the honest test


def load_features(path):
    """Read features.csv into X (rows of numbers) and y (the labels)."""
    feature_rows = []          # X: each item is one URL's list of numbers
    labels       = []          # y: 0 (safe) or 1 (dangerous), aligned with X
    feature_names = None       # the column order, minus the label

    with open(path, "r", encoding="utf-8") as features_file:
        reader = csv.DictReader(features_file)
        feature_names = [name for name in reader.fieldnames if name != "label"]
        for row in reader:
            # pull the numbers out IN THE FIXED column order
            one_row = [float(row[name]) for name in feature_names]
            feature_rows.append(one_row)
            labels.append(int(row["label"]))
    return feature_rows, labels, feature_names


def main():
    X, y, feature_names = load_features(FEATURES_CSV)
    print(f"loaded {len(X)} rows, {len(feature_names)} features")

    # SPLIT: hide 20% of the data from the model as an honest exam.
    # stratify=y keeps the same safe/dangerous balance in both halves.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_FRACTION,
        random_state=RANDOM_SEED,
        stratify=y,
    )
    print(f"train rows: {len(X_train)}   test rows: {len(X_test)}")

    # LEARN: fit the model on the TRAIN half only.
    model = LogisticRegression(max_iter=1000)   # max_iter: give it enough steps to settle
    model.fit(X_train, y_train)                 # this is "training"

    # GRADE twice, so we can compare:
    train_accuracy = accuracy_score(y_train, model.predict(X_train))  # on data it saw
    test_accuracy  = accuracy_score(y_test,  model.predict(X_test))   # on data it did NOT
    print(f"accuracy on TRAIN (seen)   : {train_accuracy:.3f}")
    print(f"accuracy on TEST  (unseen) : {test_accuracy:.3f}")

    # SAVE the model and the exact feature order it expects.
    joblib.dump(model, MODEL_OUT)
    with open(FEATURE_ORDER_OUT, "w", encoding="utf-8") as order_file:
        order_file.write("\n".join(feature_names) + "\n")
    print(f"saved model -> {MODEL_OUT}")


if __name__ == "__main__":
    main()
