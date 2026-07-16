"""
threshold_sweep.py
------------------
The model outputs a PROBABILITY (0..1) that a URL is dangerous, not a plain
yes/no. Calling it "dangerous" only when prob >= 0.50 is a CHOICE, not a law.

This script tries several cut-off values and shows the trade-off on the
unseen test set:

  lower cut  -> flag MORE as dangerous -> fewer MISSES, more FALSE ALARMS
  higher cut -> flag FEWER as dangerous -> more misses, fewer false alarms

You said MISSES are the scary error, so we lean toward a lower cut.
"""

import csv
import joblib
from sklearn.model_selection import train_test_split

FEATURES_CSV  = "data/features.csv"
MODEL_IN      = "train/model.joblib"
RANDOM_SEED   = 42            # MUST match training, to rebuild the same test set
TEST_FRACTION = 0.20


def load_features(path):
    """Read features.csv into X (rows of numbers) and y (labels)."""
    feature_rows, labels, feature_names = [], [], None
    with open(path, "r", encoding="utf-8") as features_file:
        reader = csv.DictReader(features_file)
        feature_names = [name for name in reader.fieldnames if name != "label"]
        for row in reader:
            feature_rows.append([float(row[name]) for name in feature_names])
            labels.append(int(row["label"]))
    return feature_rows, labels


def main():
    X, y = load_features(FEATURES_CSV)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_FRACTION, random_state=RANDOM_SEED, stratify=y,
    )

    model = joblib.load(MODEL_IN)
    # predict_proba gives [prob_safe, prob_dangerous] per URL; we keep the 2nd.
    danger_probs = [pair[1] for pair in model.predict_proba(X_test)]

    print(f"{'cut':>5} {'misses':>7} {'false_alarms':>13} {'recall':>8}")
    for cut in [0.50, 0.40, 0.30, 0.20, 0.10]:
        misses = false_alarms = caught = total_dangerous = 0
        for danger_prob, truth in zip(danger_probs, y_test):
            guess = 1 if danger_prob >= cut else 0     # apply THIS cut
            if truth == 1:                              # a truly dangerous URL
                total_dangerous += 1
                if guess == 0:
                    misses += 1                         # let it through (bad)
                else:
                    caught += 1
            else:                                       # a truly safe URL
                if guess == 1:
                    false_alarms += 1                   # cried wolf
        recall = caught / total_dangerous               # share of dangerous caught
        print(f"{cut:>5.2f} {misses:>7} {false_alarms:>13} {recall:>8.3f}")


if __name__ == "__main__":
    main()
