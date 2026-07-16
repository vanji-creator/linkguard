"""
predict_baseline.py
-------------------
Use the trained model on ANY url string, and turn its probability into a
THREE-way verdict using two cuts:

  probability < LOW_CUT           -> "safe"
  probability > HIGH_CUT          -> "dangerous"
  in between  (the grey zone)     -> "suspicious"

"suspicious" is NOT something the model learned. It is a BAND we draw on the
model's probability AFTER the model runs — exactly as we planned.

IMPORTANT: prediction must use the SAME feature code as training, or the
numbers won't line up with what the model learned. So we IMPORT
extract_features from build_features instead of copying it (no drift).
"""

import sys
import joblib

sys.path.insert(0, "data")                 # let us import the feature builder
from build_features import extract_features  # the exact same feature function

MODEL_IN         = "train/model.joblib"
FEATURE_ORDER_IN = "train/feature_order.txt"
LOW_CUT  = 0.30      # below this -> safe
HIGH_CUT = 0.70      # above this -> dangerous ; between the two -> suspicious


def load_feature_order():
    """Read the exact column order the model was trained on."""
    with open(FEATURE_ORDER_IN, "r", encoding="utf-8") as order_file:
        return [line.strip() for line in order_file if line.strip()]


def url_to_row(url, feature_order):
    """Turn one URL into a row of numbers IN THE ORDER the model expects."""
    features = extract_features(url)                       # same code as training
    return [features[name] for name in feature_order]      # keep the fixed order


def verdict_for(danger_probability):
    """Map a probability to our three-way verdict using the two cuts."""
    if danger_probability < LOW_CUT:
        return "safe"
    if danger_probability > HIGH_CUT:
        return "dangerous"
    return "suspicious"


def main():
    model = joblib.load(MODEL_IN)
    feature_order = load_feature_order()

    # Fresh URLs the model never trained on — including google.com/search,
    # the URL that broke the LAST model.
    test_urls = [
        "https://www.google.com/search?q=how+to+train+a+model",
        "https://github.com/features/actions",
        "https://en.wikipedia.org/wiki/Malware",
        "https://github.com/hax0r99/free-robux/releases/download/v1/setup.exe",
        "http://185.220.101.5/gate.php",
        "https://sbi-verify-kyc-update.xyz/login.php",
        "http://a7.wtf/n2/ppc",
        "https://fastly.net/styles.2c2823cd013b82c0e74b.css",
    ]

    print(f"{'verdict':>11}  {'p(danger)':>9}  url")
    print("-" * 70)
    for url in test_urls:
        row = url_to_row(url, feature_order)
        danger_prob = model.predict_proba([row])[0][1]     # prob of class 1
        print(f"{verdict_for(danger_prob):>11}  {danger_prob:>9.3f}  {url}")


if __name__ == "__main__":
    main()
