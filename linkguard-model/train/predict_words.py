"""
predict_words.py
----------------
Run the WORD/CHUNK model on fresh URLs and give the same three-way verdict.
The whole point: check the URLs the SHAPE-only model MISSED
(github .../free-robux/setup.exe and a7.wtf/n2/ppc) — does reading words
finally catch them?

The Pipeline already contains the vectorizer, so we just feed it URL text
(scheme stripped, exactly like training).
"""

import joblib

MODEL_IN = "train/model_words.joblib"
LOW_CUT  = 0.30
HIGH_CUT = 0.70


def strip_scheme(url):
    if "://" in url:
        return url.split("://", 1)[1]
    return url


def verdict_for(danger_probability):
    if danger_probability < LOW_CUT:
        return "safe"
    if danger_probability > HIGH_CUT:
        return "dangerous"
    return "suspicious"


def main():
    pipeline = joblib.load(MODEL_IN)

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
        text = strip_scheme(url)                         # same prep as training
        danger_prob = pipeline.predict_proba([text])[0][1]
        print(f"{verdict_for(danger_prob):>11}  {danger_prob:>9.3f}  {url}")


if __name__ == "__main__":
    main()
