"""
inspect_misses.py
-----------------
Look at every dangerous URL the final model MISSED on the honest
(domain-grouped) test split — the same split train_final.py used.

For each miss we print the model's danger probability, sorted from
"almost caught" (near 0.50) down to "totally fooled" (near 0.00).
Then we group the misses by domain and by ending (.exe, .zip, ...)
to spot patterns — patterns tell us WHAT DATA TO ADD next.

Input : data/dataset_large.csv + train/model_final.joblib
Output: printed report only (no files written)
"""

import csv
import joblib
from collections import Counter
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit

DATASET_CSV   = "data/dataset_large.csv"
MODEL_FILE    = "train/model_final.joblib"
RANDOM_SEED   = 42          # same seed as train_final.py -> exact same split
TEST_FRACTION = 0.20


def strip_scheme(url):
    return url.split("://", 1)[1] if "://" in url else url


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def ending_of(url):
    """Last piece after the final '/' and '.', e.g. 'exe' — or '(no file)'."""
    path = urlparse(url if "://" in url else "http://" + url).path
    last_part = path.rsplit("/", 1)[-1]
    if "." in last_part:
        return "." + last_part.rsplit(".", 1)[-1].lower()
    return "(no file ending)"


def main():
    raw_urls, urls, labels, groups = [], [], [], []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            raw_urls.append(row["url"])
            urls.append(strip_scheme(row["url"]))
            labels.append(int(row["label"]))
            groups.append(host_of(row["url"]))

    # rebuild the EXACT same honest split as train_final.py
    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_FRACTION,
                                 random_state=RANDOM_SEED)
    train_idx, test_idx = next(splitter.split(urls, labels, groups))

    pipeline = joblib.load(MODEL_FILE)

    # score every dangerous test URL, collect the ones predicted SAFE
    misses = []                             # (probability, raw_url)
    for i in test_idx:
        if labels[i] != 1:
            continue                        # only look at truly-dangerous rows
        danger_probability = pipeline.predict_proba([urls[i]])[0][1]
        if danger_probability < 0.50:       # model said "safe" -> a MISS
            misses.append((danger_probability, raw_urls[i]))

    misses.sort(reverse=True)               # near-catches first
    print(f"{len(misses)} misses out of "
          f"{sum(1 for i in test_idx if labels[i] == 1)} dangerous test URLs\n")

    print("=== EVERY MISS, sorted: almost-caught -> totally-fooled ===")
    for danger_probability, url in misses:
        display_url = url if len(url) <= 100 else url[:97] + "..."
        print(f"  p={danger_probability:.3f}  {display_url}")

    # pattern hunt 1: which band did misses fall in?
    band_counter = Counter()
    for danger_probability, _ in misses:
        if danger_probability >= 0.30:
            band_counter["0.30-0.50 (suspicious band — near catch)"] += 1
        elif danger_probability >= 0.10:
            band_counter["0.10-0.30 (weak smell)"] += 1
        else:
            band_counter["0.00-0.10 (totally fooled)"] += 1
    print("\n=== HOW WRONG WERE WE? ===")
    for band, count in band_counter.most_common():
        print(f"  {count:3d}  {band}")

    # pattern hunt 2: repeated domains among misses
    domain_counter = Counter(host_of(url) for _, url in misses)
    print("\n=== DOMAINS APPEARING MORE THAN ONCE IN MISSES ===")
    for domain, count in domain_counter.most_common():
        if count > 1:
            print(f"  {count:3d}  {domain}")

    # pattern hunt 3: file endings among misses
    ending_counter = Counter(ending_of(url) for _, url in misses)
    print("\n=== FILE ENDINGS AMONG MISSES ===")
    for ending, count in ending_counter.most_common(10):
        print(f"  {count:3d}  {ending}")


if __name__ == "__main__":
    main()
