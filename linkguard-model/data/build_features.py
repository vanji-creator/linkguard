"""
build_features.py
-----------------
Turn each URL into a ROW OF NUMBERS the model can learn from.

A "feature" is just one measurement (one question we ask about the URL).
Example question: "how many dots are in this URL?" -> a number.
Ask the SAME list of questions of every URL, and each URL becomes a row
of numbers. The same URL always gives the same row (it is a fixed formula,
not a random hash).

IMPORTANT design choice — we STRIP the scheme (http:// or https://) first.
  Reason: our safe pile is 100% https ONLY because our collector always
  used https. That "0% http" is a fake signal from our METHOD, not a truth
  about safe sites. So we hide the scheme from the model on purpose.
  (We KEEP raw-IP detection, because THAT class difference is real.)

Input : data/dataset.csv    (columns: url,label)
Output: data/features.csv   (one column per feature, plus the label)
"""

import csv
import re

DATASET_CSV  = "data/dataset.csv"     # the labeled URLs we built earlier
FEATURES_CSV = "data/features.csv"    # the rows of numbers we will write

# A host that is a bare IP address, e.g. 91.92.40.118
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def strip_scheme(url):
    """Remove a leading http:// or https:// so the model never sees the scheme."""
    if "://" in url:                       # e.g. "https://a.com/x"
        return url.split("://", 1)[1]      # -> "a.com/x"  (keep the part after ://)
    return url                             # already had no scheme, leave as-is


def split_host_and_path(url_without_scheme):
    """Split "a.com/x/y" into host "a.com" and path "/x/y"."""
    if "/" in url_without_scheme:                       # there is a path
        first_slash = url_without_scheme.index("/")     # position of the first "/"
        host = url_without_scheme[:first_slash]         # everything before it
        path = url_without_scheme[first_slash:]         # the "/" and everything after
    else:                                               # no path at all
        host = url_without_scheme
        path = ""
    return host, path


def count_digits(text):
    """Count how many characters in text are digits 0-9."""
    total = 0                              # running count
    for single_character in text:          # look at each character
        if single_character.isdigit():     # is it 0-9 ?
            total += 1                      # yes -> add one
    return total


def extract_features(raw_url):
    """Ask a fixed list of questions about one URL -> return a dict of numbers."""
    url = strip_scheme(raw_url)                   # hide the scheme (see file header)
    host, path = split_host_and_path(url)         # break into host and path
    num_digits = count_digits(url)                # reused twice below

    features = {}
    features["url_length"]    = len(url)                      # total characters
    features["host_length"]   = len(host)                     # length of the host part
    features["path_length"]   = len(path)                     # length of the path part
    features["num_dots"]      = url.count(".")                # dots (subdomain depth etc.)
    features["num_hyphens"]   = url.count("-")                # hyphens (phishing uses many)
    features["num_digits"]    = num_digits                    # how many digit characters
    features["num_slashes"]   = url.count("/")                # path depth
    features["has_at_symbol"] = 1 if "@" in url else 0        # "@" is a known phishing trick
    features["has_raw_ip"]    = 1 if IP_PATTERN.match(host) else 0   # REAL danger signal (kept)
    # ratio: how "numeric" the URL looks, independent of its length
    features["digit_ratio"]   = round(num_digits / len(url), 3) if len(url) else 0.0
    return features


def main():
    rows_out = []            # each item: one dict of features + its label
    feature_names = None     # the column order, locked from the first URL

    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        reader = csv.DictReader(dataset_file)          # reads rows as {url, label}
        for row in reader:
            features = extract_features(row["url"])    # URL -> numbers
            features["label"] = int(row["label"])      # keep the answer alongside
            if feature_names is None:                  # first row only:
                feature_names = list(features.keys())  # remember the column order
            rows_out.append(features)

    with open(FEATURES_CSV, "w", newline="", encoding="utf-8") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=feature_names)
        writer.writeheader()                           # the column names row
        writer.writerows(rows_out)                     # all the number rows

    print(f"wrote {len(rows_out)} rows, {len(feature_names) - 1} features -> {FEATURES_CSV}")
    print("example row:", rows_out[0])                 # SEE one URL turned into numbers


if __name__ == "__main__":
    main()
