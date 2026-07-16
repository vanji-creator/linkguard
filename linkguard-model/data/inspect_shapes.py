"""
inspect_shapes.py
-----------------
Look at the dataset BEFORE training and check the "shape" of each class.

Goal: did we kill the shortcut? A shortcut exists when some accidental feature
(like "has a path") is very different between safe and dangerous. We want the
accidental ones to look ALIKE in both classes, and only the REAL danger signals
to differ.

For each URL we measure 4 simple shape features, then compare the average of
each feature for safe (label 0) vs dangerous (label 1).
"""

import re
import pandas as pd

DATASET = "data/dataset.csv"

# Matches a URL whose host is a raw IP address, e.g. http://91.92.40.118/...
IP_HOST_PATTERN = re.compile(r'^https?://\d{1,3}(\.\d{1,3}){3}')


def url_length(url):
    """How many characters long is the URL."""
    return len(url)


def is_http(url):
    """True if it uses plain http:// (not the secure https://)."""
    return url.startswith("http://")


def is_ip_host(url):
    """True if the host is a raw IP address instead of a domain name."""
    return bool(IP_HOST_PATTERN.match(url))


def has_path(url):
    """True if there is anything after the host (a /path, not a bare domain)."""
    after_scheme = re.sub(r'^https?://', '', url)  # drop "https://"
    return '/' in after_scheme                     # a '/' left means there is a path


def main():
    data = pd.read_csv(DATASET)                    # load the labeled table

    # measure each shape feature for every URL (adds 4 new columns)
    data["length"]     = data["url"].apply(url_length)
    data["is_http"]    = data["url"].apply(is_http)
    data["is_ip_host"] = data["url"].apply(is_ip_host)
    data["has_path"]   = data["url"].apply(has_path)

    # group by label and average each feature.
    # (the average of a True/False column = the FRACTION that are True)
    summary = data.groupby("label")[["length", "is_http", "is_ip_host", "has_path"]].mean()
    summary.index = ["SAFE (0)", "DANGEROUS (1)"]  # friendlier row names

    pd.set_option("display.float_format", lambda value: f"{value:.2f}")
    print(summary)


if __name__ == "__main__":
    main()
