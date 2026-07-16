"""
check_shape.py
--------------
Before training, check whether any CHEAP shape feature accidentally separates
safe from dangerous. If it does, the model could grab that shortcut instead of
learning real danger. This is called checking for "leakage".

We compare, for each class (0 = safe, 1 = dangerous):
  - how often the URL has a path
  - average URL length
  - how often it uses http (not https)
  - how often the host is a raw IP address

We WANT the "accidental" ones (has-path, length) to look SIMILAR across
classes, and we EXPECT the "real signal" ones (raw IP) to still differ.
"""

import csv
import re
from urllib.parse import urlparse   # splits a URL into host, path, etc.

DATASET_CSV = "data/dataset.csv"
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")   # matches e.g. 91.92.40.118


def describe(urls):
    """Return simple shape stats for a list of URLs."""
    total = len(urls)
    has_path = 0        # URLs that have something after the host
    http_only = 0       # URLs using plain http
    raw_ip = 0          # URLs whose host is a bare IP address
    length_sum = 0      # to compute average length

    for url in urls:
        parsed = urlparse(url)                 # break the URL into parts
        length_sum += len(url)                 # add up lengths
        if parsed.path and parsed.path != "/": # path beyond just "/"
            has_path += 1
        if parsed.scheme == "http":            # not https
            http_only += 1
        host = parsed.hostname or ""           # the domain or IP
        if IP_PATTERN.match(host):             # host is a raw IP
            raw_ip += 1

    # turn counts into easy-to-read percentages
    return {
        "count":        total,
        "has_path_%":   round(100 * has_path / total, 1),
        "avg_length":   round(length_sum / total, 1),
        "http_only_%":  round(100 * http_only / total, 1),
        "raw_ip_%":     round(100 * raw_ip / total, 1),
    }


def main():
    safe_urls = []
    dangerous_urls = []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        reader = csv.DictReader(dataset_file)      # reads rows as {url, label}
        for row in reader:
            if row["label"] == "0":
                safe_urls.append(row["url"])
            else:
                dangerous_urls.append(row["url"])

    print("SAFE     :", describe(safe_urls))
    print("DANGEROUS:", describe(dangerous_urls))


if __name__ == "__main__":
    main()
