"""
combine_large.py
----------------
Combine the SCALED, engineered piles into one labeled table.

  safe      (label 0) <- data/safe_urls_large.txt      (thousands of domains)
  dangerous (label 1) <- data/dangerous_capped.txt     (capped at 60/domain)

Steps: de-dupe each pile, balance to the smaller size, shuffle, label,
then print a quick audit (counts + unique domains per class) so we can
eyeball the result BEFORE training.

Output: data/dataset_large.csv   (url,label)
"""

import csv
import random
from urllib.parse import urlparse

SAFE_FILE      = "data/safe_urls_large.txt"
DANGEROUS_FILE = "data/dangerous_capped.txt"
OUTPUT_CSV     = "data/dataset_large.csv"
RANDOM_SEED    = 42


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def load_urls(path):
    """Read URLs (one per line), skip blanks/comments, de-dupe keeping order."""
    urls = []
    with open(path, "r", encoding="utf-8") as url_file:
        for line in url_file:
            url = line.strip()
            if url and not url.startswith("#"):
                urls.append(url)
    return list(dict.fromkeys(urls))       # de-dupe


def main():
    random.seed(RANDOM_SEED)

    safe_urls      = load_urls(SAFE_FILE)
    dangerous_urls = load_urls(DANGEROUS_FILE)
    print(f"loaded  safe={len(safe_urls)}  dangerous={len(dangerous_urls)}")

    # balance to the smaller pile (fair random sample of the bigger one)
    pile_size = min(len(safe_urls), len(dangerous_urls))
    random.shuffle(safe_urls)
    random.shuffle(dangerous_urls)
    safe_urls      = safe_urls[:pile_size]
    dangerous_urls = dangerous_urls[:pile_size]
    print(f"balanced both classes to {pile_size} each")

    rows = [(url, 0) for url in safe_urls] + [(url, 1) for url in dangerous_urls]
    random.shuffle(rows)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    # quick audit so we trust it before training
    safe_domains = len(set(host_of(u) for u in safe_urls))
    dangerous_domains = len(set(host_of(u) for u in dangerous_urls))
    print(f"wrote {len(rows)} rows -> {OUTPUT_CSV}")
    print(f"unique domains: safe={safe_domains}  dangerous={dangerous_domains}")


if __name__ == "__main__":
    main()
