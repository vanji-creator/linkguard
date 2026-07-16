"""
audit.py
--------
Look HARD at our current dataset before we scale it. We do NOT train here —
we only inspect, so we know what we are feeding the model.

It answers four checklist questions:
  1. INVENTORY     — how many safe vs dangerous?
  2. DUPLICATES    — the same URL appearing more than once?
  3. DOMINANCE     — does one domain flood a class?
  4. CONTAMINATION — do safe and dangerous share any domain?

Input: data/dataset.csv  (url,label)
"""

import csv
from collections import Counter
from urllib.parse import urlparse

DATASET_CSV = "data/dataset.csv"


def host_of(url):
    """Return the domain (host) of a URL, without scheme, lowercased."""
    parsed = urlparse(url if "://" in url else "http://" + url)  # urlparse needs a scheme
    return (parsed.hostname or "").lower()


def main():
    safe_urls, dangerous_urls = [], []
    with open(DATASET_CSV, "r", encoding="utf-8") as dataset_file:
        for row in csv.DictReader(dataset_file):
            if row["label"] == "0":
                safe_urls.append(row["url"])
            else:
                dangerous_urls.append(row["url"])

    # 1. INVENTORY -------------------------------------------------------
    print("1. INVENTORY")
    print(f"   safe     : {len(safe_urls)}")
    print(f"   dangerous: {len(dangerous_urls)}")

    # 2. DUPLICATES ------------------------------------------------------
    print("\n2. DUPLICATES (same exact URL more than once)")
    for name, urls in [("safe", safe_urls), ("dangerous", dangerous_urls)]:
        counts = Counter(urls)
        dupes = {url: n for url, n in counts.items() if n > 1}
        print(f"   {name}: {len(urls) - len(counts)} duplicate rows "
              f"({len(dupes)} URLs repeated)")

    # 3. DOMINANCE -------------------------------------------------------
    print("\n3. DOMINANCE (top domains per class)")
    for name, urls in [("safe", safe_urls), ("dangerous", dangerous_urls)]:
        domain_counts = Counter(host_of(u) for u in urls)
        total = len(urls)
        top = domain_counts.most_common(5)
        unique_domains = len(domain_counts)
        top5_share = 100 * sum(n for _, n in top) / total
        print(f"   {name}: {unique_domains} unique domains, "
              f"top-5 = {top5_share:.1f}% of the class")
        for domain, n in top:
            print(f"       {n:5d}  {domain}")

    # 4. CONTAMINATION ---------------------------------------------------
    print("\n4. CONTAMINATION (domains in BOTH safe and dangerous)")
    safe_domains = set(host_of(u) for u in safe_urls)
    dangerous_domains = set(host_of(u) for u in dangerous_urls)
    shared = safe_domains & dangerous_domains
    print(f"   shared domains: {len(shared)}")
    for domain in sorted(shared)[:20]:
        print(f"       {domain}")


if __name__ == "__main__":
    main()
