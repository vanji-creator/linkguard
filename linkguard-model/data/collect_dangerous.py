"""
collect_dangerous.py
--------------------
Build a bigger, more VARIED, de-dominated dangerous pile.

Audit finding this fixes: raw.githubusercontent.com was 23% of the class.
Two moves:
  1. add OpenPhish (phishing) to URLhaus (malware) for real variety,
  2. CAP each domain to at most MAX_PER_DOMAIN URLs, so no single domain
     floods the class (raw.githubusercontent 940 -> 60).

Sources (no API key needed):
  URLhaus recent  data/raw/urlhaus_recent.txt   (already downloaded)
  OpenPhish feed  https://openphish.com/feed.txt (downloaded fresh)

Output: data/dangerous_capped.txt
"""

import requests
from collections import Counter, defaultdict
from urllib.parse import urlparse

URLHAUS_FILE   = "data/raw/urlhaus_recent.txt"
OPENPHISH_URL  = "https://openphish.com/feed.txt"
OUTPUT_FILE    = "data/dangerous_capped.txt"
MAX_PER_DOMAIN = 60


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def load_urlhaus():
    """Read the URLhaus file (one URL per line, '#' lines are comments)."""
    urls = []
    with open(URLHAUS_FILE, "r", encoding="utf-8") as urlhaus_file:
        for line in urlhaus_file:
            url = line.strip()
            if url and not url.startswith("#"):
                urls.append(url)
    return urls


def download_openphish():
    """Fetch the free OpenPhish phishing feed (plain list of URLs)."""
    try:
        response = requests.get(OPENPHISH_URL, timeout=30,
                                headers={"User-Agent": "Mozilla/5.0"})
        lines = [line.strip() for line in response.text.splitlines() if line.strip()]
        print(f"OpenPhish: downloaded {len(lines)} phishing URLs")
        return lines
    except Exception as error:
        print(f"OpenPhish: download failed ({error}) — continuing with URLhaus only")
        return []


def cap_per_domain(urls, max_per_domain):
    """Keep at most `max_per_domain` URLs from any single domain."""
    kept = []
    per_domain_count = defaultdict(int)
    for url in urls:
        domain = host_of(url)
        if per_domain_count[domain] < max_per_domain:
            per_domain_count[domain] += 1
            kept.append(url)
    return kept


def main():
    urlhaus_urls = load_urlhaus()
    openphish_urls = download_openphish()
    print(f"URLhaus: {len(urlhaus_urls)}   OpenPhish: {len(openphish_urls)}")

    # combine + de-duplicate exact URLs (keep order)
    combined = list(dict.fromkeys(urlhaus_urls + openphish_urls))
    print(f"combined + deduped: {len(combined)}")

    # show dominance BEFORE capping
    before = Counter(host_of(u) for u in combined)
    print("\nTOP domains BEFORE cap:")
    for domain, n in before.most_common(5):
        print(f"   {n:5d}  {domain}")

    # apply the per-domain cap
    capped = cap_per_domain(combined, MAX_PER_DOMAIN)
    after = Counter(host_of(u) for u in capped)
    print(f"\nafter cap: {len(capped)} URLs, {len(after)} domains")
    print("TOP domains AFTER cap:")
    for domain, n in after.most_common(5):
        print(f"   {n:5d}  {domain}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        for url in capped:
            output_file.write(url + "\n")
    print(f"\nwrote {len(capped)} dangerous URLs -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
