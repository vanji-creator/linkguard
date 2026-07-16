"""
collect_safe_large.py
---------------------
Scaled-up SAFE collection for the bigger dataset.

Same idea as collect_safe.py (harvest real internal links from trusted Tranco
homepages), but:
  - visit MANY more domains (top ~2000 instead of 400) for domain variety,
  - take fewer links per domain (cap 20) so no single site dominates,
  - write to disk as we go, so an interruption never loses progress.

Output: data/safe_urls_large.txt
"""

import sys
import time

sys.path.insert(0, "data")
import collect_safe                       # reuse the crawler + harvest logic

HOW_MANY_DOMAINS = 2000                    # far more domains than before
OUTPUT_FILE      = "data/safe_urls_large.txt"

collect_safe.MAX_LINKS_PER_DOMAIN = 20     # smaller per-domain cap = more spread


def main():
    top_domains = collect_safe.read_top_domains(HOW_MANY_DOMAINS)
    seen = set()                           # de-dupe across all domains as we go
    collected = 0

    # open once and flush after each domain, so progress survives interruption
    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        for position, domain in enumerate(top_domains, start=1):
            urls = collect_safe.harvest_links_from_domain(domain)
            for url in urls:
                if url in seen:
                    continue
                seen.add(url)
                output_file.write(url + "\n")
                collected += 1
            output_file.flush()            # persist after every domain
            if position % 25 == 0:
                print(f"[{position}/{len(top_domains)}] {collected} urls so far",
                      flush=True)
            time.sleep(0.15)               # be polite

    print(f"\nDONE. {collected} safe URLs -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
