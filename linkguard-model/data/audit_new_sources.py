"""
audit_new_sources.py
--------------------
Quarantine check for the two candidate phishing sources BEFORE any merge:

  1. PhiUSIIL (UCI 2024)         - data/PhiUSIIL_Phishing_URL_Dataset.csv
  2. Phishing.Database (GitHub)  - data/raw/phishing_db_active.txt

For each source we measure the things that have burned us before:
  - SHAPE: how many URLs have a real path / query / are bare domains?
    (if one class is all bare domains, a model learns shape, not content
     - the shortcut that killed the first SecureBERT model)
  - scheme mix and "www." prefix per class (more shortcut fuel)
  - domain dominance: does one domain own a huge slice?
  - contamination: do these domains overlap our existing training piles?

Run: cd linkguard-model && .venv/bin/python data/audit_new_sources.py
"""

import csv
from collections import Counter
from urllib.parse import urlparse

PHIUSIIL_CSV   = "data/PhiUSIIL_Phishing_URL_Dataset.csv"
PHISHING_DB    = "data/raw/phishing_db_active.txt"
OUR_DATASET    = "data/dataset_large.csv"


def host_of(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def shape_report(name, urls):
    """Print the shape fingerprint of one pile of URLs."""
    total = len(urls)
    if total == 0:
        print(f"\n--- {name}: EMPTY ---")
        return

    has_path = has_query = bare = www = https = 0
    domain_counter = Counter()
    for url in urls:
        parsed = urlparse(url if "://" in url else "http://" + url)
        path_is_real = parsed.path not in ("", "/")
        if path_is_real: has_path += 1
        if parsed.query: has_query += 1
        if not path_is_real and not parsed.query: bare += 1
        host = (parsed.hostname or "").lower()
        if host.startswith("www."): www += 1
        if url.lower().startswith("https"): https += 1
        domain_counter[host] += 1

    def pct(n): return f"{100 * n / total:5.1f}%"
    print(f"\n--- {name}  ({total:,} URLs, {len(domain_counter):,} domains) ---")
    print(f"  has real path : {pct(has_path)}")
    print(f"  has query     : {pct(has_query)}")
    print(f"  bare domain   : {pct(bare)}")
    print(f"  www. prefix   : {pct(www)}")
    print(f"  https scheme  : {pct(https)}")
    top = domain_counter.most_common(5)
    print(f"  top domains   : " +
          ", ".join(f"{d or '(none)'}={c:,}" for d, c in top))


def main():
    # ---- load PhiUSIIL (label 0 = phishing, 1 = legitimate) ----
    phi_phishing, phi_legit = [], []
    with open(PHIUSIIL_CSV, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            (phi_phishing if row["label"] == "0" else phi_legit).append(row["URL"])

    # ---- load Phishing.Database active links ----
    with open(PHISHING_DB, encoding="utf-8", errors="replace") as f:
        pdb_links = [line.strip() for line in f if line.strip()]

    # ---- load our existing training piles (for contamination check) ----
    our_safe_domains, our_danger_domains = set(), set()
    with open(OUR_DATASET, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            target = our_safe_domains if row["label"] == "0" else our_danger_domains
            target.add(host_of(row["url"]))

    shape_report("PhiUSIIL phishing (label=0)", phi_phishing)
    shape_report("PhiUSIIL legitimate (label=1)", phi_legit)
    shape_report("Phishing.Database ACTIVE", pdb_links)
    print("\n(for comparison — our CURRENT training piles:)")
    with open(OUR_DATASET, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    shape_report("ours: safe", [r["url"] for r in rows if r["label"] == "0"])
    shape_report("ours: dangerous", [r["url"] for r in rows if r["label"] == "1"])

    # ---- contamination: new phishing domains already in OUR SAFE pile? ----
    print("\n=== CONTAMINATION CHECK ===")
    for name, urls in [("PhiUSIIL phishing", phi_phishing),
                       ("Phishing.Database", pdb_links)]:
        domains = {host_of(u) for u in urls}
        in_our_safe = domains & our_safe_domains
        in_our_danger = domains & our_danger_domains
        print(f"  {name}: {len(domains):,} domains | "
              f"already in our SAFE pile: {len(in_our_safe)} | "
              f"already in our danger pile: {len(in_our_danger)}")
        if in_our_safe:
            examples = sorted(in_our_safe)[:8]
            print(f"     safe-pile overlaps (danger sign!): {examples}")


if __name__ == "__main__":
    main()
