"""
combine_and_label.py
--------------------
Turn our two separate piles into ONE labeled table to train on.

  label 0 = safe        (from safe_urls.txt)
  label 1 = dangerous   (from URLhaus)

We also BALANCE the classes: make both piles the same size. This is the
"equal amount" rule we designed — it stops the model from cheating by just
always guessing whichever class is bigger.

Output: data/dataset.csv   with columns:  url,label
"""

import csv        # to write a clean comma-separated table
import random     # to shuffle and to downsample the bigger pile

# ---- settings ----
SAFE_FILE      = "data/safe_urls.txt"          # our collected safe URLs
DANGEROUS_FILE = "data/raw/urlhaus_recent.txt" # URLhaus malware URLs
OUTPUT_CSV     = "data/dataset.csv"            # the labeled table we build
RANDOM_SEED    = 42   # fixing the seed = same shuffle every run = reproducible


def load_urls(path):
    """Read a file of URLs (one per line), skipping blanks and '#' comment lines."""
    urls = []                                       # collected URLs go here
    with open(path, "r", encoding="utf-8") as url_file:
        for line in url_file:
            url = line.strip()                      # remove trailing newline/spaces
            if not url or url.startswith("#"):      # skip blank lines and comments
                continue
            urls.append(url)
    return urls


def main():
    random.seed(RANDOM_SEED)                        # make every run identical

    safe_urls      = load_urls(SAFE_FILE)           # label 0
    dangerous_urls = load_urls(DANGEROUS_FILE)      # label 1
    print(f"loaded {len(safe_urls)} safe, {len(dangerous_urls)} dangerous")

    # BALANCE: shrink both piles to the size of the SMALLER one.
    pile_size = min(len(safe_urls), len(dangerous_urls))
    random.shuffle(safe_urls)                       # shuffle before cutting, so the
    random.shuffle(dangerous_urls)                  # kept URLs are a fair random sample
    safe_urls      = safe_urls[:pile_size]          # keep first `pile_size`
    dangerous_urls = dangerous_urls[:pile_size]
    print(f"balanced both classes to {pile_size} each")

    # Build (url, label) rows for each pile, then mix them together.
    labeled_rows  = [(url, 0) for url in safe_urls]         # safe  -> 0
    labeled_rows += [(url, 1) for url in dangerous_urls]    # danger -> 1
    random.shuffle(labeled_rows)                            # interleave safe & dangerous

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(["url", "label"])           # the header row
        writer.writerows(labeled_rows)              # all the data rows

    print(f"wrote {len(labeled_rows)} rows -> {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
