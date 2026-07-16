"""
build_dataset.py
----------------
Combine the two piles into ONE labeled table that we can train on.

  safe URLs      -> label 0
  dangerous URLs -> label 1

Two important moves:
  BALANCE  : use an EQUAL number of safe and dangerous rows, so the model
             cannot cheat by always guessing the bigger class.
  SHUFFLE  : mix the rows so labels are not in big blocks. We use a fixed
             random_state (a "seed") so the shuffle is the SAME every run
             -> reproducible results.

Output: data/dataset.csv  with two columns: url, label
"""

import pandas as pd                 # the standard tool for tables of data

SAFE_FILE      = "data/safe_urls.txt"          # our collected safe URLs
DANGEROUS_FILE = "data/raw/urlhaus_recent.txt" # URLhaus malware URLs
OUTPUT_CSV     = "data/dataset.csv"            # the labeled table we will save
RANDOM_SEED    = 42                            # fixed seed = same result every run


def read_urls(path):
    """Read a file of URLs (one per line), skipping blanks and '#' comments."""
    urls = []                                   # collected URLs go here
    with open(path, encoding="utf-8") as text_file:
        for line in text_file:
            cleaned = line.strip()              # remove spaces / newline
            if not cleaned or cleaned.startswith("#"):
                continue                        # skip empty lines and comments
            urls.append(cleaned)
    return urls


def main():
    safe_urls = read_urls(SAFE_FILE)            # label 0 later
    dangerous_urls = read_urls(DANGEROUS_FILE)  # label 1 later
    print(f"loaded  safe={len(safe_urls)}  dangerous={len(dangerous_urls)}")

    # BALANCE: the class size is the SMALLER of the two piles.
    class_size = min(len(safe_urls), len(dangerous_urls))
    print(f"balancing both classes to {class_size} rows each")

    # Put each pile into a small table with its label attached.
    safe_frame = pd.DataFrame({"url": safe_urls, "label": 0})
    dangerous_frame = pd.DataFrame({"url": dangerous_urls, "label": 1})

    # Randomly pick class_size rows from each (random, not just the first N).
    safe_frame = safe_frame.sample(n=class_size, random_state=RANDOM_SEED)
    dangerous_frame = dangerous_frame.sample(n=class_size, random_state=RANDOM_SEED)

    # Stack the two tables, then SHUFFLE the whole thing so labels are mixed.
    dataset = pd.concat([safe_frame, dangerous_frame], ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    dataset.to_csv(OUTPUT_CSV, index=False)     # save without the row-number column
    print(f"\nwrote {len(dataset)} rows -> {OUTPUT_CSV}")
    print("label counts:")
    print(dataset["label"].value_counts())      # should be equal: 0 and 1


if __name__ == "__main__":
    main()
