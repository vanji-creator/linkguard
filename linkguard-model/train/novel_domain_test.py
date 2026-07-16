"""
novel_domain_test.py
--------------------
Honest generalization check for the WORD/CHUNK model.

The worry: with 22k chunk-columns and safe URLs from only 157 domains, the
model might have MEMORISED safe-domain fingerprints (githu, googl, wikipedi)
instead of learning general safety.

The test: collect safe URLs from Tranco domains our training NEVER used
(ranks 401+), then run the model. These are all truly SAFE, so ANY
"dangerous"/"suspicious" verdict here is a FALSE ALARM on a novel-but-safe
site. A low false-alarm rate = the model generalizes. A high rate = it
memorised our old domains.
"""

import sys
import joblib

sys.path.insert(0, "data")                 # reuse the crawler we already wrote
import collect_safe                        # for harvest_links_from_domain + settings

MODEL_IN   = "train/model_words.joblib"
TRANCO     = "data/raw/top-1m.csv"
SKIP_RANKS = 400      # ranks 1..400 were used in TRAINING -> skip them
TAKE_RANKS = 100      # how many NOVEL domains to test (401..500)
LOW_CUT, HIGH_CUT = 0.30, 0.70

# keep the crawl quick: fewer links per novel domain than the training crawl used
collect_safe.MAX_LINKS_PER_DOMAIN = 15


def strip_scheme(url):
    return url.split("://", 1)[1] if "://" in url else url


def verdict_for(danger_probability):
    if danger_probability < LOW_CUT:
        return "safe"
    if danger_probability > HIGH_CUT:
        return "dangerous"
    return "suspicious"


def read_novel_domains():
    """Read Tranco domains AFTER the ones used in training (ranks 401..500)."""
    novel_domains = []
    with open(TRANCO, "r", encoding="utf-8") as tranco_file:
        for line in tranco_file:
            rank_text, domain = line.strip().split(",", 1)
            rank = int(rank_text)
            if rank <= SKIP_RANKS:            # used in training -> skip
                continue
            novel_domains.append(domain)
            if len(novel_domains) >= TAKE_RANKS:
                break
    return novel_domains


def main():
    pipeline = joblib.load(MODEL_IN)
    novel_domains = read_novel_domains()

    # Harvest real safe URLs from each novel domain (same crawler as training).
    novel_safe_urls = []
    for position, domain in enumerate(novel_domains, start=1):
        print(f"[{position}/{len(novel_domains)}] {domain}", flush=True)
        novel_safe_urls.extend(collect_safe.harvest_links_from_domain(domain))
    print(f"\ncollected {len(novel_safe_urls)} novel safe URLs")

    if not novel_safe_urls:
        print("no URLs collected — nothing to test")
        return

    # Score them all. Every one SHOULD be 'safe'; anything else is a false alarm.
    counts = {"safe": 0, "suspicious": 0, "dangerous": 0}
    false_alarms = []          # (probability, url) for the non-safe ones
    for url in novel_safe_urls:
        danger_prob = pipeline.predict_proba([strip_scheme(url)])[0][1]
        label = verdict_for(danger_prob)
        counts[label] += 1
        if label != "safe":
            false_alarms.append((danger_prob, url))

    total = len(novel_safe_urls)
    non_safe = counts["suspicious"] + counts["dangerous"]
    print("\n--- RESULTS on novel-but-safe URLs ---")
    print(f"  safe       : {counts['safe']:5d}")
    print(f"  suspicious : {counts['suspicious']:5d}")
    print(f"  dangerous  : {counts['dangerous']:5d}")
    print(f"  FALSE-ALARM RATE (not safe): {non_safe}/{total} = {100*non_safe/total:.1f}%")

    # show the worst offenders so we can eyeball WHY
    false_alarms.sort(reverse=True)
    print("\n  worst false alarms (highest danger prob):")
    for probability, url in false_alarms[:10]:
        print(f"    {probability:.3f}  {url[:85]}")


if __name__ == "__main__":
    main()
