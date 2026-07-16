"""
collect_safe.py
----------------
Build the SAFE half of our dataset.

Idea (from what we designed together):
  - TRUST comes from Tranco: its top domains are popular, long-lived sites,
    so they are almost certainly safe.
  - SHAPE (real paths, varied length) comes from visiting each trusted
    homepage and harvesting the real internal links it already publishes.
  - DIVERSITY: we cap how many links we take from any single domain, so no
    one site dominates and the model learns "safe in general", not "github = safe".

Output: data/safe_urls.txt  (one safe URL per line)
"""

import re                     # for pulling href="..." links out of raw HTML
import time                   # to pause politely between sites
import concurrent.futures     # to put a HARD time limit on each download
import requests               # to download each homepage

# ---- settings you can tune (kept at the top so they are easy to find) ----
TRANCO_FILE      = "data/raw/top-1m.csv"   # the ranked list: "rank,domain"
OUTPUT_FILE      = "data/safe_urls.txt"    # where we save the safe URLs
HOW_MANY_DOMAINS = 400                      # how many top domains to visit
MAX_LINKS_PER_DOMAIN = 60                   # diversity cap: at most N links from one site
REQUEST_TIMEOUT  = 12                       # requests' own timeout (connect/read gaps)
HARD_LIMIT_SECONDS = 18                     # absolute cap per domain, even if requests hangs
BROWSER_HEADER   = {"User-Agent": "Mozilla/5.0"}  # some sites ignore non-browsers

# A small pool of worker threads. We download inside a worker so the main loop can
# enforce HARD_LIMIT_SECONDS: if a hostile server dribbles data to hang requests,
# we simply abandon that worker and move on. One bad site can't freeze the crawl.
DOWNLOAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# This regex finds links that point to an inner page: href="/something"
# We only want same-site paths (starting with "/"), not ads/other domains.
INTERNAL_LINK_PATTERN = re.compile(r'href="(/[^"?#]+)"')

def is_same_site_path(path):
    """
    Return True only for links to THIS domain's own inner pages.

    We reject "//other.com/..." (protocol-relative links to a DIFFERENT domain).
    Reason = TRUST: our "safe" guarantee only covers a trusted domain's OWN pages.
    A trusted site linking OUT to some other domain does NOT make that domain safe.

    We deliberately KEEP asset URLs (.css/.png/etc.) — they are real, correctly-safe
    URLs on the trusted domain, so they belong in the safe pile.
    """
    if path.startswith("//"):                     # "//other.com/..." = a DIFFERENT domain
        return False                              # not covered by this domain's trust
    return True                                   # a same-site path (/foo) is fine to keep


def read_top_domains(how_many):
    """Read the first `how_many` domain names from the Tranco file."""
    domains = []                                  # collected domain names go here
    with open(TRANCO_FILE, "r", encoding="utf-8") as tranco_file:
        for line in tranco_file:                  # each line looks like "1,google.com"
            rank, domain = line.strip().split(",", 1)   # split into rank and domain
            domains.append(domain)                # keep just the domain
            if len(domains) >= how_many:          # stop once we have enough
                break
    return domains


def download_homepage_html(domain):
    """Download one homepage's raw HTML. May hang on a bad server; the caller bounds it."""
    homepage_url = "https://" + domain            # try the secure version
    response = requests.get(homepage_url, headers=BROWSER_HEADER,
                            timeout=REQUEST_TIMEOUT)
    return response.text                          # the raw HTML


def harvest_links_from_domain(domain):
    """Visit one domain's homepage and return a list of real safe URLs (with paths)."""
    homepage_url = "https://" + domain
    # Run the download in a worker thread with a HARD wall-clock limit. If the
    # server tries to hang us, future.result() raises TimeoutError -> we give up.
    future = DOWNLOAD_POOL.submit(download_homepage_html, domain)
    try:
        html_text = future.result(timeout=HARD_LIMIT_SECONDS)
    except Exception as error:                    # timeout, network error, bad cert, etc.
        print(f"  skip {domain}: {error}")        # note it and move on (don't crash)
        return []

    found_paths = INTERNAL_LINK_PATTERN.findall(html_text)   # e.g. ['/features', '/about']
    safe_urls = []                                 # full URLs we will keep
    seen_paths = set()                             # avoid duplicates within this one site
    for path in found_paths:
        if path in seen_paths:                     # already have this exact path
            continue
        seen_paths.add(path)
        if not is_same_site_path(path):            # drop links to OTHER domains (trust)
            continue
        safe_urls.append(homepage_url + path)      # e.g. "https://github.com/features"
        if len(safe_urls) >= MAX_LINKS_PER_DOMAIN: # diversity cap reached for this site
            break
    return safe_urls


def main():
    top_domains = read_top_domains(HOW_MANY_DOMAINS)   # the trusted sites to visit
    all_safe_urls = []                                 # everything we collect

    for position, domain in enumerate(top_domains, start=1):
        print(f"[{position}/{len(top_domains)}] visiting {domain} ...")
        urls_from_this_domain = harvest_links_from_domain(domain)
        all_safe_urls.extend(urls_from_this_domain)    # add them to the big list
        time.sleep(0.15)                               # be polite: small pause per site

    # remove any duplicates across ALL domains, keep a stable order
    unique_safe_urls = list(dict.fromkeys(all_safe_urls))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        for url in unique_safe_urls:
            output_file.write(url + "\n")

    print(f"\nDONE. Collected {len(unique_safe_urls)} unique safe URLs "
          f"from {len(top_domains)} domains -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
