"""
collect.py — Download all training data feeds.

Automated sources (all free, no registration):
  • URLhaus    — malware URLs (~600K)
  • OpenPhish  — phishing feed (~5K live)
  • ThreatFox  — threat IOCs (~50K)
  • PhishStats — phishing URLs with scores (~100K, updated every 90 min)
  • Tranco     — top-1M safe domains

Usage:
    python data/collect.py
"""

import sys
import json
import zipfile
import io
import time
from pathlib import Path

import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    RAW_DIR, URLHAUS_URL, OPENPHISH_URL, THREATFOX_URL, TRANCO_URL,
    PHISHSTATS_URL,
)

TIMEOUT = 60
HEADERS = {"User-Agent": "LinkGuard-Research/1.0 (security-research)"}


def _download(url: str, dest: Path, desc: str, method="GET", **kwargs) -> bool:
    """Download url → dest file. Returns True on success."""
    try:
        print(f"  Fetching {desc}...")
        if method == "POST":
            r = requests.post(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        else:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                             stream=True, **kwargs)
        r.raise_for_status()

        total = int(r.headers.get("content-length", 0))
        with open(dest, "wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, desc=f"  {desc}", leave=False
        ) as bar:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
                bar.update(len(chunk))
        print(f"  ✓ {desc} → {dest.name} ({dest.stat().st_size // 1024} KB)")
        return True
    except Exception as e:
        print(f"  ✗ {desc} failed: {e}")
        return False


def collect_urlhaus():
    dest = RAW_DIR / "urlhaus.txt"
    if dest.exists():
        print(f"  ✓ URLhaus already present ({dest.stat().st_size // 1024} KB) — skipping")
        return
    _download(URLHAUS_URL, dest, "URLhaus malware feed")


def collect_openphish():
    dest = RAW_DIR / "openphish.txt"
    if dest.exists():
        print(f"  ✓ OpenPhish already present — skipping")
        return
    _download(OPENPHISH_URL, dest, "OpenPhish phishing feed")


def collect_threatfox():
    dest = RAW_DIR / "threatfox.json"
    if dest.exists():
        print(f"  ✓ ThreatFox already present — skipping")
        return
    try:
        print("  Fetching ThreatFox IOCs (last 30 days)...")
        r = requests.post(
            THREATFOX_URL,
            json={"query": "get_iocs", "days": 30},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        with open(dest, "w") as f:
            json.dump(data, f)
        ioc_count = len(data.get("data", []))
        print(f"  ✓ ThreatFox → {dest.name} ({ioc_count} IOCs)")
    except Exception as e:
        print(f"  ✗ ThreatFox failed: {e}")


def collect_tranco():
    dest = RAW_DIR / "tranco_top1m.csv"
    if dest.exists():
        print(f"  ✓ Tranco top-1M already present — skipping")
        return
    zip_dest = RAW_DIR / "tranco_top1m.zip"
    ok = _download(TRANCO_URL, zip_dest, "Tranco top-1M safe domains")
    if ok:
        print("  Extracting Tranco zip...")
        with zipfile.ZipFile(zip_dest) as zf:
            # zip contains a single CSV file named "top-1m.csv"
            names = zf.namelist()
            csv_name = next((n for n in names if n.endswith(".csv")), names[0])
            with zf.open(csv_name) as src, open(dest, "wb") as dst:
                dst.write(src.read())
        zip_dest.unlink()
        print(f"  ✓ Tranco extracted → {dest.name}")


def collect_phishstats():
    """
    PhishStats — phishing URLs with confidence scores.
    Free, no registration, updated every 90 minutes.
    Format: #date,score,url,ip
    We keep score >= 5 (high-confidence phishing confirmed by multiple sources).
    """
    dest = RAW_DIR / "phishstats.csv"
    if dest.exists():
        print(f"  ✓ PhishStats already present — skipping")
        return
    _download(PHISHSTATS_URL, dest, "PhishStats phishing feed")


def main():
    print("\n=== LinkGuard — Data Collection ===\n")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/5] URLhaus (malware URLs)")
    collect_urlhaus()

    print("\n[2/5] OpenPhish (phishing feed)")
    collect_openphish()

    print("\n[3/5] ThreatFox (threat IOCs)")
    collect_threatfox()

    print("\n[4/5] PhishStats (phishing URLs, no registration needed)")
    collect_phishstats()

    print("\n[5/5] Tranco top-1M (safe domains)")
    collect_tranco()

    print("\n✓ Collection complete. Run: python data/preprocess.py\n")


if __name__ == "__main__":
    main()
