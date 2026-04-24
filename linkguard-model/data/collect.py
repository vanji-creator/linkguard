"""
collect.py — Download all training data feeds.

Automated sources (all free, no registration, no API key):
  • URLhaus          — malware URLs (~600K)
  • OpenPhish        — phishing feed (~5K live)
  • ThreatFox CSV    — bulk IOC export, no auth (replaces broken JSON API)
  • Phishing.Database — 400K+ active phishing links, GitHub-hosted
  • Tranco           — top-1M safe domains

Usage:
    python data/collect.py
"""

import sys
import csv
import zipfile
import io
from pathlib import Path

import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    RAW_DIR,
    URLHAUS_URL, OPENPHISH_URL, THREATFOX_CSV_URL,
    PHISHING_DB_URL, TRANCO_URL,
)

TIMEOUT = 90
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def _download(url: str, dest: Path, desc: str) -> bool:
    """Stream-download url → dest. Returns True on success."""
    try:
        print(f"  Fetching {desc}...")
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(dest, "wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, desc=f"  {desc}", leave=False
        ) as bar:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
                bar.update(len(chunk))
        size_kb = dest.stat().st_size // 1024
        print(f"  ✓ {desc} → {dest.name} ({size_kb:,} KB)")
        return True
    except Exception as e:
        print(f"  ✗ {desc} failed: {e}")
        return False


def collect_urlhaus():
    dest = RAW_DIR / "urlhaus.txt"
    if dest.exists():
        print(f"  ✓ URLhaus already present — skipping")
        return
    _download(URLHAUS_URL, dest, "URLhaus malware feed")


def collect_openphish():
    dest = RAW_DIR / "openphish.txt"
    if dest.exists():
        print(f"  ✓ OpenPhish already present — skipping")
        return
    _download(OPENPHISH_URL, dest, "OpenPhish phishing feed")


def collect_threatfox():
    """
    ThreatFox bulk CSV export — no API key needed.
    Format: id,ioc,ioc_type,threat_type,fk_malware,malware_alias,...
    We extract rows where ioc_type is 'url' or 'domain'.
    """
    dest = RAW_DIR / "threatfox.txt"
    if dest.exists():
        print(f"  ✓ ThreatFox already present — skipping")
        return

    zip_dest = RAW_DIR / "_threatfox.zip"
    ok = _download(THREATFOX_CSV_URL, zip_dest, "ThreatFox bulk CSV (zipped)")
    if not ok:
        return

    print("  Extracting ThreatFox zip...")
    urls = []
    try:
        with zipfile.ZipFile(zip_dest) as zf:
            csv_name = next(
                (n for n in zf.namelist() if n.endswith(".csv")),
                zf.namelist()[0]
            )
            with zf.open(csv_name) as f:
                text = io.TextIOWrapper(f, encoding="utf-8", errors="ignore")
                reader = csv.reader(text)
                for row in reader:
                    if not row or row[0].startswith("#"):
                        continue
                    if len(row) < 3:
                        continue
                    ioc      = row[1].strip().strip('"')
                    ioc_type = row[2].strip().strip('"').lower()
                    if ioc_type == "url":
                        urls.append(ioc)
                    elif ioc_type == "domain":
                        urls.append("http://" + ioc)
    except Exception as e:
        print(f"  ✗ ThreatFox extraction failed: {e}")
        zip_dest.unlink(missing_ok=True)
        return

    zip_dest.unlink(missing_ok=True)
    with open(dest, "w") as f:
        f.write("\n".join(urls))
    print(f"  ✓ ThreatFox → {dest.name} ({len(urls):,} URLs/domains)")


def collect_phishing_database():
    """
    mitchellkrogza/Phishing.Database — active phishing links.
    Plain text, one URL per line, GitHub-hosted, no auth.
    ~400K entries, updated regularly.
    """
    dest = RAW_DIR / "phishing_database.txt"
    if dest.exists():
        print(f"  ✓ Phishing.Database already present — skipping")
        return
    _download(PHISHING_DB_URL, dest, "Phishing.Database (GitHub)")


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
            names    = zf.namelist()
            csv_name = next((n for n in names if n.endswith(".csv")), names[0])
            with zf.open(csv_name) as src, open(dest, "wb") as dst:
                dst.write(src.read())
        zip_dest.unlink()
        print(f"  ✓ Tranco extracted → {dest.name}")


def _count_lines(path: Path) -> int:
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def main():
    print("\n=== LinkGuard — Data Collection ===\n")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/5] URLhaus (malware URLs)")
    collect_urlhaus()

    print("\n[2/5] OpenPhish (phishing feed)")
    collect_openphish()

    print("\n[3/5] ThreatFox (bulk CSV — no auth needed)")
    collect_threatfox()

    print("\n[4/5] Phishing.Database (GitHub, 400K+ active phishing)")
    collect_phishing_database()

    print("\n[5/5] Tranco top-1M (safe domains)")
    collect_tranco()

    print("\n── Summary ────────────────────────────────────────")
    for name, fname in [
        ("URLhaus",            "urlhaus.txt"),
        ("OpenPhish",          "openphish.txt"),
        ("ThreatFox",          "threatfox.txt"),
        ("Phishing.Database",  "phishing_database.txt"),
        ("Tranco",             "tranco_top1m.csv"),
    ]:
        path = RAW_DIR / fname
        if path.exists():
            lines = _count_lines(path)
            print(f"  {name:<22} {lines:>8,} lines")
        else:
            print(f"  {name:<22}   MISSING")

    print("\n✓ Collection complete. Run: python data/preprocess.py\n")


if __name__ == "__main__":
    main()
