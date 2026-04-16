"""
hf_client.py — Test the deployed HuggingFace Spaces endpoint.

Use this to verify your Spaces API is working before wiring it into
the extension. Set HF_SPACE_URL to your Space's URL.

Usage:
    HF_SPACE_URL=https://your-space.hf.space python serve/hf_client.py

Or edit HF_SPACE_URL directly below.
"""

import os
import sys
import time
import json
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import CONFIDENCE_THRESHOLD

HF_SPACE_URL = os.getenv("HF_SPACE_URL", "").rstrip("/")

TEST_URLS = [
    ("https://www.google.com/", "safe"),
    ("https://github.com/vanji-creator/linkguard", "safe"),
    ("http://paypal-secure-login.xyz/verify?token=abc123", "dangerous"),
    ("https://free-iphone-winner.tk/claim?user=vanji", "dangerous"),
    ("http://192.168.1.1/admin/login.php", "suspicious"),
    ("https://sbi-kyc-update.online/verify/account", "dangerous"),
]


def scan_url(url: str, space_url: str) -> dict:
    endpoint = f"{space_url}/scan"
    t0 = time.perf_counter()
    r  = requests.post(endpoint, json={"url": url}, timeout=15)
    r.raise_for_status()
    result = r.json()
    result["latency_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if not HF_SPACE_URL:
        print("⚠  HF_SPACE_URL not set.")
        print("   Set it in config.py (HF_SPACE) or via environment variable:")
        print("   export HF_SPACE_URL=https://your-space.hf.space")
        sys.exit(1)

    print(f"\n=== LinkGuard — HuggingFace Spaces Test ===")
    print(f"Endpoint: {HF_SPACE_URL}/scan\n")

    # Health check
    try:
        h = requests.get(f"{HF_SPACE_URL}/health", timeout=10)
        print(f"Health: {h.json()}\n")
    except Exception as e:
        print(f"Health check failed: {e}\n")

    icons   = {"safe": "✓", "suspicious": "⚠", "dangerous": "✗"}
    correct = 0

    for url, expected in TEST_URLS:
        try:
            result  = scan_url(url, HF_SPACE_URL)
            verdict = result["verdict"]
            conf    = result["confidence"]
            match   = "✓" if verdict == expected else "✗"
            below   = " (→ VT)" if conf < CONFIDENCE_THRESHOLD else ""
            if verdict == expected:
                correct += 1
            print(f"  {match} {icons.get(verdict,'?')} [{verdict:10s}] "
                  f"conf={conf:.1%}{below:<8}  {url}")
        except Exception as e:
            print(f"  ✗ ERROR: {e}  {url}")

    print(f"\nAccuracy: {correct}/{len(TEST_URLS)} ({correct/len(TEST_URLS):.0%})")
    print("\nPaste this URL into config.py → HF_SPACE and background.js → LG_MODEL_URL")


if __name__ == "__main__":
    main()
