"""
features.py — 50-dimensional URL feature extractor.

Used by both the training pipeline and the inference server.
Produces a deterministic float32 numpy array for any URL string.

Feature groups:
  [0-5]   Length features
  [6-14]  Character count features
  [15-20] Hostname structure
  [21-26] Path/query structure
  [27-31] Entropy features
  [32-38] Keyword / pattern flags
  [39-44] Token statistics
  [45-49] Reputation signals
"""

import re
import math
from urllib.parse import urlparse, parse_qs, unquote
from typing import List

import numpy as np

# ── Constant sets ──────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "work", "click", "link",
    "online", "site", "info", "pw", "cc", "biz", "ws", "su", "icu", "fun",
    "space", "loan", "stream", "racing", "party", "review", "science", "win",
    "webcam", "country",
}
SAFE_TLDS = {
    "com", "org", "net", "edu", "gov", "in", "io", "co", "uk", "de", "fr",
    "jp", "au", "ca", "us", "int",
}
INDIA_GOV_TLDS = {"gov.in", "nic.in", "ac.in"}

BRAND_KEYWORDS = {
    "google", "facebook", "paypal", "amazon", "microsoft", "apple", "netflix",
    "instagram", "twitter", "linkedin", "whatsapp", "telegram", "youtube",
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "canara", "bob",
    "paytm", "phonepe", "razorpay", "uidai", "irctc", "incometax",
}
PHISHING_KEYWORDS = {
    "login", "signin", "sign-in", "account", "update", "verify", "secure",
    "confirm", "password", "credential", "wallet", "authenticate", "validation",
    "suspend", "urgent", "blocked", "kyc", "otp", "upi", "payment", "reward",
    "prize", "winner", "claim", "free", "gift", "offer", "lucky", "bonus",
    "alert", "limited", "expire", "reactivate", "unusual",
}
REDIRECT_KEYWORDS = {"redirect", "redir", "forward", "url=", "link=", "goto", "jump"}
FREE_HOSTS = {
    "000webhostapp.com", "wixsite.com", "weebly.com", "yolasite.com",
    "wordpress.com", "blogspot.com", "tumblr.com", "github.io",
    "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com",
}
SHORTENERS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "tiny.cc", "rb.gy", "shorte.st", "clck.ru",
}

_IP_RE  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PORT_RE = re.compile(r":\d+$")
_HEX_RE  = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _tokenize(url: str) -> List[str]:
    """Split URL on separators to get meaningful tokens."""
    return [t for t in re.split(r"[.\-_/=?&#+%@!:,]", url) if t]


def extract(url: str) -> np.ndarray:
    """
    Extract 50 float32 features from a URL string.
    Always returns an array of shape (50,) regardless of URL validity.
    """
    feats = np.zeros(50, dtype=np.float32)

    url = url.strip()
    if not url:
        return feats

    # Ensure parseable
    raw = url
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        p = urlparse(url)
    except Exception:
        return feats

    hostname   = (p.hostname or "").lower()
    path       = p.path or ""
    query      = p.query or ""
    fragment   = p.fragment or ""
    netloc     = p.netloc or ""
    url_lower  = url.lower()
    full_lower = raw.lower()

    # ── [0-5] Length features ─────────────────────────────────────────────────
    feats[0] = min(len(raw), 2000)               # url_length (capped)
    feats[1] = len(hostname)                      # hostname_length
    feats[2] = len(path)                          # path_length
    feats[3] = len(query)                         # query_length
    feats[4] = len(fragment)                      # fragment_length
    feats[5] = len(netloc)                        # netloc_length (includes port)

    # ── [6-14] Character counts ───────────────────────────────────────────────
    feats[6]  = raw.count(".")
    feats[7]  = raw.count("-")
    feats[8]  = raw.count("_")
    feats[9]  = sum(c.isdigit() for c in raw)
    feats[10] = raw.count("@")
    feats[11] = raw.count("%")
    feats[12] = raw.count("?")
    feats[13] = raw.count("=")
    feats[14] = raw.count("&")

    # ── [15-20] Hostname structure ────────────────────────────────────────────
    feats[15] = 1.0 if _IP_RE.match(hostname) else 0.0         # has_ip
    feats[16] = 1.0 if p.port else 0.0                          # has_explicit_port

    parts = hostname.split(".")
    tld   = parts[-1] if parts else ""
    feats[17] = max(0, len(parts) - 2)                           # subdomain_depth
    feats[18] = len(tld)                                         # tld_length
    feats[19] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0          # is_suspicious_tld
    feats[20] = 1.0 if tld in SAFE_TLDS else 0.0                # is_safe_tld

    # ── [21-26] Path / query structure ───────────────────────────────────────
    feats[21] = 1.0 if p.scheme == "https" else 0.0             # has_https
    feats[22] = path.count("/")                                  # path_depth
    feats[23] = len(parse_qs(query))                             # num_query_params
    feats[24] = 1.0 if _HEX_RE.search(raw) else 0.0            # has_encoded_chars
    feats[25] = len(_HEX_RE.findall(raw))                        # num_encoded_chars
    feats[26] = 1.0 if "//" in path else 0.0                    # has_double_slash_path

    # ── [27-31] Entropy ───────────────────────────────────────────────────────
    feats[27] = _entropy(raw)                                    # url_entropy
    feats[28] = _entropy(hostname)                               # hostname_entropy
    feats[29] = _entropy(path)                                   # path_entropy
    feats[30] = _entropy(query)                                  # query_entropy
    n = len(raw)
    feats[31] = sum(c.isdigit() for c in raw) / max(n, 1)       # digit_ratio

    # ── [32-38] Keyword / pattern flags ──────────────────────────────────────
    path_query = (path + query).lower()
    feats[32] = 1.0 if any(kw in full_lower for kw in PHISHING_KEYWORDS) else 0.0
    feats[33] = sum(1 for kw in PHISHING_KEYWORDS if kw in full_lower)   # kw count
    feats[34] = 1.0 if any(kw in full_lower for kw in REDIRECT_KEYWORDS) else 0.0
    feats[35] = 1.0 if "--" in hostname else 0.0                # consecutive hyphens in host
    feats[36] = 1.0 if any(b in hostname for b in BRAND_KEYWORDS) else 0.0  # brand in host (impersonation)
    feats[37] = 1.0 if any(b in path_query for b in BRAND_KEYWORDS) else 0.0 # brand in path
    feats[38] = sum(1 for b in BRAND_KEYWORDS if b in full_lower)          # total brand mentions

    # ── [39-44] Token statistics ──────────────────────────────────────────────
    tokens = _tokenize(full_lower)
    if tokens:
        lengths = [len(t) for t in tokens]
        feats[39] = len(tokens)                                   # num_tokens
        feats[40] = max(lengths)                                  # longest_token
        feats[41] = sum(lengths) / len(lengths)                   # avg_token_length
    else:
        feats[39] = feats[40] = feats[41] = 0.0

    # Consonant cluster ratio in hostname (DGA detection)
    consonants = sum(1 for c in hostname if c.isalpha() and c not in "aeiou")
    letters    = sum(1 for c in hostname if c.isalpha())
    feats[42] = consonants / max(letters, 1)                      # consonant_ratio_host

    # Vowel ratio in hostname
    vowels = letters - consonants
    feats[43] = vowels / max(letters, 1)                          # vowel_ratio_host

    # Special char density
    special = sum(1 for c in raw if not c.isalnum() and c not in ":/.-_?&=%#+@!")
    feats[44] = special / max(n, 1)                               # unusual_char_density

    # ── [45-49] Reputation signals ────────────────────────────────────────────
    reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    feats[45] = 1.0 if reg_domain in FREE_HOSTS else 0.0          # is_free_host
    feats[46] = 1.0 if reg_domain in SHORTENERS else 0.0          # is_shortener
    feats[47] = 1.0 if any(d in hostname for d in INDIA_GOV_TLDS) else 0.0  # is_india_gov
    # Numeric subdomain (e.g. 192-168-1-1.evil.com)
    feats[48] = 1.0 if re.search(r"\d{1,3}[-\.]\d{1,3}[-\.]\d{1,3}", hostname) else 0.0
    # URL contains another URL (double-URL embedding)
    feats[49] = 1.0 if re.search(r"https?://", path + query) else 0.0

    # Replace any NaN/inf that crept in
    np.nan_to_num(feats, copy=False)
    return feats


def feature_names() -> List[str]:
    return [
        "url_length", "hostname_length", "path_length", "query_length",
        "fragment_length", "netloc_length",
        "num_dots", "num_hyphens", "num_underscores", "num_digits",
        "num_at", "num_percent", "num_question", "num_equals", "num_ampersand",
        "has_ip", "has_port", "subdomain_depth", "tld_length",
        "is_suspicious_tld", "is_safe_tld",
        "has_https", "path_depth", "num_query_params",
        "has_encoded_chars", "num_encoded_chars", "has_double_slash_path",
        "url_entropy", "hostname_entropy", "path_entropy", "query_entropy",
        "digit_ratio",
        "has_phishing_kw", "phishing_kw_count", "has_redirect_kw",
        "has_consec_hyphens_host", "brand_in_host", "brand_in_path",
        "brand_count",
        "num_tokens", "longest_token", "avg_token_length",
        "consonant_ratio_host", "vowel_ratio_host", "unusual_char_density",
        "is_free_host", "is_shortener", "is_india_gov",
        "numeric_subdomain", "embedded_url",
    ]


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=hello",
        "http://192.168.1.1/admin/login.php",
        "https://paypal-secure-login.xyz/verify/account?token=abc123",
        "https://bit.ly/3xkQm9",
        "http://xn--80aaolcalcnig8a.xn--p1ai/kyc-update?otp=verify",
    ]
    names = feature_names()
    for url in test_urls:
        f = extract(url)
        print(f"\n{url}")
        interesting = [(names[i], f[i]) for i in range(50) if f[i] != 0.0]
        for name, val in interesting:
            print(f"  {name}: {val:.3f}")
