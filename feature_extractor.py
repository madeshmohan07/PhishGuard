"""
feature_extractor.py
---------------------
Extracts lexical and structural features from a URL for the
AI-Based Phishing Website Detection System.

These features are computed purely from the URL string (no network
calls), which keeps the runtime detection pipeline fast and avoids
introducing a live-network dependency into the classifier itself.
This mirrors the feature list described in Section 5.3 of the
project report.
"""

import re
import math
from urllib.parse import urlparse

# A small, well-known list of URL-shortening services used to flag
# shortened links (Section 5.3 - "Use of URL-shortening services").
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly",
    "shorte.st", "s.id", "tiny.cc", "clck.ru", "lnkd.in",
}

# Keywords frequently seen in phishing URLs, often combined with an
# untrusted domain (Section 5.3 - "Presence of suspicious keywords").
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "signin",
    "bank", "confirm", "password", "webscr", "ebayisapi", "wp-admin",
    "suspend", "authorize", "billing", "invoice", "alert",
]

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _ensure_scheme(url: str) -> str:
    """Prepend a scheme if the user typed a bare domain, so urlparse
    can correctly separate host / path (Section 5.1 - System Input)."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_valid_url(raw_url: str) -> bool:
    """Section 5.2 - URL Validation. Returns False for empty or
    structurally malformed input."""
    if not raw_url or not raw_url.strip():
        return False
    try:
        parsed = urlparse(_ensure_scheme(raw_url))
        host = parsed.netloc.rpartition("@")[2].split(":")[0]  # ignore user-info before '@'
        if not host or "." not in host and not IP_PATTERN.match(host):
            return False
        # reject hosts with illegal characters / empty labels
        if re.search(r"[^a-zA-Z0-9\-.:]", host.replace("[", "").replace("]", "")):
            return False
        return True
    except Exception:
        return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(raw_url: str) -> dict:
    """
    Extract the full lexical/structural feature set for a single URL.
    Returns a dict of feature_name -> numeric value, in a fixed order
    matching FEATURE_NAMES below.
    """
    url = _ensure_scheme(raw_url)
    parsed = urlparse(url)
    hostport = parsed.netloc.rpartition("@")[2]  # real host is what follows the last '@'
    host = hostport.split(":")[0].lower()
    path = parsed.path or ""
    full = url.lower()

    labels = host.split(".") if host else []
    # crude "registered domain" heuristic: last two labels (ignores
    # multi-part TLDs like co.uk, acceptable for a lexical feature set)
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    subdomain_count = max(len(labels) - 2, 0)

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_at_symbols": full.count("@"),
        "num_question_marks": full.count("?"),
        "num_equal_signs": full.count("="),
        "num_ampersands": full.count("&"),
        "num_percent": full.count("%"),
        "num_digits": sum(c.isdigit() for c in full),
        "digit_ratio": (sum(c.isdigit() for c in full) / len(full)) if full else 0,
        "num_subdomains": subdomain_count,
        "has_ip_address": 1 if IP_PATTERN.match(host) else 0,
        "uses_https": 1 if parsed.scheme == "https" else 0,
        "is_shortened": 1 if registered_domain in SHORTENERS else 0,
        "has_suspicious_keyword": 1 if any(k in full for k in SUSPICIOUS_KEYWORDS) else 0,
        "has_port": 1 if ":" in hostport else 0,
        "double_slash_in_path": 1 if "//" in path else 0,
        "brand_like_subdomain": 1 if subdomain_count >= 3 else 0,
        "url_entropy": round(_shannon_entropy(full), 3),
        "hostname_entropy": round(_shannon_entropy(host), 3),
        "has_www_prefix": 1 if labels[:1] == ["www"] else 0,
        "path_depth": len([p for p in path.split("/") if p]),
        "tld_length": len(labels[-1]) if labels else 0,
    }
    return features


FEATURE_NAMES = list(extract_features("http://example.com/").keys())


def explain_suspicious(features: dict) -> list:
    """Human-readable list of which extracted features look suspicious,
    used for the optional explanation shown alongside a PHISHING result
    (Section 5.6)."""
    reasons = []
    if features["has_ip_address"]:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if features["is_shortened"]:
        reasons.append("URL uses a known link-shortening service")
    if features["has_suspicious_keyword"]:
        reasons.append("URL contains a keyword commonly seen in phishing links (e.g. 'login', 'verify', 'secure')")
    if features["num_subdomains"] >= 3:
        reasons.append("URL has an unusually high number of subdomains")
    if features["url_length"] > 75:
        reasons.append("URL is unusually long")
    if features["num_at_symbols"] > 0:
        reasons.append("URL contains an '@' symbol, which can be used to obscure the real destination")
    if features["num_hyphens"] >= 4:
        reasons.append("Domain/path contains an unusually high number of hyphens")
    if features["url_entropy"] > 4.3:
        reasons.append("URL has high character randomness, often seen in generated phishing links")
    return reasons
