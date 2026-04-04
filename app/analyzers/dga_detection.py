"""DGA (Domain Generation Algorithm) detection — flag algorithmically generated domains."""

import math
import re
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP

# TLDs to ignore (common legitimate short domains)
IGNORE_TLDS = {"local", "internal", "localhost", "arpa", "test", "invalid", "example"}

# Known CDN/cloud domains that look random but are legitimate
KNOWN_LEGITIMATE = {
    "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamaitechnologies.com",
    "azure.com", "azurewebsites.net", "cloudflare.com", "fastly.net",
    "googleusercontent.com", "googleapis.com", "gstatic.com",
    "microsoftonline.com", "windows.net", "office.com", "office365.com",
}

# Consonant-heavy threshold for DGA scoring
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _consonant_ratio(s):
    """Calculate the ratio of consonants to total alpha characters."""
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0
    consonant_count = sum(1 for c in alpha if c in CONSONANTS)
    return consonant_count / len(alpha)


def _digit_ratio(s):
    """Calculate the ratio of digits to total characters."""
    if not s:
        return 0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _has_dictionary_words(s):
    """Simple heuristic — check if string contains common English patterns."""
    common = ["the", "and", "for", "com", "net", "org", "web", "mail", "www",
              "api", "app", "dev", "cdn", "img", "login", "auth", "cloud"]
    s_lower = s.lower()
    for word in common:
        if word in s_lower:
            return True
    return False


def _score_domain(label):
    """Score a domain label for DGA likelihood. Higher = more suspicious."""
    score = 0

    # Length-based scoring
    if len(label) > 20:
        score += 2
    elif len(label) > 12:
        score += 1

    # Entropy
    ent = _entropy(label)
    if ent > 4.0:
        score += 3
    elif ent > 3.5:
        score += 2
    elif ent > 3.0:
        score += 1

    # Consonant ratio (DGA domains tend to be consonant-heavy)
    cr = _consonant_ratio(label)
    if cr > 0.75:
        score += 2
    elif cr > 0.65:
        score += 1

    # Digit ratio (DGA domains often mix digits)
    dr = _digit_ratio(label)
    if dr > 0.3:
        score += 2
    elif dr > 0.15:
        score += 1

    # No dictionary words found
    if not _has_dictionary_words(label) and len(label) > 8:
        score += 1

    # Reduce score for known patterns
    if _has_dictionary_words(label):
        score -= 1

    return max(0, score)


def analyze_dga(packets):
    results = {
        "suspicious_domains": [],
        "summary": {
            "total_queries": 0,
            "suspicious_count": 0,
            "unique_suspicious_domains": 0,
        },
    }

    seen_domains = set()
    domain_queries = defaultdict(lambda: {"count": 0, "clients": set(), "first_seen": None})

    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            continue

        # Only queries (QR=0)
        if pkt[DNS].qr != 0:
            continue

        results["summary"]["total_queries"] += 1

        try:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            continue

        parts = qname.lower().split(".")
        if len(parts) < 2:
            continue

        tld = parts[-1]
        if tld in IGNORE_TLDS:
            continue

        # Get the base domain (SLD)
        base_domain = ".".join(parts[-2:])
        if base_domain in KNOWN_LEGITIMATE:
            continue

        # Score the second-level domain label
        sld = parts[-2]
        if len(sld) < 6:
            continue

        score = _score_domain(sld)

        if score >= 4:  # DGA threshold
            client_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            ts = float(pkt.time)

            if base_domain not in seen_domains:
                seen_domains.add(base_domain)

            dq = domain_queries[base_domain]
            dq["count"] += 1
            dq["clients"].add(client_ip)
            if dq["first_seen"] is None:
                dq["first_seen"] = ts

    # Build results
    for domain, data in sorted(domain_queries.items(), key=lambda x: -x[1]["count"]):
        sld = domain.split(".")[0]
        ent = _entropy(sld)
        cr = _consonant_ratio(sld)
        score = _score_domain(sld)

        if score >= 7:
            severity = "CRITICAL"
        elif score >= 5:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        results["suspicious_domains"].append({
            "domain": domain,
            "sld": sld,
            "dga_score": score,
            "entropy": round(ent, 2),
            "consonant_ratio": round(cr, 2),
            "query_count": data["count"],
            "unique_clients": len(data["clients"]),
            "clients": sorted(data["clients"]),
            "timestamp": data["first_seen"],
            "severity": severity,
        })

    results["summary"]["suspicious_count"] = sum(d["query_count"] for d in results["suspicious_domains"])
    results["summary"]["unique_suspicious_domains"] = len(results["suspicious_domains"])

    return results
