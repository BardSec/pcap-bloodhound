"""
DNS Tunneling Detector
──────────────────────
Normal DNS subdomains have Shannon entropy between 2.5–3.2 bits.
Tunneling tools (iodine, dnscat2, dns2tcp) encode stolen data in subdomain
labels, pushing entropy above 3.8.  This analyzer:

  • Entropy-scores every DNS query subdomain
  • Flags abnormal label lengths (> 50 chars)
  • Tracks elevated TXT / NULL / CNAME / ANY record queries
  • Estimates bytes exfiltrated per base domain
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

# DNS record type codes → names (subset)
QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
    252: "AXFR",
    # NULL — often used by iodine
    10: "NULL",
}

# Record types preferred by tunneling tools (not A / AAAA / PTR / MX / NS / SOA)
SUSPICIOUS_QTYPES: set[int] = {5, 10, 16, 252, 255}

ENTROPY_THRESHOLD = 3.8
MAX_SAFE_LABEL_LEN = 50
MIN_SUSPICIOUS_QUERY_COUNT = 5  # ignore one-off anomalies at domain level


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_dns_tunneling(packets: list) -> dict[str, Any]:
    """
    Returns:
        suspicious_queries  – list of individual flagged DNS queries
        tunnel_domains      – per-domain rollup with exfiltration estimate
        total_suspicious    – total count of flagged queries
    """
    suspicious_queries: list[dict] = []
    # base_domain → aggregated stats
    domain_stats: dict[str, dict] = defaultdict(
        lambda: {
            "count": 0,
            "total_label_bytes": 0,
            "high_entropy_count": 0,
            "long_label_count": 0,
            "suspicious_qtype_count": 0,
            "qtype_counter": Counter(),
        }
    )

    for pkt in packets:
        if "DNS" not in pkt:
            continue

        dns = pkt["DNS"]

        # Only DNS queries (qr == 0) with a question section
        if dns.qr != 0 or not dns.qd:
            continue

        try:
            qname_raw: bytes = dns.qd.qname
            qname: str = qname_raw.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            continue

        qtype: int = dns.qd.qtype
        labels = qname.split(".")

        # Require at least a two-label FQDN
        if len(labels) < 2:
            continue

        # base domain = last two labels; subdomain = everything before that
        base_domain = ".".join(labels[-2:]).lower()
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""

        entropy = _shannon_entropy(subdomain) if subdomain else 0.0
        label_len = len(subdomain)
        ts = float(pkt.time)

        # Update per-domain stats
        stats = domain_stats[base_domain]
        stats["count"] += 1
        stats["total_label_bytes"] += label_len
        stats["qtype_counter"][qtype] += 1

        reasons: list[str] = []

        if entropy > ENTROPY_THRESHOLD and subdomain:
            reasons.append(f"High entropy subdomain ({entropy:.2f} bits > {ENTROPY_THRESHOLD})")
            stats["high_entropy_count"] += 1

        if label_len > MAX_SAFE_LABEL_LEN:
            reasons.append(f"Long subdomain label ({label_len} chars)")
            stats["long_label_count"] += 1

        if qtype in SUSPICIOUS_QTYPES:
            reasons.append(f"Suspicious record type ({QTYPE_NAMES.get(qtype, qtype)})")
            stats["suspicious_qtype_count"] += 1

        if reasons:
            suspicious_queries.append(
                {
                    "qname": qname,
                    "subdomain": subdomain[:120],
                    "base_domain": base_domain,
                    "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                    "entropy": round(entropy, 3),
                    "subdomain_length": label_len,
                    "reasons": reasons,
                    "timestamp": ts,
                    "severity": "HIGH" if entropy > 4.2 or label_len > 80 else "MEDIUM",
                }
            )

    # ── Domain-level rollup ───────────────────────────────────────────────────
    tunnel_domains: list[dict] = []

    for domain, stats in domain_stats.items():
        score = (
            stats["high_entropy_count"] * 3
            + stats["long_label_count"] * 2
            + stats["suspicious_qtype_count"]
        )
        if score < MIN_SUSPICIOUS_QUERY_COUNT:
            continue

        # Rough exfil estimate: label bytes × 0.55 (base32/hex encoding ~45 % overhead)
        est_exfil_bytes = int(stats["total_label_bytes"] * 0.55)

        tunnel_domains.append(
            {
                "domain": domain,
                "query_count": stats["count"],
                "high_entropy_queries": stats["high_entropy_count"],
                "long_label_queries": stats["long_label_count"],
                "suspicious_qtype_queries": stats["suspicious_qtype_count"],
                "suspicion_score": score,
                "estimated_exfil_bytes": est_exfil_bytes,
                "estimated_exfil_kb": round(est_exfil_bytes / 1024, 2),
                "record_types": {
                    QTYPE_NAMES.get(k, str(k)): v
                    for k, v in stats["qtype_counter"].most_common(10)
                },
                "severity": "CRITICAL" if est_exfil_bytes > 100_000 else "HIGH",
            }
        )

    tunnel_domains.sort(key=lambda x: x["suspicion_score"], reverse=True)
    suspicious_queries.sort(key=lambda x: x["entropy"], reverse=True)

    return {
        "suspicious_queries": suspicious_queries[:500],
        "tunnel_domains": tunnel_domains,
        "total_suspicious": len(suspicious_queries),
    }
