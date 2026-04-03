"""
DNS Health Analyzer
────────────────────
Tracks DNS query/response pairs to surface network filtering and resolver
problems:

  • NXDOMAIN (rcode 3) — domain doesn't exist *or* is blocked at DNS level
    (Cisco Umbrella, OpenDNS, Cloudflare Gateway all return NXDOMAIN for
    policy-blocked domains)
  • SERVFAIL (rcode 2) — upstream resolver is broken or unreachable
  • REFUSED  (rcode 5) — policy rejection by the resolver
  • Query timeouts     — DNS queries that never received a response
  • Slow responses     — RTT > 500 ms (indicates resolver latency)
  • Top failing domains — aggregated view for quick triage
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

QTYPE_NAMES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
    255: "ANY", 252: "AXFR", 10: "NULL",
}

RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

RCODE_SEVERITY: dict[int, str] = {
    2: "HIGH",    # SERVFAIL   — resolver or upstream broken
    3: "MEDIUM",  # NXDOMAIN   — blocked or mistyped domain
    5: "HIGH",    # REFUSED    — policy block at resolver level
    1: "LOW",
    4: "LOW",
}

SLOW_MS = 500     # ms — queries slower than this are flagged


def analyze_dns_health(packets: list) -> dict[str, Any]:
    """
    Returns failure details, per-domain aggregation, timeouts, and slow queries.
    """
    # pending queries: (qname, qtype, txid, client_ip) → {timestamp, resolver_ip}
    pending: dict[tuple, dict] = {}

    failures: list[dict] = []
    slow_queries: list[dict] = []

    # domain → Counter of rcode_names
    domain_fail_counter: dict[str, Counter] = defaultdict(Counter)

    for pkt in packets:
        if "DNS" not in pkt or "IP" not in pkt:
            continue

        dns = pkt["DNS"]
        ip = pkt["IP"]
        ts = float(pkt.time)

        if not dns.qd:
            continue

        try:
            qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            continue

        qtype: int = dns.qd.qtype
        txid: int = dns.id

        # ── Query ────────────────────────────────────────────────────────────
        if dns.qr == 0:
            key = (qname, qtype, txid, ip.src)
            pending[key] = {"ts": ts, "resolver_ip": ip.dst, "qname": qname, "qtype": qtype}

        # ── Response ─────────────────────────────────────────────────────────
        elif dns.qr == 1:
            rcode: int = dns.rcode
            client_ip = ip.dst  # response flows server → client

            key = (qname, qtype, txid, client_ip)
            query_info = pending.pop(key, None)
            rtt_ms = round((ts - query_info["ts"]) * 1000, 1) if query_info else None

            if rcode != 0:
                rcode_name = RCODE_NAMES.get(rcode, f"RCODE-{rcode}")
                domain_fail_counter[qname][rcode_name] += 1
                failures.append(
                    {
                        "qname": qname,
                        "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                        "rcode": rcode,
                        "rcode_name": rcode_name,
                        "client_ip": client_ip,
                        "resolver_ip": ip.src,
                        "rtt_ms": rtt_ms,
                        "timestamp": ts,
                        "severity": RCODE_SEVERITY.get(rcode, "LOW"),
                    }
                )
            elif rtt_ms is not None and rtt_ms > SLOW_MS:
                slow_queries.append(
                    {
                        "qname": qname,
                        "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                        "rtt_ms": rtt_ms,
                        "client_ip": client_ip,
                        "resolver_ip": ip.src,
                        "timestamp": ts,
                    }
                )

    # Remaining pending = timed-out queries
    timeouts = [
        {
            "qname": v["qname"],
            "qtype": QTYPE_NAMES.get(v["qtype"], str(v["qtype"])),
            "client_ip": k[3],
            "resolver_ip": v["resolver_ip"],
            "timestamp": v["ts"],
            "severity": "HIGH",
        }
        for k, v in pending.items()
    ]

    # ── Per-domain failure summary ───────────────────────────────────────────
    top_failing = sorted(
        [
            {
                "domain": domain,
                "failures": dict(counter),
                "total": sum(counter.values()),
            }
            for domain, counter in domain_fail_counter.items()
        ],
        key=lambda x: -x["total"],
    )[:30]

    nxdomain = sum(1 for f in failures if f["rcode"] == 3)
    servfail  = sum(1 for f in failures if f["rcode"] == 2)
    refused   = sum(1 for f in failures if f["rcode"] == 5)

    return {
        "failures": failures[:500],
        "timeouts": timeouts[:100],
        "slow_queries": sorted(slow_queries, key=lambda x: -x["rtt_ms"])[:50],
        "top_failing_domains": top_failing,
        "summary": {
            "total_failures": len(failures),
            "nxdomain": nxdomain,
            "servfail": servfail,
            "refused": refused,
            "timeouts": len(timeouts),
            "slow": len(slow_queries),
        },
    }
