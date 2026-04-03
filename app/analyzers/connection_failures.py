"""
Connection Failure Detector
────────────────────────────
Detects network filtering/blocking evidence in a PCAP:

  1. ICMP Destination Unreachable  — router/firewall explicitly rejected traffic
     Code 13 ("administratively prohibited") is the classic firewall ACL hit.

  2. TCP RST responses             — server or firewall actively terminated connections
     Aggregated by destination so you can see which hosts/ports are being blocked.

  3. Silently dropped SYNs         — outbound SYNs with no SYN-ACK or RST response
     (firewall drop-without-reject policy).  Aggregated by destination.
"""
from __future__ import annotations

import struct
from collections import defaultdict
from typing import Any


ICMP_UNREACH_CODES: dict[int, str] = {
    0:  "Network Unreachable",
    1:  "Host Unreachable",
    2:  "Protocol Unreachable",
    3:  "Port Unreachable",
    6:  "Destination Network Unknown",
    7:  "Destination Host Unknown",
    9:  "Destination Network Administratively Prohibited",
    10: "Destination Host Administratively Prohibited",
    13: "Communication Administratively Prohibited",
}

# Codes that almost certainly indicate a firewall/ACL rule
FIREWALL_CODES = {9, 10, 13}


def _is_private(ip: str) -> bool:
    try:
        p = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    return (
        p[0] == 10
        or (p[0] == 172 and 16 <= p[1] <= 31)
        or (p[0] == 192 and p[1] == 168)
        or p[0] == 127
    )


def analyze_connection_failures(packets: list) -> dict[str, Any]:
    """
    Returns:
        icmp_unreachables  – individual ICMP type-3 messages
        tcp_resets         – RST events aggregated by dst_ip:port
        silently_dropped   – SYNs with no response, aggregated by dst_ip:port
        summary            – counts
    """
    icmp_unreachables: list[dict] = []

    # (src_ip, src_port, dst_ip, dst_port) -> first_seen_ts
    syn_map: dict[tuple, float] = {}
    # set of stream keys that received a SYN-ACK or RST
    responded: set[tuple] = set()
    # RST events: dst_ip:port counter
    rst_agg: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "clients": set()})

    for pkt in packets:
        if "IP" not in pkt:
            continue

        ip = pkt["IP"]
        ts = float(pkt.time)

        # ── ICMP Destination Unreachable ──────────────────────────────────────
        if "ICMP" in pkt:
            icmp = pkt["ICMP"]
            if icmp.type == 3:
                orig_dst_ip = "?"
                orig_dst_port: str | int = "?"
                try:
                    inner = icmp.payload
                    if "IP" in inner:
                        orig_dst_ip = inner["IP"].dst
                        if "TCP" in inner:
                            orig_dst_port = inner["TCP"].dport
                        elif "UDP" in inner:
                            orig_dst_port = inner["UDP"].dport
                except Exception:
                    pass

                icmp_unreachables.append(
                    {
                        "reporter_ip": ip.src,
                        "orig_src_ip": ip.dst,
                        "orig_dst_ip": orig_dst_ip,
                        "orig_dst_port": orig_dst_port,
                        "icmp_code": icmp.code,
                        "reason": ICMP_UNREACH_CODES.get(icmp.code, f"Code {icmp.code}"),
                        "is_firewall_block": icmp.code in FIREWALL_CODES,
                        "timestamp": ts,
                        "severity": "HIGH" if icmp.code in FIREWALL_CODES else "MEDIUM",
                    }
                )
            continue  # ICMP packets have no TCP layer

        # ── TCP flag tracking ────────────────────────────────────────────────
        if "TCP" not in pkt:
            continue

        tcp = pkt["TCP"]
        flags = int(tcp.flags)
        src_ip, dst_ip = ip.src, ip.dst
        sport, dport = tcp.sport, tcp.dport

        is_syn     = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN but not ACK
        is_syn_ack = bool(flags & 0x02) and bool(flags & 0x10)
        is_rst     = bool(flags & 0x04)

        key = (src_ip, sport, dst_ip, dport)
        rev = (dst_ip, dport, src_ip, sport)

        if is_syn:
            # Only track outbound SYNs (private → public)
            if _is_private(src_ip) and not _is_private(dst_ip):
                if key not in syn_map:
                    syn_map[key] = ts

        elif is_syn_ack:
            responded.add(rev)

        elif is_rst:
            responded.add(key)
            responded.add(rev)
            # Record RST aggregated by the connection target
            # RST can come from server (src=server) or from a firewall (src=fw)
            target = (dst_ip, dport) if _is_private(src_ip) else (src_ip, sport)
            rst_agg[target]["count"] += 1
            rst_agg[target]["clients"].add(src_ip if _is_private(src_ip) else dst_ip)

    # ── Build silently-dropped aggregation ───────────────────────────────────
    drop_agg: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "clients": set()})
    for (src, sport, dst, dport), ts in syn_map.items():
        key = (src, sport, dst, dport)
        if key not in responded:
            drop_agg[(dst, dport)]["count"] += 1
            drop_agg[(dst, dport)]["clients"].add(src)

    # ── Serialise aggregations ────────────────────────────────────────────────
    tcp_resets = sorted(
        [
            {
                "dst_ip": k[0],
                "dst_port": k[1],
                "reset_count": v["count"],
                "affected_clients": sorted(v["clients"])[:10],
                "severity": "HIGH" if v["count"] > 5 else "MEDIUM",
            }
            for k, v in rst_agg.items()
        ],
        key=lambda x: -x["reset_count"],
    )[:50]

    silently_dropped = sorted(
        [
            {
                "dst_ip": k[0],
                "dst_port": k[1],
                "drop_count": v["count"],
                "affected_clients": sorted(v["clients"])[:10],
                "note": "SYN sent, no SYN-ACK or RST received — firewall likely silently dropping",
                "severity": "MEDIUM",
            }
            for k, v in drop_agg.items()
        ],
        key=lambda x: -x["drop_count"],
    )[:50]

    return {
        "icmp_unreachables": icmp_unreachables[:200],
        "tcp_resets": tcp_resets,
        "silently_dropped": silently_dropped,
        "summary": {
            "icmp_count": len(icmp_unreachables),
            "firewall_icmp_count": sum(1 for i in icmp_unreachables if i["is_firewall_block"]),
            "rst_destination_count": len(tcp_resets),
            "dropped_destination_count": len(silently_dropped),
        },
    }
