"""Multicast/broadcast storm detection — flag excessive broadcast traffic."""

from collections import defaultdict

from scapy.all import ARP, Ether, IP


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MULTICAST_PREFIX = "01:00:5e"
IPV6_MULTICAST_PREFIX = "33:33"

# Thresholds
BROADCAST_STORM_THRESHOLD = 100  # packets per second
BROADCAST_RATIO_THRESHOLD = 0.30  # 30% of total traffic


def analyze_broadcast_storms(packets):
    results = {
        "broadcast_sources": [],
        "multicast_sources": [],
        "storm_periods": [],
        "summary": {
            "total_packets": len(packets),
            "broadcast_packets": 0,
            "multicast_packets": 0,
            "broadcast_pct": 0,
            "peak_broadcast_pps": 0,
            "storm_detected": False,
        },
    }

    if not packets:
        return results

    bcast_by_source = defaultdict(int)
    mcast_by_source = defaultdict(int)
    bcast_by_second = defaultdict(int)
    bcast_total = 0
    mcast_total = 0

    for pkt in packets:
        if not pkt.haslayer(Ether):
            continue

        dst_mac = pkt[Ether].dst.lower()
        src_mac = pkt[Ether].src.lower()
        ts = int(float(pkt.time))
        src_ip = pkt[IP].src if pkt.haslayer(IP) else src_mac

        if dst_mac == BROADCAST_MAC:
            bcast_total += 1
            bcast_by_source[src_ip] += 1
            bcast_by_second[ts] += 1
        elif dst_mac.startswith(MULTICAST_PREFIX) or dst_mac.startswith(IPV6_MULTICAST_PREFIX):
            mcast_total += 1
            mcast_by_source[src_ip] += 1

    # Top broadcast sources
    results["broadcast_sources"] = sorted(
        [{"source": src, "packet_count": cnt,
          "severity": "HIGH" if cnt > 500 else "MEDIUM" if cnt > 100 else "LOW"}
         for src, cnt in bcast_by_source.items()],
        key=lambda x: x["packet_count"],
        reverse=True,
    )[:20]

    # Top multicast sources
    results["multicast_sources"] = sorted(
        [{"source": src, "packet_count": cnt,
          "severity": "MEDIUM" if cnt > 200 else "LOW"}
         for src, cnt in mcast_by_source.items()],
        key=lambda x: x["packet_count"],
        reverse=True,
    )[:20]

    # Detect storm periods (seconds where broadcast > threshold)
    for ts, cnt in sorted(bcast_by_second.items()):
        if cnt >= BROADCAST_STORM_THRESHOLD:
            results["storm_periods"].append({
                "timestamp": ts,
                "packets_per_second": cnt,
                "severity": "CRITICAL" if cnt > 500 else "HIGH",
            })

    peak_pps = max(bcast_by_second.values()) if bcast_by_second else 0
    total = len(packets)
    bcast_pct = round((bcast_total / total) * 100, 1) if total > 0 else 0

    results["summary"] = {
        "total_packets": total,
        "broadcast_packets": bcast_total,
        "multicast_packets": mcast_total,
        "broadcast_pct": bcast_pct,
        "peak_broadcast_pps": peak_pps,
        "storm_detected": peak_pps >= BROADCAST_STORM_THRESHOLD or bcast_pct > BROADCAST_RATIO_THRESHOLD * 100,
    }

    return results
