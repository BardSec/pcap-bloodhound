"""
Data Exfiltration Profiler
──────────────────────────
Statistical outlier detection on flow volumes.  Any outbound flow exceeding
1 MB with a send/receive ratio greater than 5:1 is flagged with:

  • Bandwidth calculations
  • Flow duration
  • Visual bar data (send vs. receive byte counts for the frontend)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

EXFIL_THRESHOLD_BYTES = 1_000_000   # 1 MB minimum outbound
ASYMMETRY_RATIO = 5.0               # outbound / inbound > 5:1


def _is_private(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    return False


def analyze_exfiltration(packets: list) -> list[dict[str, Any]]:
    """
    Returns flows sorted by outbound byte count (largest first).
    Each entry contains bandwidth stats and chart-ready bar data.
    """
    # Normalize flow key: (internal_ip, external_ip, internal_port, external_port)
    # Values: {out: bytes, in: bytes, start: ts, end: ts, pkts: int}
    flows: dict[tuple, dict] = defaultdict(
        lambda: {"out": 0, "in": 0, "start": None, "end": None, "pkts": 0}
    )

    for pkt in packets:
        if "IP" not in pkt:
            continue

        ip = pkt["IP"]
        src, dst = ip.src, ip.dst

        if "TCP" in pkt:
            sport = pkt["TCP"].sport
            dport = pkt["TCP"].dport
        elif "UDP" in pkt:
            sport = pkt["UDP"].sport
            dport = pkt["UDP"].dport
        else:
            continue

        src_private = _is_private(src)
        dst_private = _is_private(dst)

        # Only care about internal ↔ external flows
        if src_private == dst_private:
            continue

        pkt_len = len(pkt)
        ts = float(pkt.time)

        if src_private:
            # Outbound packet (internal → external)
            flow_key = (src, dst, sport, dport)
            direction = "out"
        else:
            # Inbound packet (external → internal)
            flow_key = (dst, src, dport, sport)
            direction = "in"

        flow = flows[flow_key]
        flow[direction] += pkt_len
        flow["pkts"] += 1
        if flow["start"] is None:
            flow["start"] = ts
        flow["end"] = ts

    results: list[dict] = []

    for (internal_ip, external_ip, internal_port, external_port), data in flows.items():
        outbound = data["out"]
        inbound = data["in"]

        if outbound < EXFIL_THRESHOLD_BYTES:
            continue

        ratio = outbound / max(inbound, 1)
        if ratio < ASYMMETRY_RATIO:
            continue

        duration_sec = (
            data["end"] - data["start"]
            if data["end"] is not None and data["start"] is not None
            else 0.0
        )
        bandwidth_bps = outbound / max(duration_sec, 1.0)

        results.append(
            {
                "src_ip": internal_ip,
                "dst_ip": external_ip,
                "dst_port": external_port,
                "outbound_bytes": outbound,
                "inbound_bytes": inbound,
                "ratio": round(ratio, 2),
                "outbound_mb": round(outbound / 1_048_576, 2),
                "inbound_kb": round(inbound / 1024, 2),
                "duration_sec": round(duration_sec, 2),
                "bandwidth_kbps": round(bandwidth_bps / 1024, 2),
                "packet_count": data["pkts"],
                "severity": "CRITICAL" if outbound > 10_000_000 else "HIGH",
                # Chart data for the send/receive bar
                "bar_data": {
                    "labels": ["Outbound", "Inbound"],
                    "values": [outbound, inbound],
                },
            }
        )

    results.sort(key=lambda x: x["outbound_bytes"], reverse=True)
    return results
