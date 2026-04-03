"""
Traffic Timeline Analyzer
──────────────────────────
Produces the data behind three classic Wireshark views:

  • IO Graph       — per-bin packet/byte counts across the capture window,
                     with spike and gap detection
  • Conversations  — all unique IP flows aggregated by bytes (bidirectional),
                     ranked so you can see which flows dominate bandwidth
  • Endpoints      — per-IP traffic totals with sent/received split

Bin size is chosen automatically based on capture duration:
    < 30 s  →  0.5 s bins
    < 5 min →  1 s bins
    < 30 min→  10 s bins
    ≥ 30 min→  60 s bins
    (capped at 1 000 bins for frontend performance)
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _choose_bin_s(duration: float) -> float:
    if duration <= 0:
        return 1.0
    if duration < 30:
        return 0.5
    if duration < 300:
        return 1.0
    if duration < 1800:
        return 10.0
    return 60.0


def analyze_traffic_timeline(packets: list) -> dict[str, Any]:
    if not packets:
        return {
            "timeline": [],
            "bin_seconds": 1.0,
            "spikes": [],
            "gaps": [],
            "top_conversations": [],
            "top_endpoints": [],
            "summary": {
                "capture_duration_s": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "avg_pps": 0,
                "peak_pps": 0,
                "peak_pps_at": 0,
                "spike_count": 0,
                "gap_count": 0,
                "conversation_count": 0,
            },
        }

    # ── Time range ────────────────────────────────────────────────────────────
    times = [float(p.time) for p in packets]
    t_start = min(times)
    t_end   = max(times)
    duration = max(t_end - t_start, 0.001)

    bin_s = _choose_bin_s(duration)

    # Cap at 1 000 bins
    n_bins = int(duration / bin_s) + 1
    if n_bins > 1000:
        bin_s = duration / 1000.0
        n_bins = 1001

    bins_pkts  = [0] * n_bins
    bins_bytes = [0] * n_bins

    # conversation key → stats (bidirectional)
    convos: dict[tuple, dict] = {}

    # endpoint IP → stats
    endpoints: dict[str, dict] = defaultdict(
        lambda: {"bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0}
    )

    for pkt in packets:
        ts  = float(pkt.time)
        pkt_len = len(pkt)

        idx = min(int((ts - t_start) / bin_s), n_bins - 1)
        bins_pkts[idx]  += 1
        bins_bytes[idx] += pkt_len

        if "IP" not in pkt:
            continue

        ip   = pkt["IP"]
        src  = ip.src
        dst  = ip.dst

        # ── Endpoint stats ────────────────────────────────────────────────────
        endpoints[src]["bytes_sent"] += pkt_len
        endpoints[src]["pkts_sent"]  += 1
        endpoints[dst]["bytes_recv"] += pkt_len
        endpoints[dst]["pkts_recv"]  += 1

        # ── Conversation key (normalised so A < B) ────────────────────────────
        if "TCP" in pkt:
            proto = "TCP"
            sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
        elif "UDP" in pkt:
            proto = "UDP"
            sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
        elif "ICMP" in pkt:
            proto = "ICMP"
            sport, dport = 0, 0
        else:
            proto = ip.proto if hasattr(ip, "proto") else "?"
            sport, dport = 0, 0

        if src < dst or (src == dst and sport <= dport):
            key = (src, dst, sport, dport, proto)
        else:
            key = (dst, src, dport, sport, proto)

        if key not in convos:
            convos[key] = {
                "ip_a": key[0], "ip_b": key[1],
                "port_a": key[2], "port_b": key[3],
                "proto": proto,
                "packets": 0, "bytes": 0,
                "first_ts": ts, "last_ts": ts,
            }
        c = convos[key]
        c["packets"] += 1
        c["bytes"]   += pkt_len
        if ts < c["first_ts"]:
            c["first_ts"] = ts
        if ts > c["last_ts"]:
            c["last_ts"] = ts

    # ── Build timeline array ─────────────────────────────────────────────────
    timeline = [
        {
            "t":    round(i * bin_s, 3),
            "pkts": bins_pkts[i],
            "bytes": bins_bytes[i],
            "pps":  round(bins_pkts[i]  / bin_s, 2),
            "bps":  round(bins_bytes[i] / bin_s, 2),
        }
        for i in range(n_bins)
    ]

    # ── Spike detection (bin pps > 3× average, minimum threshold 5 pkts) ─────
    total_pkts = sum(bins_pkts)
    avg_pkts_per_bin = total_pkts / n_bins if n_bins > 0 else 0
    spike_threshold  = max(avg_pkts_per_bin * 3, avg_pkts_per_bin + 5, 5)

    spikes = [
        {
            "t":     round(i * bin_s, 3),
            "pkts":  bins_pkts[i],
            "pps":   round(bins_pkts[i] / bin_s, 1),
            "ratio": round(bins_pkts[i] / avg_pkts_per_bin, 1) if avg_pkts_per_bin > 0 else 0,
        }
        for i in range(n_bins)
        if bins_pkts[i] >= spike_threshold and avg_pkts_per_bin > 0
    ]

    # ── Gap detection (consecutive zero-traffic bins surrounded by traffic) ───
    gaps: list[dict] = []
    gap_start: int | None = None
    for i, count in enumerate(bins_pkts):
        in_interior = 0 < i < n_bins - 1
        if count == 0 and in_interior:
            if gap_start is None:
                gap_start = i
        else:
            if gap_start is not None:
                gaps.append({
                    "start_t":   round(gap_start * bin_s, 3),
                    "end_t":     round(i * bin_s, 3),
                    "duration_s": round((i - gap_start) * bin_s, 2),
                })
                gap_start = None

    # ── Top conversations ─────────────────────────────────────────────────────
    top_convos = sorted(convos.values(), key=lambda x: -x["bytes"])[:50]
    for c in top_convos:
        c["duration_s"] = round(c["last_ts"] - c["first_ts"], 2)
        c["start_t"]    = round(c["first_ts"] - t_start, 3)
        del c["first_ts"]
        del c["last_ts"]

    # ── Top endpoints ─────────────────────────────────────────────────────────
    top_endpoints = sorted(
        [
            {
                "ip": ip,
                "bytes_total": v["bytes_sent"] + v["bytes_recv"],
                "bytes_sent":  v["bytes_sent"],
                "bytes_recv":  v["bytes_recv"],
                "pkts_total":  v["pkts_sent"] + v["pkts_recv"],
            }
            for ip, v in endpoints.items()
        ],
        key=lambda x: -x["bytes_total"],
    )[:30]

    # ── Summary ───────────────────────────────────────────────────────────────
    avg_pps  = round(total_pkts / duration, 1) if duration > 0 else 0
    peak_bin = bins_pkts.index(max(bins_pkts)) if bins_pkts else 0
    peak_pps = round(max(bins_pkts) / bin_s, 1)

    return {
        "timeline":          timeline,
        "bin_seconds":       round(bin_s, 3),
        "spikes":            spikes[:20],
        "gaps":              gaps[:20],
        "top_conversations": top_convos,
        "top_endpoints":     top_endpoints,
        "summary": {
            "capture_duration_s": round(duration, 2),
            "total_packets":      total_pkts,
            "total_bytes":        sum(bins_bytes),
            "avg_pps":            avg_pps,
            "peak_pps":           peak_pps,
            "peak_pps_at":        round(peak_bin * bin_s, 2),
            "spike_count":        len(spikes),
            "gap_count":          len(gaps),
            "conversation_count": len(convos),
        },
    }
