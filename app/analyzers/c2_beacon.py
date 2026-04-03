"""
C2 Beaconing Detector
─────────────────────
Calculates the coefficient of variation (CV = σ/μ) on inter-arrival times
for every outbound connection pair.  A CV < 0.15 with a meaningful number
of connections indicates suspiciously regular timing — the heartbeat pattern
produced by Cobalt Strike, Sliver, and similar implants.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np


# ── Private address space (RFC 1918 + loopback + link-local) ────────────────

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
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False


# ── Minimum samples required to calculate a meaningful CV ───────────────────
MIN_SAMPLES = 8
# Ignore extremely short mean intervals (< 5 s) — normal keep-alives, HTTP
MIN_MEAN_IAT_SEC = 5.0
# CV threshold below which we flag the connection as suspicious
CV_THRESHOLD = 0.15


def analyze_c2_beaconing(packets: list) -> list[dict[str, Any]]:
    """Return a list of suspicious flows sorted by CV (most regular first)."""

    # flow_key -> sorted list of packet timestamps
    flows: dict[tuple, list[float]] = defaultdict(list)

    for pkt in packets:
        if "IP" not in pkt:
            continue

        src: str = pkt["IP"].src
        dst: str = pkt["IP"].dst

        # Only outbound: private → public
        if not _is_private(src) or _is_private(dst):
            continue

        if "TCP" in pkt:
            port = pkt["TCP"].dport
            proto = "TCP"
        elif "UDP" in pkt:
            port = pkt["UDP"].dport
            proto = "UDP"
        else:
            continue

        flows[(src, dst, port, proto)].append(float(pkt.time))

    results: list[dict] = []

    for (src, dst, port, proto), timestamps in flows.items():
        if len(timestamps) < MIN_SAMPLES:
            continue

        timestamps.sort()
        iats = np.diff(timestamps)  # inter-arrival times in seconds

        if len(iats) < MIN_SAMPLES - 1:
            continue

        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))

        if mean_iat < MIN_MEAN_IAT_SEC:
            continue  # ignore high-frequency normal traffic

        cv = std_iat / mean_iat

        if cv >= CV_THRESHOLD:
            continue

        # Build time-series relative to first packet (for the sparkline chart)
        t0 = timestamps[0]
        rel_timestamps = [round(t - t0, 2) for t in timestamps[:200]]
        interval_series = [round(float(x), 3) for x in iats[:200].tolist()]

        results.append(
            {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "protocol": proto,
                "cv": round(cv, 4),
                "mean_interval_sec": round(mean_iat, 2),
                "std_interval_sec": round(std_iat, 4),
                "connection_count": len(timestamps),
                "severity": "CRITICAL" if cv < 0.05 else "HIGH",
                # Chart data
                "interval_series": interval_series,
                "rel_timestamps": rel_timestamps,
                # Human-readable beacon period
                "beacon_period_display": _format_period(mean_iat),
            }
        )

    results.sort(key=lambda x: x["cv"])
    return results


def _format_period(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"
