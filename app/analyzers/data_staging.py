"""Data staging detection — internal-to-internal large transfers followed by external exfil."""

from collections import defaultdict

from scapy.all import IP, TCP

# Thresholds
INTERNAL_TRANSFER_MIN_BYTES = 5 * 1024 * 1024  # 5 MB internal transfer
EXTERNAL_TRANSFER_MIN_BYTES = 1 * 1024 * 1024   # 1 MB external transfer
TIME_WINDOW_SEC = 600  # 10 minutes between staging and exfil


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def analyze_data_staging(packets):
    results = {
        "staging_flows": [],
        "exfil_flows": [],
        "staging_exfil_pairs": [],
        "summary": {
            "internal_large_transfers": 0,
            "external_large_transfers": 0,
            "staging_exfil_patterns": 0,
        },
    }

    # Track flows: (src, dst) -> {bytes_sent, bytes_recv, first_seen, last_seen}
    internal_flows = defaultdict(lambda: {"bytes": 0, "first_seen": None, "last_seen": None, "packets": 0})
    external_flows = defaultdict(lambda: {"bytes": 0, "first_seen": None, "last_seen": None, "packets": 0, "dst_port": 0})

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        ts = float(pkt.time)
        pkt_len = len(pkt)

        src_priv = _is_private(src)
        dst_priv = _is_private(dst)

        if src_priv and dst_priv and src != dst:
            # Internal-to-internal
            key = (src, dst)
            flow = internal_flows[key]
            flow["bytes"] += pkt_len
            flow["packets"] += 1
            if flow["first_seen"] is None:
                flow["first_seen"] = ts
            flow["last_seen"] = ts

        elif src_priv and not dst_priv:
            # Internal-to-external (potential exfil)
            key = (src, dst)
            flow = external_flows[key]
            flow["bytes"] += pkt_len
            flow["packets"] += 1
            if flow["first_seen"] is None:
                flow["first_seen"] = ts
            flow["last_seen"] = ts
            if pkt.haslayer(TCP):
                flow["dst_port"] = pkt[TCP].dport

    # Find large internal transfers (staging)
    staging = []
    for (src, dst), data in internal_flows.items():
        if data["bytes"] >= INTERNAL_TRANSFER_MIN_BYTES:
            staging.append({
                "src_ip": src,
                "dst_ip": dst,
                "bytes": data["bytes"],
                "mb": round(data["bytes"] / (1024 * 1024), 2),
                "packets": data["packets"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_sec": round(data["last_seen"] - data["first_seen"], 1),
                "severity": "MEDIUM",
            })

    # Find large external transfers (exfil)
    exfil = []
    for (src, dst), data in external_flows.items():
        if data["bytes"] >= EXTERNAL_TRANSFER_MIN_BYTES:
            exfil.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": data["dst_port"],
                "bytes": data["bytes"],
                "mb": round(data["bytes"] / (1024 * 1024), 2),
                "packets": data["packets"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "duration_sec": round(data["last_seen"] - data["first_seen"], 1),
                "severity": "HIGH",
            })

    # Correlate: find staging events followed by exfil from the same host
    pairs = []
    for s in staging:
        staging_host = s["dst_ip"]  # The host that received the staged data
        for e in exfil:
            if e["src_ip"] == staging_host:
                # Check if exfil started after staging (within time window)
                time_gap = e["first_seen"] - s["last_seen"]
                if -60 <= time_gap <= TIME_WINDOW_SEC:
                    pairs.append({
                        "staging_src": s["src_ip"],
                        "staging_dst": staging_host,
                        "staging_mb": s["mb"],
                        "exfil_dst": e["dst_ip"],
                        "exfil_port": e["dst_port"],
                        "exfil_mb": e["mb"],
                        "time_gap_sec": round(time_gap, 1),
                        "severity": "CRITICAL",
                    })

    results["staging_flows"] = sorted(staging, key=lambda x: -x["bytes"])
    results["exfil_flows"] = sorted(exfil, key=lambda x: -x["bytes"])
    results["staging_exfil_pairs"] = pairs

    results["summary"] = {
        "internal_large_transfers": len(staging),
        "external_large_transfers": len(exfil),
        "staging_exfil_patterns": len(pairs),
    }

    return results
