"""Lateral movement detection — flag SMB/WinRM/RDP between internal hosts."""

from collections import defaultdict

from scapy.all import IP, TCP

# Ports associated with lateral movement techniques
LATERAL_PORTS = {
    445: "SMB",
    139: "NetBIOS/SMB",
    135: "MS-RPC/DCOM",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    22: "SSH",
    23: "Telnet",
}

# Scan threshold — one source hitting this many unique internal destinations
SCAN_THRESHOLD = 5


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def analyze_lateral_movement(packets):
    results = {
        "lateral_connections": [],
        "scan_patterns": [],
        "summary": {
            "total_lateral_flows": 0,
            "unique_sources": 0,
            "scan_sources": 0,
            "protocols_seen": [],
        },
    }

    # Track internal-to-internal connections on lateral movement ports
    # Key: (src, dst, dport) -> connection info
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None})
    # Track per-source destinations for scan detection
    source_targets = defaultdict(lambda: defaultdict(set))  # src -> port -> set(dst)

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        ts = float(pkt.time)

        if dport not in LATERAL_PORTS:
            continue
        if not _is_private(src) or not _is_private(dst):
            continue
        if src == dst:
            continue

        flow_key = (src, dst, dport)
        flow = flows[flow_key]
        flow["packets"] += 1
        flow["bytes"] += len(pkt)
        if flow["first_seen"] is None:
            flow["first_seen"] = ts
        flow["last_seen"] = ts

        source_targets[src][dport].add(dst)

    # Build lateral connections list
    protocols_seen = set()
    for (src, dst, dport), data in sorted(flows.items(), key=lambda x: -x[1]["packets"]):
        protocol = LATERAL_PORTS[dport]
        protocols_seen.add(protocol)

        # Determine severity based on protocol
        if dport in (5985, 5986):  # WinRM
            severity = "CRITICAL"
        elif dport in (445, 135):  # SMB/DCOM
            severity = "HIGH"
        elif dport == 3389:  # RDP
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        results["lateral_connections"].append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "protocol": protocol,
            "packets": data["packets"],
            "bytes": data["bytes"],
            "duration_sec": round(data["last_seen"] - data["first_seen"], 1) if data["first_seen"] and data["last_seen"] else 0,
            "timestamp": data["first_seen"],
            "severity": severity,
        })

    # Detect scan patterns (one source hitting many internal destinations)
    for src, port_targets in source_targets.items():
        for dport, targets in port_targets.items():
            if len(targets) >= SCAN_THRESHOLD:
                results["scan_patterns"].append({
                    "src_ip": src,
                    "dst_port": dport,
                    "protocol": LATERAL_PORTS[dport],
                    "unique_targets": len(targets),
                    "targets": sorted(targets)[:20],
                    "severity": "CRITICAL",
                })

    results["summary"] = {
        "total_lateral_flows": len(flows),
        "unique_sources": len(source_targets),
        "scan_sources": len(results["scan_patterns"]),
        "protocols_seen": sorted(protocols_seen),
    }

    return results
