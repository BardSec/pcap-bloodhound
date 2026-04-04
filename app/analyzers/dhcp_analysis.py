"""DHCP lease analysis — parse DHCP traffic for lease activity and anomalies."""

from collections import defaultdict

from scapy.all import BOOTP, DHCP, IP, UDP, Ether


DHCP_MESSAGE_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


def _get_dhcp_option(options, key):
    """Extract a DHCP option value by name."""
    for opt in options:
        if isinstance(opt, tuple) and opt[0] == key:
            return opt[1]
    return None


def analyze_dhcp(packets):
    results = {
        "leases": [],
        "discovers_without_offer": [],
        "declines": [],
        "naks": [],
        "dhcp_servers": [],
        "summary": {
            "total_dhcp_packets": 0,
            "discover_count": 0,
            "offer_count": 0,
            "request_count": 0,
            "ack_count": 0,
            "decline_count": 0,
            "nak_count": 0,
            "unique_servers": 0,
        },
    }

    dhcp_servers = defaultdict(int)
    discovers = {}  # xid -> {client_mac, timestamp}
    offers = {}     # xid -> {server, offered_ip, timestamp}
    leases = {}     # client_mac -> latest lease info
    msg_counts = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(DHCP):
            continue

        results["summary"]["total_dhcp_packets"] += 1
        ts = float(pkt.time)

        options = pkt[DHCP].options
        msg_type_val = _get_dhcp_option(options, "message-type")
        if msg_type_val is None:
            continue

        msg_type = DHCP_MESSAGE_TYPES.get(msg_type_val, f"UNKNOWN({msg_type_val})")
        msg_counts[msg_type] += 1

        client_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
        xid = pkt[BOOTP].xid if pkt.haslayer(BOOTP) else 0

        if msg_type == "DISCOVER":
            discovers[xid] = {
                "client_mac": client_mac,
                "timestamp": ts,
                "hostname": _get_dhcp_option(options, "hostname"),
            }

        elif msg_type == "OFFER":
            server_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            offered_ip = pkt[BOOTP].yiaddr if pkt.haslayer(BOOTP) else "unknown"
            dhcp_servers[server_ip] += 1
            offers[xid] = {
                "server_ip": server_ip,
                "offered_ip": offered_ip,
                "timestamp": ts,
            }

        elif msg_type == "ACK":
            server_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            assigned_ip = pkt[BOOTP].yiaddr if pkt.haslayer(BOOTP) else "unknown"
            lease_time = _get_dhcp_option(options, "lease_time")
            dhcp_servers[server_ip] += 1

            lease = {
                "client_mac": client_mac,
                "assigned_ip": assigned_ip,
                "server_ip": server_ip,
                "lease_time": lease_time,
                "hostname": _get_dhcp_option(options, "hostname"),
                "domain": _get_dhcp_option(options, "domain"),
                "timestamp": ts,
            }
            leases[client_mac] = lease

        elif msg_type == "DECLINE":
            results["declines"].append({
                "client_mac": client_mac,
                "timestamp": ts,
                "severity": "MEDIUM",
            })

        elif msg_type == "NAK":
            server_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            results["naks"].append({
                "client_mac": client_mac,
                "server_ip": server_ip,
                "timestamp": ts,
                "severity": "MEDIUM",
            })

    # Find discovers without offers
    for xid, disc in discovers.items():
        if xid not in offers:
            results["discovers_without_offer"].append({
                "client_mac": disc["client_mac"],
                "hostname": disc.get("hostname"),
                "timestamp": disc["timestamp"],
                "severity": "LOW",
            })

    results["leases"] = sorted(leases.values(), key=lambda x: x["timestamp"], reverse=True)

    results["dhcp_servers"] = [
        {"server_ip": ip, "response_count": count,
         "severity": "HIGH" if len(dhcp_servers) > 1 else "INFO"}
        for ip, count in sorted(dhcp_servers.items(), key=lambda x: -x[1])
    ]

    results["summary"].update({
        "discover_count": msg_counts.get("DISCOVER", 0),
        "offer_count": msg_counts.get("OFFER", 0),
        "request_count": msg_counts.get("REQUEST", 0),
        "ack_count": msg_counts.get("ACK", 0),
        "decline_count": msg_counts.get("DECLINE", 0),
        "nak_count": msg_counts.get("NAK", 0),
        "unique_servers": len(dhcp_servers),
    })

    return results
