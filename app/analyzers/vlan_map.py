"""VLAN traffic map — visualize inter-VLAN communication and flag unexpected cross-talk."""

from collections import defaultdict

from scapy.all import Dot1Q, IP, Ether


def analyze_vlan_traffic(packets):
    results = {
        "vlans": [],
        "cross_vlan_flows": [],
        "summary": {
            "vlan_count": 0,
            "cross_vlan_count": 0,
            "tagged_packet_count": 0,
        },
    }

    vlan_hosts = defaultdict(set)  # vlan_id -> set of IPs
    vlan_bytes = defaultdict(int)
    vlan_packets = defaultdict(int)
    cross_vlan = defaultdict(lambda: {"packets": 0, "bytes": 0, "hosts": set()})
    tagged_count = 0

    for pkt in packets:
        if not pkt.haslayer(Dot1Q):
            continue

        tagged_count += 1
        vlan_id = pkt[Dot1Q].vlan
        pkt_len = len(pkt)

        vlan_packets[vlan_id] += 1
        vlan_bytes[vlan_id] += pkt_len

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            vlan_hosts[vlan_id].add(src)

            # Check if destination is in a different VLAN
            dst_vlan = None
            for vid, hosts in vlan_hosts.items():
                if vid != vlan_id and dst in hosts:
                    dst_vlan = vid
                    break

            if dst_vlan is not None:
                key = (min(vlan_id, dst_vlan), max(vlan_id, dst_vlan))
                cross_vlan[key]["packets"] += 1
                cross_vlan[key]["bytes"] += pkt_len
                cross_vlan[key]["hosts"].add(src)
                cross_vlan[key]["hosts"].add(dst)

    # Build VLAN summary
    for vid in sorted(vlan_packets.keys()):
        results["vlans"].append({
            "vlan_id": vid,
            "host_count": len(vlan_hosts[vid]),
            "packet_count": vlan_packets[vid],
            "bytes": vlan_bytes[vid],
            "hosts": sorted(vlan_hosts[vid])[:20],
        })

    # Build cross-VLAN flows
    for (vlan_a, vlan_b), data in sorted(cross_vlan.items()):
        results["cross_vlan_flows"].append({
            "vlan_a": vlan_a,
            "vlan_b": vlan_b,
            "packets": data["packets"],
            "bytes": data["bytes"],
            "unique_hosts": len(data["hosts"]),
            "severity": "MEDIUM",
        })

    results["summary"]["vlan_count"] = len(vlan_packets)
    results["summary"]["cross_vlan_count"] = len(cross_vlan)
    results["summary"]["tagged_packet_count"] = tagged_count

    return results
