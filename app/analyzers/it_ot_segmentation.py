"""IT/OT segmentation analysis — detect boundary crossings between IT and OT zones."""

import logging
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, UDP

logger = logging.getLogger(__name__)

# ICS/OT ports
OT_PORTS = {502, 20000, 4840, 44818, 47808, 2404, 102}

OT_PORT_NAMES = {
    502: "Modbus",
    20000: "DNP3",
    4840: "OPC-UA",
    44818: "EtherNet/IP",
    47808: "BACnet",
    2404: "IEC-104",
    102: "IEC-61850",
}

# Common IT service ports
IT_PORTS = {80, 443, 25, 587, 53, 143, 993, 110, 995, 3389, 22, 8080, 8443}

IT_PORT_NAMES = {
    80: "HTTP",
    443: "HTTPS",
    25: "SMTP",
    587: "SMTP-Submission",
    53: "DNS",
    143: "IMAP",
    993: "IMAPS",
    110: "POP3",
    995: "POP3S",
    3389: "RDP",
    22: "SSH",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def _is_rfc1918(ip: str) -> bool:
    """Return True if the IP address is in RFC 1918 private space."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
    )


def analyze_it_ot_segmentation(packets: list) -> dict[str, Any]:
    """Classify hosts as IT or OT and detect boundary crossings."""

    # --- Pass 1: classify hosts ---
    it_hosts: set[str] = set()
    ot_hosts: set[str] = set()

    # Track per-host details
    host_packets: dict[str, int] = defaultdict(int)
    host_it_protocols: dict[str, set] = defaultdict(set)
    host_ot_protocols: dict[str, set] = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        sport = None
        dport = None
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        if sport is None:
            continue

        host_packets[src] += 1
        host_packets[dst] += 1

        # Classify by destination port (client initiating to a service)
        if dport in OT_PORTS:
            ot_hosts.add(dst)
            ot_hosts.add(src)
            proto = OT_PORT_NAMES.get(dport, str(dport))
            host_ot_protocols[dst].add(proto)
            host_ot_protocols[src].add(proto)

        if sport in OT_PORTS:
            ot_hosts.add(src)
            ot_hosts.add(dst)
            proto = OT_PORT_NAMES.get(sport, str(sport))
            host_ot_protocols[src].add(proto)
            host_ot_protocols[dst].add(proto)

        if dport in IT_PORTS:
            it_hosts.add(dst)
            it_hosts.add(src)
            proto = IT_PORT_NAMES.get(dport, str(dport))
            host_it_protocols[dst].add(proto)
            host_it_protocols[src].add(proto)

        if sport in IT_PORTS:
            it_hosts.add(src)
            it_hosts.add(dst)
            proto = IT_PORT_NAMES.get(sport, str(sport))
            host_it_protocols[src].add(proto)
            host_it_protocols[dst].add(proto)

    dual_role = it_hosts & ot_hosts
    it_only = it_hosts - ot_hosts
    ot_only = ot_hosts - it_hosts

    # --- Pass 2: boundary crossings and OT internet access ---
    boundary_flows: dict[tuple, dict] = {}
    ot_internet_flows: dict[tuple, dict] = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        sport = None
        dport = None
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        if sport is None:
            continue

        # Determine roles (hosts in both sets count as dual-role; still
        # flag crossings when a purely-IT host talks to a purely-OT host)
        src_is_it = src in it_only or src in dual_role
        src_is_ot = src in ot_only or src in dual_role
        dst_is_it = dst in it_only or dst in dual_role
        dst_is_ot = dst in ot_only or dst in dual_role

        # Boundary crossing: IT src -> OT dst or OT src -> IT dst
        src_role = None
        dst_role = None
        if src in it_only and dst in ot_only:
            src_role, dst_role = "IT", "OT"
        elif src in ot_only and dst in it_only:
            src_role, dst_role = "OT", "IT"
        elif src in it_only and dst in dual_role:
            src_role, dst_role = "IT", "OT"
        elif src in dual_role and dst in it_only:
            src_role, dst_role = "OT", "IT"
        elif src in ot_only and dst in dual_role:
            src_role, dst_role = "OT", "IT"
        elif src in dual_role and dst in ot_only:
            src_role, dst_role = "IT", "OT"

        if src_role and dst_role and src_role != dst_role:
            flow_key = (src, dst, dport)
            if flow_key not in boundary_flows:
                boundary_flows[flow_key] = {
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_role": src_role,
                    "dst_role": dst_role,
                    "port": dport,
                    "packets": 0,
                    "description": f"{src_role} host {src} -> {dst_role} host {dst} on port {dport}",
                }
            boundary_flows[flow_key]["packets"] += 1

        # OT internet access: OT host connecting to non-RFC1918 destination
        if src in ot_hosts and not _is_rfc1918(dst):
            inet_key = (src, dst, dport)
            if inet_key not in ot_internet_flows:
                ot_internet_flows[inet_key] = {
                    "ot_ip": src,
                    "external_ip": dst,
                    "port": dport,
                    "packets": 0,
                }
            ot_internet_flows[inet_key]["packets"] += 1

    # Build output lists
    it_hosts_list = sorted(
        [
            {
                "ip": ip,
                "protocols_seen": sorted(host_it_protocols.get(ip, set())),
                "packets": host_packets.get(ip, 0),
            }
            for ip in it_only
        ],
        key=lambda h: h["packets"],
        reverse=True,
    )

    ot_hosts_list = sorted(
        [
            {
                "ip": ip,
                "ics_protocols_seen": sorted(host_ot_protocols.get(ip, set())),
                "packets": host_packets.get(ip, 0),
            }
            for ip in ot_only
        ],
        key=lambda h: h["packets"],
        reverse=True,
    )

    boundary_list = sorted(
        boundary_flows.values(), key=lambda f: f["packets"], reverse=True
    )

    ot_internet_list = sorted(
        ot_internet_flows.values(), key=lambda f: f["packets"], reverse=True
    )

    summary = {
        "it_hosts": len(it_only),
        "ot_hosts": len(ot_only),
        "dual_role_hosts": len(dual_role),
        "boundary_crossings": len(boundary_list),
        "ot_internet_access": len(ot_internet_list),
    }

    logger.info(
        "IT/OT segmentation analysis complete: %d IT hosts, %d OT hosts, "
        "%d dual-role, %d boundary crossings, %d OT internet flows",
        summary["it_hosts"],
        summary["ot_hosts"],
        summary["dual_role_hosts"],
        summary["boundary_crossings"],
        summary["ot_internet_access"],
    )

    return {
        "summary": summary,
        "it_hosts": it_hosts_list,
        "ot_hosts": ot_hosts_list,
        "boundary_violations": boundary_list,
        "ot_internet_access": ot_internet_list,
    }
