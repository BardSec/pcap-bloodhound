"""Network service discovery — inventory all visible services in the capture."""

from collections import defaultdict

from scapy.all import IP, TCP, UDP

# Well-known ports to service names
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP Server", 68: "DHCP Client", 80: "HTTP", 110: "POP3",
    111: "RPC", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD/Print",
    587: "SMTP Submission", 631: "IPP/CUPS", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIPS",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP Alt",
    8443: "HTTPS Alt", 9090: "Prometheus", 9100: "Print (RAW)",
    27017: "MongoDB",
}


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def analyze_services(packets):
    results = {
        "services": [],
        "summary": {
            "total_services": 0,
            "internal_services": 0,
            "external_services": 0,
        },
    }

    # Track services that responded (SYN-ACK for TCP, any response for UDP)
    # Key: (server_ip, port, proto) -> set of clients
    active_services = defaultdict(lambda: {"clients": set(), "packets": 0, "bytes": 0})

    # Track TCP SYN-ACKs (server is responding)
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        pkt_len = len(pkt)

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # SYN-ACK means src:sport is a service
            if flags == 0x12:  # SYN-ACK
                key = (src, sport, "TCP")
                active_services[key]["clients"].add(dst)
                active_services[key]["packets"] += 1
                active_services[key]["bytes"] += pkt_len

            # Also count established traffic to known service ports
            elif flags & 0x10 and sport in KNOWN_SERVICES:  # ACK from server
                key = (src, sport, "TCP")
                active_services[key]["clients"].add(dst)
                active_services[key]["packets"] += 1
                active_services[key]["bytes"] += pkt_len

        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            # Response from known service ports
            if sport in KNOWN_SERVICES:
                key = (src, sport, "UDP")
                active_services[key]["clients"].add(dst)
                active_services[key]["packets"] += 1
                active_services[key]["bytes"] += pkt_len

    # Build service list
    internal_count = 0
    external_count = 0

    for (ip, port, proto), data in sorted(active_services.items(), key=lambda x: -len(x[1]["clients"])):
        service_name = KNOWN_SERVICES.get(port, f"Port {port}")
        is_internal = _is_private(ip)

        if is_internal:
            internal_count += 1
        else:
            external_count += 1

        results["services"].append({
            "server_ip": ip,
            "port": port,
            "protocol": proto,
            "service": service_name,
            "client_count": len(data["clients"]),
            "packet_count": data["packets"],
            "bytes": data["bytes"],
            "internal": is_internal,
            "severity": "INFO",
        })

    results["summary"] = {
        "total_services": len(active_services),
        "internal_services": internal_count,
        "external_services": external_count,
    }

    return results
