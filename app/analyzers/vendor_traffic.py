"""Detect EdTech vendor traffic anomalies — unencrypted connections, bulk exports, third-party data sharing."""

from collections import defaultdict

from scapy.all import IP, TCP, DNS, DNSQR, Raw


# Known EdTech vendor domains (matched as substrings against DNS queries and SNI)
EDTECH_VENDORS = {
    # SIS platforms
    "powerschool": "PowerSchool",
    "infinite-campus": "Infinite Campus",
    "infinitecampus": "Infinite Campus",
    "skyward": "Skyward",
    "aeries": "Aeries",
    "synergy": "Edupoint Synergy",
    "aspencloud": "Follett Aspen",
    "tyler-sis": "Tyler SIS",
    "eschoolplus": "PowerSchool eSchoolPlus",
    # LMS / Classroom
    "instructure.com": "Canvas",
    "canvas.": "Canvas",
    "schoology": "Schoology",
    "google.com/schoolutils": "Google Classroom",
    "classroom.google": "Google Classroom",
    "teams.microsoft": "Microsoft Teams",
    "seesaw": "Seesaw",
    # SSO / Rostering
    "clever.com": "Clever",
    "classlink": "ClassLink",
    # Content filtering / monitoring
    "goguardian": "GoGuardian",
    "securly": "Securly",
    "lightspeed": "Lightspeed Systems",
    "relay.school": "Lightspeed Relay",
    "bark.us": "Bark",
    "gaggle.net": "Gaggle",
    # Assessment
    "nwea.org": "NWEA MAP",
    "renaissance.com": "Renaissance",
    "iready": "Curriculum Associates iReady",
    "amplify.com": "Amplify",
    "khanacademy": "Khan Academy",
    "ixl.com": "IXL",
    # Communication
    "parentSquare": "ParentSquare",
    "parentsquare": "ParentSquare",
    "bloomz": "Bloomz",
    "remind.com": "Remind",
    "classdojo": "ClassDojo",
}

# Third-party analytics/tracking domains that may collect student data
TRACKING_DOMAINS = [
    "doubleclick.net", "googlesyndication.com", "facebook.com/tr",
    "analytics.google.com", "px.ads", "adsrvr.org", "adnxs.com",
    "criteo.com", "taboola.com", "outbrain.com", "hotjar.com",
    "fullstory.com", "mouseflow.com", "mixpanel.com", "segment.io",
    "segment.com", "amplitude.com", "heapanalytics.com",
    "newrelic.com", "datadoghq.com", "sentry.io",
    "crazyegg.com", "optimizely.com", "hubspot.com",
    "marketo.net", "pardot.com", "salesforce.com",
    "tiktok.com", "snapchat.com", "instagram.com",
]

# Bulk export threshold (bytes) — flag large outbound transfers to vendor domains
BULK_EXPORT_THRESHOLD = 500_000  # 500 KB


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def _extract_tls_sni(payload):
    """Try to extract SNI from a TLS ClientHello."""
    try:
        if len(payload) < 44:
            return None
        if payload[0] != 0x16:
            return None
        if payload[5] != 0x01:
            return None
        pos = 43
        if pos >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        ext_end = pos + ext_len
        while pos + 4 < ext_end and pos + 4 < len(payload):
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0 and elen > 5:
                sni_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                sni = payload[pos + 5:pos + 5 + sni_len]
                return sni.decode("ascii", errors="ignore")
            pos += elen
    except Exception:
        pass
    return None


def analyze_vendor_traffic(packets):
    results = {
        "vendor_connections": [],
        "unencrypted_vendor_flows": [],
        "tracker_connections": [],
        "bulk_transfers": [],
        "summary": {
            "vendors_detected": 0,
            "unencrypted_vendor_flows": 0,
            "tracker_connections": 0,
            "bulk_transfers": 0,
        },
    }

    # Track which vendors are seen via DNS and SNI
    vendor_hits = defaultdict(lambda: {"encrypted": 0, "cleartext": 0, "domains": set()})
    tracker_hits = defaultdict(set)  # tracker_domain -> set of client IPs

    # Track bytes per outbound flow for bulk export detection
    outbound_bytes = defaultdict(int)  # (src, dst) -> bytes
    flow_vendor = {}  # (src, dst) -> vendor_name
    flow_domains = {}  # (src, dst) -> domain

    seen_unencrypted = set()

    # First pass: map IPs to vendor names via DNS
    ip_to_vendor = {}
    ip_to_domain = {}

    for pkt in packets:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            continue

        try:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
        except Exception:
            continue

        # Check vendor domains
        for pattern, vendor_name in EDTECH_VENDORS.items():
            if pattern.lower() in qname:
                # Try to get resolved IP from DNS response
                if pkt.haslayer(DNS) and pkt[DNS].ancount > 0:
                    for i in range(pkt[DNS].ancount):
                        try:
                            rr = pkt[DNS].an[i] if i == 0 else pkt[DNS].an[i]
                            if hasattr(rr, 'rdata'):
                                rdata = str(rr.rdata)
                                if '.' in rdata and not rdata.endswith('.'):
                                    ip_to_vendor[rdata] = vendor_name
                                    ip_to_domain[rdata] = qname
                        except Exception:
                            pass
                vendor_hits[vendor_name]["domains"].add(qname)
                break

        # Check tracker domains
        for tracker in TRACKING_DOMAINS:
            if tracker in qname:
                if pkt.haslayer(IP):
                    client = pkt[IP].src if _is_private(pkt[IP].src) else pkt[IP].dst
                    tracker_hits[tracker].add(client)
                break

    # Second pass: analyze traffic flows
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        if not _is_private(src):
            continue

        # Check SNI in TLS handshakes for vendor identification
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 443:
            payload = bytes(pkt[Raw].load)
            sni = _extract_tls_sni(payload)
            if sni:
                sni_lower = sni.lower()
                for pattern, vendor_name in EDTECH_VENDORS.items():
                    if pattern.lower() in sni_lower:
                        vendor_hits[vendor_name]["encrypted"] += 1
                        vendor_hits[vendor_name]["domains"].add(sni)
                        ip_to_vendor[dst] = vendor_name
                        ip_to_domain[dst] = sni
                        break

        # Track cleartext vendor traffic (HTTP)
        if pkt.haslayer(TCP) and pkt[TCP].dport in (80, 8080):
            vendor_name = ip_to_vendor.get(dst)
            if vendor_name:
                vendor_hits[vendor_name]["cleartext"] += 1
                key = (src, dst, vendor_name)
                if key not in seen_unencrypted:
                    seen_unencrypted.add(key)
                    results["unencrypted_vendor_flows"].append({
                        "client_ip": src,
                        "server_ip": dst,
                        "vendor": vendor_name,
                        "domain": ip_to_domain.get(dst, "unknown"),
                        "port": pkt[TCP].dport,
                        "timestamp": float(pkt.time),
                        "severity": "CRITICAL",
                    })

        # Track outbound bytes for bulk export detection
        if pkt.haslayer(TCP) and dst in ip_to_vendor:
            try:
                payload_len = len(pkt[IP].payload)
                flow_key = (src, dst)
                outbound_bytes[flow_key] += payload_len
                flow_vendor[flow_key] = ip_to_vendor[dst]
                flow_domains[flow_key] = ip_to_domain.get(dst, "unknown")
            except Exception:
                pass

    # Build vendor connection summary
    for vendor_name, stats in sorted(vendor_hits.items()):
        results["vendor_connections"].append({
            "vendor": vendor_name,
            "domains": sorted(stats["domains"])[:10],
            "encrypted_connections": stats["encrypted"],
            "cleartext_connections": stats["cleartext"],
            "severity": "CRITICAL" if stats["cleartext"] > 0 else "INFO",
        })

    # Build tracker connection list
    for tracker, clients in sorted(tracker_hits.items()):
        results["tracker_connections"].append({
            "tracker_domain": tracker,
            "client_count": len(clients),
            "client_ips": sorted(clients)[:20],
            "severity": "HIGH",
        })

    # Flag bulk transfers to vendor IPs
    for (src, dst), total_bytes in outbound_bytes.items():
        if total_bytes >= BULK_EXPORT_THRESHOLD:
            results["bulk_transfers"].append({
                "client_ip": src,
                "server_ip": dst,
                "vendor": flow_vendor.get((src, dst), "unknown"),
                "domain": flow_domains.get((src, dst), "unknown"),
                "bytes_sent": total_bytes,
                "megabytes_sent": round(total_bytes / (1024 * 1024), 2),
                "severity": "HIGH" if total_bytes < 5_000_000 else "CRITICAL",
            })

    results["bulk_transfers"].sort(key=lambda x: x["bytes_sent"], reverse=True)

    results["summary"]["vendors_detected"] = len(results["vendor_connections"])
    results["summary"]["unencrypted_vendor_flows"] = len(results["unencrypted_vendor_flows"])
    results["summary"]["tracker_connections"] = len(results["tracker_connections"])
    results["summary"]["bulk_transfers"] = len(results["bulk_transfers"])

    return results
