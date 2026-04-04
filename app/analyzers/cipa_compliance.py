"""CIPA compliance check — verify web traffic passes through the district's content filter."""

from collections import defaultdict

from scapy.all import IP, TCP, Raw


# Known content filter product signatures found in TLS certificate issuers or HTTP headers
FILTER_PRODUCTS = {
    "lightspeed": "Lightspeed Systems",
    "relay.school": "Lightspeed Relay",
    "goguardian": "GoGuardian",
    "securly": "Securly",
    "cisco umbrella": "Cisco Umbrella",
    "opendns": "Cisco Umbrella/OpenDNS",
    "zscaler": "Zscaler",
    "contentkeeper": "ContentKeeper",
    "barracuda": "Barracuda",
    "smoothwall": "Smoothwall",
    "iboss": "iboss",
    "fortigate": "Fortinet FortiGate",
    "fortiguard": "Fortinet FortiGuard",
    "palo alto": "Palo Alto Networks",
    "sonicwall": "SonicWall",
    "websense": "Forcepoint/Websense",
    "forcepoint": "Forcepoint",
    "mcafee web gateway": "McAfee Web Gateway",
    "bluecoat": "Symantec/BlueCoat",
    "cleanbrowsing": "CleanBrowsing",
}

HTTPS_PORT = 443
HTTP_PORT = 80


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
        if payload[0] != 0x16:  # Handshake
            return None
        if payload[5] != 0x01:  # ClientHello
            return None

        # Parse through to extensions
        pos = 43  # Skip to session_id_length
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

            if etype == 0 and elen > 5:  # SNI extension
                sni_list_len = int.from_bytes(payload[pos:pos + 2], "big")
                sni_type = payload[pos + 2]
                sni_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                sni = payload[pos + 5:pos + 5 + sni_len]
                return sni.decode("ascii", errors="ignore")

            pos += elen

    except Exception:
        pass
    return None


def analyze_cipa_compliance(packets):
    results = {
        "filtered_connections": [],
        "unfiltered_connections": [],
        "detected_filter": None,
        "unfiltered_destinations": [],
        "summary": {
            "total_web_flows": 0,
            "filtered_count": 0,
            "unfiltered_count": 0,
            "compliance_pct": 0,
        },
    }

    # Track web connections (outbound HTTPS/HTTP to external IPs)
    web_flows = {}  # (src, dst, dport) -> {sni, filtered, filter_product}
    filter_evidence = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport

        # Only outbound web traffic from internal hosts
        if not _is_private(src) or _is_private(dst):
            continue
        if dport not in (HTTP_PORT, HTTPS_PORT):
            continue

        flow_key = (src, dst, dport)

        if flow_key not in web_flows:
            web_flows[flow_key] = {
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": dport,
                "sni": None,
                "filtered": False,
                "filter_product": None,
                "timestamp": float(pkt.time),
            }

        # Try to extract SNI from TLS ClientHello
        if pkt.haslayer(Raw) and dport == HTTPS_PORT:
            payload = bytes(pkt[Raw].load)
            sni = _extract_tls_sni(payload)
            if sni:
                web_flows[flow_key]["sni"] = sni

        # Check for filter product signatures in payloads
        if pkt.haslayer(Raw):
            try:
                payload_str = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
                for sig, product in FILTER_PRODUCTS.items():
                    if sig in payload_str:
                        web_flows[flow_key]["filtered"] = True
                        web_flows[flow_key]["filter_product"] = product
                        filter_evidence[product] += 1
                        break
            except Exception:
                pass

    # Also check TLS certificate issuers (from server responses on port 443)
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport

        if sport not in (HTTP_PORT, HTTPS_PORT):
            continue
        if _is_private(src) or not _is_private(dst):
            continue

        flow_key = (dst, src, sport)
        if flow_key not in web_flows:
            continue

        try:
            payload_str = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
            for sig, product in FILTER_PRODUCTS.items():
                if sig in payload_str:
                    web_flows[flow_key]["filtered"] = True
                    web_flows[flow_key]["filter_product"] = product
                    filter_evidence[product] += 1
                    break
        except Exception:
            pass

    # Determine the primary filter product
    if filter_evidence:
        primary_filter = max(filter_evidence, key=filter_evidence.get)
        results["detected_filter"] = primary_filter

    # Classify flows
    unfiltered_dests = defaultdict(int)
    for flow in web_flows.values():
        if flow["filtered"]:
            results["filtered_connections"].append(flow)
        else:
            results["unfiltered_connections"].append(flow)
            dest = flow["sni"] or flow["dst_ip"]
            unfiltered_dests[dest] += 1

    # Top unfiltered destinations
    results["unfiltered_destinations"] = sorted(
        [{"destination": d, "connection_count": c, "severity": "HIGH"}
         for d, c in unfiltered_dests.items()],
        key=lambda x: x["connection_count"],
        reverse=True,
    )[:50]

    total = len(web_flows)
    filtered = len(results["filtered_connections"])
    unfiltered = len(results["unfiltered_connections"])

    results["summary"] = {
        "total_web_flows": total,
        "filtered_count": filtered,
        "unfiltered_count": unfiltered,
        "compliance_pct": round((filtered / total) * 100) if total > 0 else 100,
    }

    return results
