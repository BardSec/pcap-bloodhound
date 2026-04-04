"""Detect content filter bypass attempts — VPN/proxy tunnels and unauthorized DNS resolvers."""

import re
from collections import defaultdict

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw


# Known VPN/proxy/anonymizer signatures in SNI, HTTP Host, or DNS queries
BYPASS_INDICATORS = {
    "vpn_services": [
        "nordvpn", "expressvpn", "surfshark", "cyberghost", "privateinternetaccess",
        "pia-vpn", "tunnelbear", "windscribe", "protonvpn", "hotspotshield",
        "hidemy.name", "hide.me", "ipvanish", "mullvad",
    ],
    "proxy_tools": [
        "psiphon", "ultrasurf", "lantern", "tor2web", "torproject",
        "shadowsocks", "v2ray", "trojan-gfw", "wireguard",
    ],
    "anonymizers": [
        "anonymox", "kproxy", "hidemyass", "whoer.net",
        "croxyproxy", "proxysite", "unblockvideos",
    ],
    "dns_bypass": [
        "nextdns", "adguard-dns", "quad9",
    ],
}

# Well-known public DNS resolvers (not district-managed)
PUBLIC_DNS_RESOLVERS = {
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
}

# DoH (DNS over HTTPS) endpoints
DOH_DOMAINS = [
    "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org",
]

# DoT port
DOT_PORT = 853


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def analyze_content_filter_bypass(packets):
    findings = {
        "unauthorized_dns": [],
        "doh_dot_detected": [],
        "vpn_proxy_indicators": [],
        "summary": {
            "unauthorized_dns_count": 0,
            "doh_dot_count": 0,
            "vpn_proxy_count": 0,
        },
    }

    seen_dns = set()
    seen_vpn = set()
    seen_doh = set()

    all_patterns = []
    for category, patterns in BYPASS_INDICATORS.items():
        for p in patterns:
            all_patterns.append((p, category))

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        ts = float(pkt.time)

        # Check for DNS to public resolvers
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            if dst in PUBLIC_DNS_RESOLVERS and _is_private(src):
                key = (src, dst)
                if key not in seen_dns:
                    seen_dns.add(key)
                    findings["unauthorized_dns"].append({
                        "client_ip": src,
                        "resolver_ip": dst,
                        "resolver_name": PUBLIC_DNS_RESOLVERS[dst],
                        "timestamp": ts,
                        "severity": "HIGH",
                    })

        # Check for DoT (port 853)
        if pkt.haslayer(TCP) and _is_private(src):
            dport = pkt[TCP].dport
            if dport == DOT_PORT:
                key = ("dot", src, dst)
                if key not in seen_doh:
                    seen_doh.add(key)
                    findings["doh_dot_detected"].append({
                        "type": "DNS-over-TLS",
                        "client_ip": src,
                        "server_ip": dst,
                        "port": dport,
                        "timestamp": ts,
                        "severity": "HIGH",
                    })

        # Check for DoH domains in DNS queries
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                qname_lower = qname.lower()

                for doh_domain in DOH_DOMAINS:
                    if doh_domain in qname_lower:
                        key = ("doh", src, qname_lower)
                        if key not in seen_doh:
                            seen_doh.add(key)
                            findings["doh_dot_detected"].append({
                                "type": "DNS-over-HTTPS",
                                "client_ip": src,
                                "server_ip": dst,
                                "domain": qname,
                                "timestamp": ts,
                                "severity": "HIGH",
                            })
                        break

                # Check for VPN/proxy domains in DNS
                for pattern, category in all_patterns:
                    if pattern in qname_lower:
                        key = (src, pattern)
                        if key not in seen_vpn:
                            seen_vpn.add(key)
                            findings["vpn_proxy_indicators"].append({
                                "type": "dns_query",
                                "client_ip": src,
                                "indicator": pattern,
                                "category": category,
                                "domain": qname,
                                "timestamp": ts,
                                "severity": "CRITICAL" if category == "proxy_tools" else "HIGH",
                            })
                        break
            except Exception:
                pass

        # Check HTTP Host headers and SNI for bypass indicators
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
                for pattern, category in all_patterns:
                    if pattern in payload:
                        key = (src, pattern, "http")
                        if key not in seen_vpn:
                            seen_vpn.add(key)
                            findings["vpn_proxy_indicators"].append({
                                "type": "http_traffic",
                                "client_ip": src,
                                "dst_ip": dst,
                                "indicator": pattern,
                                "category": category,
                                "timestamp": ts,
                                "severity": "CRITICAL" if category == "proxy_tools" else "HIGH",
                            })
                        break
            except Exception:
                pass

    findings["summary"]["unauthorized_dns_count"] = len(findings["unauthorized_dns"])
    findings["summary"]["doh_dot_count"] = len(findings["doh_dot_detected"])
    findings["summary"]["vpn_proxy_count"] = len(findings["vpn_proxy_indicators"])

    return findings
