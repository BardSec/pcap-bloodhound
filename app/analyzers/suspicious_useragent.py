"""Suspicious user-agent string detection — flag non-browser HTTP user agents."""

import re
from collections import defaultdict

from scapy.all import IP, TCP, Raw

# Known suspicious/non-browser user agents
SUSPICIOUS_PATTERNS = [
    (r"python-requests", "Python Requests", "scripting"),
    (r"python-urllib", "Python urllib", "scripting"),
    (r"python/", "Python HTTP", "scripting"),
    (r"go-http-client", "Go HTTP Client", "scripting"),
    (r"curl/", "cURL", "scripting"),
    (r"wget/", "Wget", "scripting"),
    (r"powershell", "PowerShell", "scripting"),
    (r"java/", "Java HTTP", "scripting"),
    (r"perl/", "Perl HTTP", "scripting"),
    (r"ruby/", "Ruby HTTP", "scripting"),
    (r"php/", "PHP HTTP", "scripting"),
    (r"libwww-perl", "Perl LWP", "scripting"),
    (r"mechanize", "Mechanize", "scraping"),
    (r"scrapy", "Scrapy", "scraping"),
    (r"httpclient", "HTTPClient", "scripting"),
    (r"okhttp", "OkHttp", "mobile_framework"),
    (r"axios", "Axios", "scripting"),
    (r"node-fetch", "Node Fetch", "scripting"),
    (r"aiohttp", "aiohttp", "scripting"),
    (r"httpx", "HTTPX", "scripting"),
    (r"nmap", "Nmap", "scanning"),
    (r"nikto", "Nikto", "scanning"),
    (r"masscan", "Masscan", "scanning"),
    (r"sqlmap", "SQLMap", "attack"),
    (r"burp", "Burp Suite", "pentesting"),
    (r"dirbuster", "DirBuster", "scanning"),
    (r"gobuster", "GoBuster", "scanning"),
    (r"wpscan", "WPScan", "scanning"),
    (r"zgrab", "ZGrab", "scanning"),
    (r"bot", "Bot", "bot"),
    (r"spider", "Spider", "bot"),
    (r"crawler", "Crawler", "bot"),
    (r"cobalt", "Cobalt Strike", "c2"),
    (r"empire", "Empire", "c2"),
    (r"metasploit", "Metasploit", "c2"),
    (r"mimikatz", "Mimikatz", "attack"),
]

# User agents that are expected/benign
BENIGN_PATTERNS = [
    r"mozilla", r"chrome", r"safari", r"firefox", r"edge", r"opera",
    r"microsoft office", r"outlook", r"teams",
    r"windows-update", r"windowsupdate", r"microsoft-delivery",
    r"google update", r"apple-",
]

UA_REGEX = re.compile(rb"User-Agent:\s*(.+?)(?:\r\n|\r|\n)", re.IGNORECASE)


def analyze_suspicious_useragents(packets):
    results = {
        "suspicious_agents": [],
        "summary": {
            "total_http_requests": 0,
            "suspicious_count": 0,
            "unique_agents": 0,
        },
    }

    seen = defaultdict(lambda: {"clients": set(), "destinations": set(), "count": 0, "first_seen": None})
    compiled_suspicious = [(re.compile(p, re.IGNORECASE), name, cat) for p, name, cat in SUSPICIOUS_PATTERNS]
    compiled_benign = [re.compile(p, re.IGNORECASE) for p in BENIGN_PATTERNS]

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue

        try:
            payload = pkt[Raw].load
        except Exception:
            continue

        match = UA_REGEX.search(payload)
        if not match:
            continue

        results["summary"]["total_http_requests"] += 1
        ua_string = match.group(1).decode("utf-8", errors="ignore").strip()
        ua_lower = ua_string.lower()

        # Skip known benign user agents
        if any(p.search(ua_lower) for p in compiled_benign):
            continue

        # Check against suspicious patterns
        for pattern, name, category in compiled_suspicious:
            if pattern.search(ua_lower):
                src = pkt[IP].src
                dst = pkt[IP].dst
                ts = float(pkt.time)

                entry = seen[ua_string]
                entry["clients"].add(src)
                entry["destinations"].add(dst)
                entry["count"] += 1
                if entry["first_seen"] is None:
                    entry["first_seen"] = ts
                entry["name"] = name
                entry["category"] = category
                break

    # Build results
    for ua_string, data in sorted(seen.items(), key=lambda x: -x[1]["count"]):
        category = data["category"]
        if category in ("c2", "attack"):
            severity = "CRITICAL"
        elif category in ("scanning", "pentesting"):
            severity = "HIGH"
        elif category == "scripting":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results["suspicious_agents"].append({
            "user_agent": ua_string,
            "matched_tool": data["name"],
            "category": category,
            "request_count": data["count"],
            "unique_clients": len(data["clients"]),
            "clients": sorted(data["clients"]),
            "unique_destinations": len(data["destinations"]),
            "timestamp": data["first_seen"],
            "severity": severity,
        })

    results["summary"]["suspicious_count"] = sum(a["request_count"] for a in results["suspicious_agents"])
    results["summary"]["unique_agents"] = len(results["suspicious_agents"])

    return results
