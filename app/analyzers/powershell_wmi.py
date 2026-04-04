"""PowerShell/WMI over network detection — detect PS remoting and WMI/DCOM traffic."""

from collections import defaultdict

from scapy.all import IP, TCP, Raw

# PowerShell Remoting (WinRM) ports
WINRM_HTTP = 5985
WINRM_HTTPS = 5986

# WMI/DCOM ports
DCOM_PORT = 135
WMI_DYNAMIC_RANGE = range(49152, 65536)  # Windows dynamic port range

# Signatures in payloads
PS_REMOTING_SIGNATURES = [
    b"<rsp:Shell",
    b"<rsp:Command",
    b"http://schemas.microsoft.com/wbem/wsman",
    b"Microsoft.PowerShell",
    b"<creationXml",
    b"WSManFault",
]

WMI_SIGNATURES = [
    b"\x05\x00\x0b",  # DCE/RPC bind
    b"\x05\x00\x00",  # DCE/RPC request
    b"IWbemServices",
    b"IWbemLevel1Login",
    b"WMI",
    b"NTLMSSP",
]

DCOM_SIGNATURES = [
    b"\x05\x00",  # DCE/RPC header
    b"IRemUnknown",
    b"IActivation",
    b"IObjectExporter",
]


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def analyze_powershell_wmi(packets):
    results = {
        "winrm_connections": [],
        "wmi_dcom_connections": [],
        "summary": {
            "winrm_flows": 0,
            "wmi_dcom_flows": 0,
            "unique_sources": 0,
            "unique_targets": 0,
        },
    }

    winrm_flows = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "ps_confirmed": False,
        "first_seen": None, "last_seen": None,
    })
    wmi_flows = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "wmi_confirmed": False,
        "first_seen": None, "last_seen": None, "type": "DCOM",
    })
    all_sources = set()
    all_targets = set()

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        ts = float(pkt.time)
        pkt_len = len(pkt)

        # Only internal-to-internal
        if not _is_private(src) or not _is_private(dst):
            continue

        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        # WinRM (PowerShell Remoting)
        if dport in (WINRM_HTTP, WINRM_HTTPS) or sport in (WINRM_HTTP, WINRM_HTTPS):
            if dport in (WINRM_HTTP, WINRM_HTTPS):
                key = (src, dst, dport)
            else:
                key = (dst, src, sport)

            flow = winrm_flows[key]
            flow["packets"] += 1
            flow["bytes"] += pkt_len
            if flow["first_seen"] is None:
                flow["first_seen"] = ts
            flow["last_seen"] = ts

            if payload:
                for sig in PS_REMOTING_SIGNATURES:
                    if sig in payload:
                        flow["ps_confirmed"] = True
                        break

            all_sources.add(key[0])
            all_targets.add(key[1])

        # DCOM/WMI (port 135 or dynamic range with WMI signatures)
        elif dport == DCOM_PORT or sport == DCOM_PORT:
            if dport == DCOM_PORT:
                key = (src, dst, dport)
            else:
                key = (dst, src, sport)

            flow = wmi_flows[key]
            flow["packets"] += 1
            flow["bytes"] += pkt_len
            flow["type"] = "DCOM/RPC"
            if flow["first_seen"] is None:
                flow["first_seen"] = ts
            flow["last_seen"] = ts

            if payload:
                for sig in WMI_SIGNATURES:
                    if sig in payload:
                        flow["wmi_confirmed"] = True
                        flow["type"] = "WMI"
                        break
                for sig in DCOM_SIGNATURES:
                    if sig in payload:
                        flow["wmi_confirmed"] = True
                        break

            all_sources.add(key[0])
            all_targets.add(key[1])

    # Build WinRM connections
    for (src, dst, dport), data in sorted(winrm_flows.items(), key=lambda x: -x[1]["packets"]):
        results["winrm_connections"].append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "protocol": "WinRM/PS Remoting",
            "ps_confirmed": data["ps_confirmed"],
            "packets": data["packets"],
            "bytes": data["bytes"],
            "duration_sec": round(data["last_seen"] - data["first_seen"], 1) if data["first_seen"] and data["last_seen"] else 0,
            "timestamp": data["first_seen"],
            "severity": "CRITICAL" if data["ps_confirmed"] else "HIGH",
        })

    # Build WMI/DCOM connections
    for (src, dst, dport), data in sorted(wmi_flows.items(), key=lambda x: -x[1]["packets"]):
        results["wmi_dcom_connections"].append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "protocol": data["type"],
            "wmi_confirmed": data["wmi_confirmed"],
            "packets": data["packets"],
            "bytes": data["bytes"],
            "duration_sec": round(data["last_seen"] - data["first_seen"], 1) if data["first_seen"] and data["last_seen"] else 0,
            "timestamp": data["first_seen"],
            "severity": "CRITICAL" if data["wmi_confirmed"] else "MEDIUM",
        })

    results["summary"] = {
        "winrm_flows": len(winrm_flows),
        "wmi_dcom_flows": len(wmi_flows),
        "unique_sources": len(all_sources),
        "unique_targets": len(all_targets),
    }

    return results
