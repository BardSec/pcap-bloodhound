"""ICS/SCADA protocol detection — identify industrial control system traffic."""

import logging
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, UDP, Raw

logger = logging.getLogger(__name__)

# ICS protocol definitions: port -> (name, transport)
ICS_TCP_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    4840: "OPC-UA",
    44818: "EtherNet/IP",
    102: "IEC-61850",
    2404: "IEC-104",
}

ICS_UDP_PORTS = {
    47808: "BACnet",
    44818: "EtherNet/IP",
}


def _validate_modbus(payload: bytes) -> bool:
    """Validate MBAP header: 7+ bytes, protocol ID at bytes 2-3 must be 0x0000."""
    if len(payload) < 7:
        return False
    protocol_id = (payload[2] << 8) | payload[3]
    return protocol_id == 0x0000


def _validate_dnp3(payload: bytes) -> bool:
    """DNP3 frames start with 0x05 0x64."""
    return len(payload) >= 2 and payload[0] == 0x05 and payload[1] == 0x64


def _validate_iec61850(payload: bytes) -> bool:
    """Distinguish IEC 61850 MMS from regular TPKT on port 102.

    TPKT header: version=3, then reserved byte, then length.
    MMS payloads typically contain ASN.1 BER-encoded MMS PDUs; look for
    common MMS-specific tag bytes deeper in the payload.
    """
    if len(payload) < 4:
        return False
    # Must be TPKT version 3
    if payload[0] != 0x03:
        return False
    # Look for MMS-specific markers in the payload (ASN.1 context tags
    # commonly seen in MMS confirmed-request / confirmed-response PDUs)
    mms_markers = [b"\xa0", b"\xa1", b"\xa2", b"\xa3", b"\xa4"]
    for marker in mms_markers:
        if marker in payload[4:]:
            return True
    return False


def _check_encrypted(payload: bytes) -> bool:
    """Heuristic: if payload starts with TLS record header, traffic is encrypted."""
    if len(payload) < 3:
        return False
    # TLS content types: 20-25, version 0x0301-0x0304
    if payload[0] in range(20, 26) and payload[1] == 0x03 and payload[2] in range(0, 5):
        return True
    return False


def analyze_ics_scada(packets: list) -> dict[str, Any]:
    """Detect ICS/SCADA protocols and catalog industrial flows."""

    # flow key: (src_ip, dst_ip, protocol) -> info
    flows: dict[tuple, dict] = {}
    # protocol -> set of unique hosts
    protocol_hosts: dict[str, set] = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        protocol_name = None
        port = None
        encrypted = False

        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # Check destination port first, then source port (reply traffic)
            matched_port = None
            if dport in ICS_TCP_PORTS:
                matched_port = dport
            elif sport in ICS_TCP_PORTS:
                matched_port = sport

            if matched_port is not None:
                candidate = ICS_TCP_PORTS[matched_port]
                port = matched_port

                # Apply payload validation for protocols that need it
                if candidate == "Modbus":
                    if payload and not _validate_modbus(payload):
                        continue
                    protocol_name = "Modbus"
                elif candidate == "DNP3":
                    if payload and not _validate_dnp3(payload):
                        continue
                    protocol_name = "DNP3"
                elif candidate == "IEC-61850":
                    if payload and not _validate_iec61850(payload):
                        continue
                    protocol_name = "IEC-61850"
                else:
                    protocol_name = candidate

                if payload:
                    encrypted = _check_encrypted(payload)

        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            matched_port = None
            if dport in ICS_UDP_PORTS:
                matched_port = dport
            elif sport in ICS_UDP_PORTS:
                matched_port = sport

            if matched_port is not None:
                protocol_name = ICS_UDP_PORTS[matched_port]
                port = matched_port

                if payload:
                    encrypted = _check_encrypted(payload)

        if protocol_name is None:
            continue

        flow_key = (src, dst, protocol_name)
        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": protocol_name,
                "port": port,
                "packets": 0,
                "encrypted": encrypted,
            }
        flows[flow_key]["packets"] += 1
        # Promote encrypted flag if any packet in the flow is encrypted
        if encrypted:
            flows[flow_key]["encrypted"] = True

        protocol_hosts[protocol_name].add(src)
        protocol_hosts[protocol_name].add(dst)

    # Count flows per protocol
    protocol_flow_counts: dict[str, int] = defaultdict(int)
    protocol_packet_counts: dict[str, int] = defaultdict(int)
    for (_, _, proto), info in flows.items():
        protocol_flow_counts[proto] += 1
        protocol_packet_counts[proto] += info["packets"]

    total_ics_packets = sum(info["packets"] for info in flows.values())
    ics_flows_list = sorted(flows.values(), key=lambda f: f["packets"], reverse=True)

    protocol_inventory = []
    for proto in sorted(protocol_hosts.keys()):
        protocol_inventory.append({
            "protocol": proto,
            "flow_count": protocol_flow_counts[proto],
            "total_packets": protocol_packet_counts[proto],
            "unique_hosts": len(protocol_hosts[proto]),
        })

    summary = {
        "ics_protocols_detected": len(protocol_hosts),
        "modbus_flows": protocol_flow_counts.get("Modbus", 0),
        "dnp3_flows": protocol_flow_counts.get("DNP3", 0),
        "total_ics_packets": total_ics_packets,
        "opc_ua_flows": protocol_flow_counts.get("OPC-UA", 0),
        "bacnet_flows": protocol_flow_counts.get("BACnet", 0),
    }

    logger.info(
        "ICS/SCADA analysis complete: %d protocols, %d flows, %d packets",
        summary["ics_protocols_detected"],
        len(ics_flows_list),
        total_ics_packets,
    )

    return {
        "summary": summary,
        "ics_flows": ics_flows_list,
        "protocol_inventory": protocol_inventory,
    }
