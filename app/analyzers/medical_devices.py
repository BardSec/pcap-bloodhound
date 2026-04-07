"""
Medical Device & Protocol Analyzer
────────────────────────────────────
Detects medical devices and healthcare protocols in packet captures:

  • HL7v2 messages    (MSH| segment header detection)
  • DICOM traffic     (A-ASSOCIATE-RQ / A-ASSOCIATE-AC PDUs on port 104)
  • Device OUI lookup (MAC prefix → known medical device manufacturers)

Tracks unique devices by MAC address and associates them with observed IPs.
"""
from __future__ import annotations

import logging
from typing import Any

from scapy.all import TCP, IP, Raw, Ether

logger = logging.getLogger(__name__)

# ── Port constants ───────────────────────────────────────────────────────────
DICOM_PORT = 104

# ── Medical device MAC OUI prefixes ─────────────────────────────────────────
# Mapping of normalized OUI prefix (lowercase, colon-separated) to manufacturer
MEDICAL_OUIS: dict[str, str] = {
    "00:09:02": "GE Healthcare",
    "00:50:f1": "GE Healthcare",
    "00:1a:6c": "Philips Medical",
    "00:21:fb": "Philips Medical",
    "00:0b:ab": "Siemens Healthineers",
    "00:0e:8e": "Siemens Healthineers",
    "00:1e:c0": "Baxter",
    "00:17:23": "Medtronic",
    "00:1d:b5": "Welch Allyn",
    "00:1e:8f": "Draeger",
    "00:09:b0": "Nihon Kohden",
    "00:1c:62": "Mindray",
}


def _get_oui(mac: str) -> str | None:
    """Extract the OUI prefix (first 3 octets) from a MAC address."""
    prefix = mac.lower()[:8]  # "aa:bb:cc"
    return prefix if len(prefix) == 8 else None


def _is_tls_payload(payload: bytes) -> bool:
    """Check if payload starts with a TLS record header (0x16 0x03)."""
    return len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03


def _flow_key(src_ip: str, dst_ip: str, port: int) -> str:
    return f"{src_ip}->{dst_ip}:{port}"


# ── Main analysis function ───────────────────────────────────────────────────

def analyze_medical_devices(packets: list) -> dict[str, Any]:
    """
    Detect medical devices via OUI lookup and identify HL7v2 / DICOM protocol
    traffic.  Returns summary statistics, detected devices, and medical
    protocol flow details.
    """
    # Track devices by MAC address
    devices: dict[str, dict[str, Any]] = {}  # mac -> info

    # Track medical protocol flows
    hl7_flows: dict[str, dict[str, Any]] = {}
    dicom_flows: dict[str, dict[str, Any]] = {}

    dicom_associations = 0

    for pkt in packets:
        # ── OUI-based device detection ───────────────────────────────────
        if pkt.haslayer(Ether):
            ether = pkt[Ether]
            src_mac = ether.src
            oui = _get_oui(src_mac)
            if oui and oui in MEDICAL_OUIS:
                if src_mac not in devices:
                    # Try to get the IP associated with this MAC
                    ip_addr = ""
                    if pkt.haslayer(IP):
                        ip_addr = pkt[IP].src
                    devices[src_mac] = {
                        "mac": src_mac,
                        "ip": ip_addr,
                        "manufacturer": MEDICAL_OUIS[oui],
                        "packets": 0,
                    }
                devices[src_mac]["packets"] += 1
                # Update IP if we see one and don't have it yet
                if not devices[src_mac]["ip"] and pkt.haslayer(IP):
                    devices[src_mac]["ip"] = pkt[IP].src

        # ── Protocol detection requires TCP + IP ─────────────────────────
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport

        if not pkt.haslayer(Raw):
            continue

        payload = bytes(pkt[Raw].load)
        if not payload:
            continue

        encrypted = _is_tls_payload(payload)

        # ── HL7v2 detection (MSH| segment header) ───────────────────────
        if b"MSH|" in payload:
            port = dport
            key = _flow_key(src_ip, dst_ip, port)
            if key not in hl7_flows:
                hl7_flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "HL7v2",
                    "port": port,
                    "packets": 0,
                    "encrypted": encrypted,
                }
            hl7_flows[key]["packets"] += 1

        # ── DICOM detection (port 104 + PDU type bytes) ──────────────────
        if dport == DICOM_PORT or sport == DICOM_PORT:
            port = DICOM_PORT
            key = _flow_key(src_ip, dst_ip, port)
            if key not in dicom_flows:
                dicom_flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "DICOM",
                    "port": port,
                    "packets": 0,
                    "encrypted": encrypted,
                }
            dicom_flows[key]["packets"] += 1

            # Count DICOM association PDUs
            if len(payload) >= 1:
                pdu_type = payload[0]
                if pdu_type in (0x01, 0x02):  # A-ASSOCIATE-RQ / A-ASSOCIATE-AC
                    dicom_associations += 1

    medical_protocols = list(hl7_flows.values()) + list(dicom_flows.values())
    detected_devices = list(devices.values())
    unique_macs = len(devices)

    logger.info(
        "Medical device scan complete: %d devices, %d HL7 streams, "
        "%d DICOM associations, %d unique MACs",
        len(detected_devices),
        len(hl7_flows),
        dicom_associations,
        unique_macs,
    )

    return {
        "summary": {
            "medical_devices_detected": len(detected_devices),
            "hl7_streams": len(hl7_flows),
            "dicom_associations": dicom_associations,
            "unique_device_macs": unique_macs,
        },
        "detected_devices": detected_devices,
        "medical_protocols": medical_protocols,
    }
