"""
HIPAA Compliance Analyzer
─────────────────────────
Scans cleartext TCP payloads for Protected Health Information (PHI) patterns
and flags unencrypted medical protocol traffic:

  • SSN patterns       (with exclusion of known-invalid ranges)
  • Date-of-birth      (MM/DD/YYYY and YYYY-MM-DD)
  • Medical Record Nos (MRN:/MRN= followed by digits)
  • Unencrypted HL7    (port 2575)
  • Unencrypted DICOM  (port 104)

Actual PHI values are NEVER included in output — all matches are masked.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from scapy.all import TCP, IP, Raw

logger = logging.getLogger(__name__)

# ── Port constants ───────────────────────────────────────────────────────────
HL7_PORT = 2575
DICOM_PORT = 104
TLS_PORT = 443

# ── PHI regex patterns ──────────────────────────────────────────────────────
RE_SSN = re.compile(rb"\b(\d{3})-(\d{2})-(\d{4})\b")
RE_DOB_SLASH = re.compile(rb"\b\d{2}/\d{2}/\d{4}\b")
RE_DOB_DASH = re.compile(rb"\b\d{4}-\d{2}-\d{2}\b")
RE_MRN = re.compile(rb"MRN[=:]\s*(\d+)", re.IGNORECASE)


def _is_tls_payload(payload: bytes) -> bool:
    """Check if payload starts with a TLS record header (0x16 0x03)."""
    return len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03


def _is_valid_ssn(area: bytes, group: bytes, serial: bytes) -> bool:
    """Exclude obviously invalid SSN ranges per SSA rules."""
    if area == b"000" or group == b"00" or serial == b"0000":
        return False
    if area == b"666":
        return False
    if int(area) >= 900:
        return False
    return True


def _mask_ssn(match: re.Match) -> str:
    """Return masked SSN like XXX-XX-1234."""
    serial = match.group(3).decode("ascii", errors="replace")
    return f"XXX-XX-{serial}"


def _flow_key(src_ip: str, dst_ip: str, port: int) -> str:
    return f"{src_ip}->{dst_ip}:{port}"


# ── Main analysis function ───────────────────────────────────────────────────

def analyze_hipaa_compliance(packets: list) -> dict[str, Any]:
    """
    Scan packet payloads for cleartext PHI exposure and unencrypted medical
    protocol traffic.  Returns summary statistics, PHI findings, and
    unencrypted medical flow details.
    """
    phi_findings: list[dict[str, Any]] = []
    phi_flows: set[str] = set()

    # Track unencrypted medical flows: key -> {info dict}
    hl7_flows: dict[str, dict[str, Any]] = {}
    dicom_flows: dict[str, dict[str, Any]] = {}

    ssn_count = 0
    dob_count = 0
    mrn_count = 0

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport

        # ── Unencrypted HL7 / DICOM flow tracking ───────────────────────
        if dport == HL7_PORT or sport == HL7_PORT:
            port = HL7_PORT
            key = _flow_key(src_ip, dst_ip, port)
            if key not in hl7_flows:
                hl7_flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": port,
                    "protocol": "HL7",
                    "packets": 0,
                }
            hl7_flows[key]["packets"] += 1

        if dport == DICOM_PORT or sport == DICOM_PORT:
            port = DICOM_PORT
            key = _flow_key(src_ip, dst_ip, port)
            if key not in dicom_flows:
                dicom_flows[key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": port,
                    "protocol": "DICOM",
                    "packets": 0,
                }
            dicom_flows[key]["packets"] += 1

        # ── Payload inspection ───────────────────────────────────────────
        if not pkt.haslayer(Raw):
            continue

        payload = bytes(pkt[Raw].load)
        if not payload:
            continue

        # Skip TLS-encrypted payloads
        if _is_tls_payload(payload):
            continue
        if dport == TLS_PORT or sport == TLS_PORT:
            continue

        effective_port = dport

        # ── SSN scan ─────────────────────────────────────────────────────
        for m in RE_SSN.finditer(payload):
            area, group, serial = m.group(1), m.group(2), m.group(3)
            if not _is_valid_ssn(area, group, serial):
                continue
            ssn_count += 1
            fkey = _flow_key(src_ip, dst_ip, effective_port)
            phi_flows.add(fkey)
            masked = _mask_ssn(m)
            phi_findings.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": effective_port,
                "phi_type": "SSN",
                "context": f"SSN pattern detected: {masked}",
                "protocol": _protocol_label(dport, sport),
            })

        # ── DOB scan (slash format) ──────────────────────────────────────
        for m in RE_DOB_SLASH.finditer(payload):
            dob_count += 1
            fkey = _flow_key(src_ip, dst_ip, effective_port)
            phi_flows.add(fkey)
            phi_findings.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": effective_port,
                "phi_type": "DOB",
                "context": "Date pattern (MM/DD/YYYY) found in cleartext",
                "protocol": _protocol_label(dport, sport),
            })

        # ── DOB scan (dash format) ───────────────────────────────────────
        for m in RE_DOB_DASH.finditer(payload):
            dob_count += 1
            fkey = _flow_key(src_ip, dst_ip, effective_port)
            phi_flows.add(fkey)
            phi_findings.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": effective_port,
                "phi_type": "DOB",
                "context": "Date pattern (YYYY-MM-DD) found in cleartext",
                "protocol": _protocol_label(dport, sport),
            })

        # ── MRN scan ────────────────────────────────────────────────────
        for m in RE_MRN.finditer(payload):
            mrn_count += 1
            fkey = _flow_key(src_ip, dst_ip, effective_port)
            phi_flows.add(fkey)
            mrn_value = m.group(1).decode("ascii", errors="replace")
            # Mask all but last 4 digits
            if len(mrn_value) > 4:
                masked_mrn = "X" * (len(mrn_value) - 4) + mrn_value[-4:]
            else:
                masked_mrn = "X" * len(mrn_value)
            phi_findings.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": effective_port,
                "phi_type": "MRN",
                "context": f"Medical Record Number detected: {masked_mrn}",
                "protocol": _protocol_label(dport, sport),
            })

    total_phi = ssn_count + dob_count + mrn_count
    unencrypted_medical = list(hl7_flows.values()) + list(dicom_flows.values())

    logger.info(
        "HIPAA scan complete: %d PHI exposures, %d unencrypted HL7, %d unencrypted DICOM",
        total_phi,
        len(hl7_flows),
        len(dicom_flows),
    )

    return {
        "summary": {
            "phi_exposures": total_phi,
            "unencrypted_hl7_flows": len(hl7_flows),
            "unencrypted_dicom_flows": len(dicom_flows),
            "ssn_patterns": ssn_count,
            "dob_patterns": dob_count,
        },
        "phi_findings": phi_findings,
        "unencrypted_medical_flows": unencrypted_medical,
    }


def _protocol_label(dport: int, sport: int) -> str:
    """Return a human-friendly protocol label based on port numbers."""
    for port in (dport, sport):
        if port == HL7_PORT:
            return "HL7"
        if port == DICOM_PORT:
            return "DICOM"
        if port == 80 or port == 8080:
            return "HTTP"
        if port == 21:
            return "FTP"
    return "TCP"
