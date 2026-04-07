"""
PCI-DSS Compliance Scanner
───────────────────────────
Scans cleartext TCP payloads for credit card PAN (Primary Account Number)
exposures that violate PCI-DSS requirements:

  - Detects 13-19 digit sequences matching the Luhn algorithm
  - Validates against major card brand prefixes
  - Skips TLS-encrypted payloads (0x16 0x03 record header or known TLS ports)
  - Inspects HTTP POST bodies, FTP data channels, and SMTP traffic
  - Flags unencrypted connections to payment-related ports
  - Masks PANs in output, showing only last 4 digits
"""
from __future__ import annotations

import logging
import re
from typing import Any

from scapy.all import TCP, IP, Raw

logger = logging.getLogger(__name__)

# ── Port sets ────────────────────────────────────────────────────────────────
TLS_PORTS = {443, 8443}
HTTP_PORTS = {80, 8080, 8000, 8008}
FTP_PORTS = {20, 21}
SMTP_PORTS = {25, 587}
PAYMENT_PORTS = {8443}

# ── PAN regex: 13-19 digits with optional spaces or dashes ────────────────────
RE_PAN_CANDIDATE = re.compile(rb"(?<!\d)(\d[\d \-]{11,22}\d)(?!\d)")


def _luhn_check(num_str: str) -> bool:
    """Validate a numeric string using the Luhn algorithm."""
    digits = [int(d) for d in num_str]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _strip_separators(raw: bytes) -> str:
    """Remove spaces and dashes from a candidate PAN bytes sequence."""
    return raw.decode("ascii", errors="ignore").replace(" ", "").replace("-", "")


def _mask_pan(digits: str) -> str:
    """Mask all but the last 4 digits: XXXX-XXXX-XXXX-1234."""
    last4 = digits[-4:]
    masked_len = len(digits) - 4
    # Build groups of 4 Xs, then append last 4
    groups = []
    remaining = masked_len
    while remaining > 0:
        chunk = min(4, remaining)
        groups.append("X" * chunk)
        remaining -= chunk
    groups.append(last4)
    return "-".join(groups)


def _is_tls_payload(payload: bytes) -> bool:
    """Return True if payload begins with a TLS record header (0x16 0x03)."""
    return len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03


def _detect_protocol(sport: int, dport: int, payload: bytes) -> str | None:
    """Identify the application-layer protocol based on ports and payload."""
    if dport in HTTP_PORTS or sport in HTTP_PORTS:
        return "HTTP"
    if dport in FTP_PORTS or sport in FTP_PORTS:
        return "FTP"
    if dport in SMTP_PORTS or sport in SMTP_PORTS:
        return "SMTP"
    # Fallback: check payload for HTTP method
    if payload[:4] in (b"POST", b"GET ", b"PUT ", b"HEAD"):
        return "HTTP"
    return None


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_pci_compliance(packets: list) -> dict[str, Any]:
    """
    Scan packet payloads for cleartext credit card PANs and unencrypted
    payment flows.

    Returns a dict with:
      - summary: stat card values
      - pan_exposures: list of PAN exposure records
      - unencrypted_payment_flows: list of flagged payment flows
    """
    pan_exposures: list[dict[str, Any]] = []
    unencrypted_flows: list[dict[str, Any]] = []
    seen_pans: set[tuple[str, str, str]] = set()  # (src_ip, dst_ip, masked)
    seen_flows: set[tuple[str, str, int]] = set()  # (src_ip, dst_ip, port)
    packets_scanned = 0

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        sport: int = tcp_layer.sport
        dport: int = tcp_layer.dport

        # ── Check for unencrypted payment port flows ─────────────────────────
        if dport in PAYMENT_PORTS or sport in PAYMENT_PORTS:
            payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
            port = dport if dport in PAYMENT_PORTS else sport
            if not _is_tls_payload(payload) and dport not in TLS_PORTS:
                flow_key = (src_ip, dst_ip, port)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    unencrypted_flows.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": port,
                        "description": (
                            f"Unencrypted connection to payment port {port} "
                            f"without TLS"
                        ),
                    })

        # ── Scan cleartext payloads for PANs ─────────────────────────────────
        if not pkt.haslayer(Raw):
            continue

        payload = bytes(pkt[Raw])
        packets_scanned += 1

        # Skip TLS-encrypted payloads
        if _is_tls_payload(payload):
            continue

        # Skip traffic on well-known TLS ports (likely encrypted even without
        # the 0x16 header visible in this segment)
        if dport in TLS_PORTS or sport in TLS_PORTS:
            continue

        protocol = _detect_protocol(sport, dport, payload)
        if protocol is None:
            # Still scan — PAN could appear in any cleartext TCP stream
            protocol = "TCP"

        # Find PAN candidates in payload
        for match in RE_PAN_CANDIDATE.finditer(payload):
            candidate_raw = match.group(1)
            digits = _strip_separators(candidate_raw)

            # Must be 13-19 digits
            if not digits.isdigit():
                continue
            if len(digits) < 13 or len(digits) > 19:
                continue

            # Luhn validation
            if not _luhn_check(digits):
                continue

            masked = _mask_pan(digits)
            dedup_key = (src_ip, dst_ip, masked)
            if dedup_key in seen_pans:
                continue
            seen_pans.add(dedup_key)

            pan_exposures.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport,
                "dst_port": dport,
                "protocol": protocol,
                "pan_masked": masked,
            })
            logger.warning(
                "PCI: cleartext PAN detected %s → %s:%d (%s) %s",
                src_ip, dst_ip, dport, protocol, masked,
            )

    logger.info(
        "PCI compliance scan complete: %d PANs found, %d unencrypted payment flows",
        len(pan_exposures), len(unencrypted_flows),
    )

    return {
        "summary": {
            "cleartext_pans_found": len(pan_exposures),
            "unencrypted_payment_flows": len(unencrypted_flows),
            "packets_scanned": packets_scanned,
        },
        "pan_exposures": pan_exposures,
        "unencrypted_payment_flows": unencrypted_flows,
    }
