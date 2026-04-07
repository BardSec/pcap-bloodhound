"""
Financial Protocol Detector
─────────────────────────────
Identifies financial messaging protocols in packet captures:

  - FIX (Financial Information eXchange): payload containing b"8=FIX." or
    traffic on port 9878
  - Bloomberg Terminal: traffic on port 8194
  - SWIFT MT messages: payload containing {1: or {4: block markers

For each detected flow, tracks source/destination, packet count, and whether
the connection is TLS-encrypted. Flags unencrypted financial protocol usage.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from scapy.all import TCP, IP, Raw

logger = logging.getLogger(__name__)

# ── Well-known financial protocol ports ───────────────────────────────────────
FIX_PORTS = {9878}
BLOOMBERG_PORTS = {8194}

# ── TLS detection ─────────────────────────────────────────────────────────────
TLS_PORTS = {443, 8443, 4443, 9443}


def _is_tls_payload(payload: bytes) -> bool:
    """Return True if payload begins with a TLS record header (0x16 0x03)."""
    return len(payload) >= 2 and payload[0] == 0x16 and payload[1] == 0x03


def _detect_financial_protocol(
    sport: int, dport: int, payload: bytes,
) -> str | None:
    """
    Identify the financial protocol from port numbers and payload content.
    Returns protocol name or None.
    """
    # FIX protocol: payload marker or well-known port
    if b"8=FIX." in payload:
        return "FIX"
    if sport in FIX_PORTS or dport in FIX_PORTS:
        return "FIX"

    # Bloomberg: port-based detection
    if sport in BLOOMBERG_PORTS or dport in BLOOMBERG_PORTS:
        return "Bloomberg"

    # SWIFT MT messages: block markers {1: (basic header) or {4: (text block)
    if b"{1:" in payload or b"{4:" in payload:
        return "SWIFT"

    return None


def _is_encrypted(sport: int, dport: int, payload: bytes) -> bool:
    """Determine whether a flow appears to be TLS-encrypted."""
    if _is_tls_payload(payload):
        return True
    if sport in TLS_PORTS or dport in TLS_PORTS:
        return True
    return False


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_financial_protocols(packets: list) -> dict[str, Any]:
    """
    Detect FIX, Bloomberg, and SWIFT protocol flows in the packet capture.

    Returns a dict with:
      - summary: stat card values
      - financial_flows: aggregated flow records
      - unencrypted_alerts: alerts for unencrypted financial traffic
    """
    # Aggregate by (src_ip, dst_ip, protocol) → {port, packets, encrypted}
    flow_stats: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
        lambda: {"port": 0, "packets": 0, "encrypted": True}
    )

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        sport: int = tcp_layer.sport
        dport: int = tcp_layer.dport

        payload = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""

        protocol = _detect_financial_protocol(sport, dport, payload)
        if protocol is None:
            continue

        flow_key = (src_ip, dst_ip, protocol)
        stats = flow_stats[flow_key]
        stats["packets"] += 1
        # Use the destination port (or source port if it matches a known port)
        if stats["port"] == 0:
            if dport in (FIX_PORTS | BLOOMBERG_PORTS):
                stats["port"] = dport
            elif sport in (FIX_PORTS | BLOOMBERG_PORTS):
                stats["port"] = sport
            else:
                stats["port"] = dport

        # A flow is unencrypted if any packet in it lacks encryption
        if not _is_encrypted(sport, dport, payload):
            stats["encrypted"] = False

    # ── Build output tables ──────────────────────────────────────────────────
    financial_flows: list[dict[str, Any]] = []
    unencrypted_alerts: list[dict[str, Any]] = []

    fix_flows = 0
    bloomberg_flows = 0
    swift_flows = 0
    unencrypted_count = 0

    for (src_ip, dst_ip, protocol), stats in sorted(flow_stats.items()):
        encrypted = stats["encrypted"]
        port = stats["port"]

        financial_flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": port,
            "packets": stats["packets"],
            "encrypted": encrypted,
        })

        if protocol == "FIX":
            fix_flows += 1
        elif protocol == "Bloomberg":
            bloomberg_flows += 1
        elif protocol == "SWIFT":
            swift_flows += 1

        if not encrypted:
            unencrypted_count += 1
            unencrypted_alerts.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "description": (
                    f"Unencrypted {protocol} traffic detected between "
                    f"{src_ip} and {dst_ip} on port {port}"
                ),
            })
            logger.warning(
                "Financial: unencrypted %s flow %s → %s:%d",
                protocol, src_ip, dst_ip, port,
            )

    logger.info(
        "Financial protocol scan complete: FIX=%d, Bloomberg=%d, SWIFT=%d, "
        "unencrypted=%d",
        fix_flows, bloomberg_flows, swift_flows, unencrypted_count,
    )

    return {
        "summary": {
            "fix_flows": fix_flows,
            "bloomberg_flows": bloomberg_flows,
            "swift_flows": swift_flows,
            "unencrypted_financial": unencrypted_count,
        },
        "financial_flows": financial_flows,
        "unencrypted_alerts": unencrypted_alerts,
    }
