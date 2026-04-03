"""
TLS / SSL Inspection Detector
───────────────────────────────
Parses TLS handshake records from raw TCP payloads to:

  1. Extract SNI (Server Name Indication) from ClientHello messages
  2. Extract certificate CN and issuer from server Certificate messages
  3. Match SNI ↔ certificate across the same TCP stream
  4. Flag known content-filter / SSL-inspection products by issuer signature
     (Zscaler, Lightspeed, Securly, Palo Alto, Fortinet, Cisco, etc.)
  5. Detect TLS Alert fatal messages (handshake_failure, cert expired, etc.)

Note: Certificate parsing works for TLS 1.0–1.2 where the Certificate
message is transmitted in plaintext.  TLS 1.3 encrypts the Certificate,
so only SNI and Alert records are available there.
"""
from __future__ import annotations

import struct
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


# ── Common HTTPS / TLS ports ─────────────────────────────────────────────────
TLS_PORTS = {443, 8443, 4443, 9443, 10443}

# ── Known SSL-inspection / content-filter certificate issuer signatures ───────
# Matched as case-insensitive substrings against issuer O= or CN= fields.
KNOWN_FILTERS: list[tuple[str, str]] = [
    ("zscaler",            "Zscaler Cloud Security"),
    ("lightspeed",         "Lightspeed Systems"),
    ("securly",            "Securly Web Filter"),
    ("goguardian",         "GoGuardian"),
    ("iboss",              "iBoss Web Gateway"),
    ("cisco umbrella",     "Cisco Umbrella"),
    ("cisco web security", "Cisco Web Security Appliance (WSA)"),
    ("palo alto networks", "Palo Alto Networks SSL Decryption"),
    ("fortinet",           "Fortinet SSL Deep Inspection"),
    ("barracuda",          "Barracuda Web Filter"),
    ("forcepoint",         "Forcepoint Web Security"),
    ("symantec web",       "Symantec/Blue Coat Web Proxy"),
    ("blue coat",          "Symantec/Blue Coat Web Proxy"),
    ("mcafee",             "McAfee Web Gateway"),
    ("sophos",             "Sophos Web Appliance"),
    ("contentkeeper",      "ContentKeeper"),
    ("netsweeper",         "Netsweeper"),
    ("smoothwall",         "Smoothwall Filter & Firewall"),
    ("untangle",           "Untangle NG Firewall"),
    ("mimecast",           "Mimecast Email / Web Security"),
    ("proofpoint",         "Proofpoint Web Security"),
    ("netskope",           "Netskope"),
    ("menlo security",     "Menlo Security"),
    ("cato networks",      "Cato Networks"),
]

# ── TLS Alert description codes ──────────────────────────────────────────────
ALERT_DESC: dict[int, str] = {
    0:   "close_notify",
    10:  "unexpected_message",
    20:  "bad_record_mac",
    40:  "handshake_failure",
    42:  "bad_certificate",
    43:  "unsupported_certificate",
    44:  "certificate_revoked",
    45:  "certificate_expired",
    46:  "certificate_unknown",
    47:  "illegal_parameter",
    48:  "unknown_ca",
    50:  "decode_error",
    51:  "decrypt_error",
    70:  "protocol_version",
    71:  "insufficient_security",
    80:  "internal_error",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    116: "unknown_psk_identity",
    119: "certificate_required",
    120: "no_application_protocol",
}

ALERT_SEVERITY: dict[int, str] = {
    40: "HIGH",   # handshake_failure
    42: "HIGH",   # bad_certificate
    43: "MEDIUM",
    44: "HIGH",   # certificate_revoked
    45: "HIGH",   # certificate_expired
    46: "HIGH",   # certificate_unknown
    48: "HIGH",   # unknown_ca  — common when filter's CA not trusted
    112: "MEDIUM", # unrecognized_name
}


# ── Raw TLS parsing helpers ───────────────────────────────────────────────────

def _parse_sni(payload: bytes) -> str | None:
    """Extract SNI hostname from a TLS ClientHello payload."""
    try:
        # TLS record: content_type(1) version(2) length(2)
        if len(payload) < 6 or payload[0] != 0x16:
            return None

        pos = 5  # start of handshake message
        if payload[pos] != 0x01:   # ClientHello type
            return None

        pos += 4  # skip type(1) + length(3)
        pos += 2  # client_version
        pos += 32  # random

        if pos >= len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack_from(">H", payload, pos)[0]
        pos += 2 + cs_len

        if pos >= len(payload):
            return None
        cm_len = payload[pos]
        pos += 1 + cm_len

        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack_from(">H", payload, pos)[0]
        pos += 2
        ext_end = min(pos + ext_total, len(payload))

        while pos + 4 <= ext_end:
            ext_type = struct.unpack_from(">H", payload, pos)[0]
            ext_len  = struct.unpack_from(">H", payload, pos + 2)[0]
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= ext_end:
                # server_name list: list_len(2) + name_type(1) + name_len(2) + name
                name_len = struct.unpack_from(">H", payload, pos + 3)[0]
                name_start = pos + 5
                if name_start + name_len <= ext_end:
                    return payload[name_start: name_start + name_len].decode(
                        "utf-8", errors="replace"
                    )
            pos += ext_len
    except Exception:
        pass
    return None


def _parse_certificate_info(payload: bytes) -> dict | None:
    """Extract CN and issuer from the first certificate in a TLS Certificate message."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        pos = 5
        if payload[pos] != 0x0B:   # Certificate handshake type
            return None

        # Handshake length: 3 bytes
        h_len = struct.unpack_from(">I", b"\x00" + payload[pos + 1: pos + 4])[0]
        pos += 4

        # Certificate list length: 3 bytes
        if pos + 3 > len(payload):
            return None
        cl_len = struct.unpack_from(">I", b"\x00" + payload[pos: pos + 3])[0]
        pos += 3

        # First certificate length: 3 bytes
        if pos + 3 > len(payload):
            return None
        cert_len = struct.unpack_from(">I", b"\x00" + payload[pos: pos + 3])[0]
        pos += 3

        cert_data = payload[pos: pos + cert_len]
        if len(cert_data) < 16:
            return None

        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(cert_data)

        def attr(name_obj, oid: Any) -> str:
            try:
                return name_obj.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                return ""

        # not_after compat: cryptography ≥42 uses not_valid_after_utc
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        return {
            "subject_cn": attr(cert.subject, NameOID.COMMON_NAME),
            "issuer_cn":  attr(cert.issuer,  NameOID.COMMON_NAME),
            "issuer_o":   attr(cert.issuer,  NameOID.ORGANIZATION_NAME),
            "not_after":  not_after.isoformat(),
            "expired":    now > not_after,
        }
    except Exception:
        return None


def _parse_tls_alert(payload: bytes) -> dict | None:
    """Extract TLS Alert record info."""
    try:
        # Alert record: type=21 (0x15), version(2), length(2), level(1), desc(1)
        if len(payload) < 7 or payload[0] != 0x15:
            return None
        level = payload[5]   # 1=warning, 2=fatal
        desc  = payload[6]
        if level != 2:       # only surface fatal alerts
            return None
        return {
            "level": "fatal",
            "description_code": desc,
            "description": ALERT_DESC.get(desc, f"alert_{desc}"),
        }
    except Exception:
        return None


def _match_filter(issuer_cn: str, issuer_o: str) -> str | None:
    combined = (issuer_cn + " " + issuer_o).lower()
    for sig, product in KNOWN_FILTERS:
        if sig in combined:
            return product
    return None


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_tls_inspection(packets: list) -> dict[str, Any]:
    """
    Returns:
        intercepted_connections  – connections where a known filter's cert was seen
        sni_cert_mismatches      – SNI vs cert CN mismatches (possible interception)
        tls_alerts               – fatal TLS alert messages
        summary                  – counts
    """
    # stream_key (normalized) → {sni, cert_info, src_ip, dst_ip, dst_port, ts}
    streams: dict[tuple, dict] = {}
    tls_alerts: list[dict] = []

    for pkt in packets:
        if "TCP" not in pkt or "IP" not in pkt or "Raw" not in pkt:
            continue

        ip  = pkt["IP"]
        tcp = pkt["TCP"]
        payload: bytes = bytes(pkt["Raw"])
        ts = float(pkt.time)

        if len(payload) < 6:
            continue

        dport = tcp.dport
        sport = tcp.sport

        # Only look at TLS ports in either direction
        if dport not in TLS_PORTS and sport not in TLS_PORTS:
            continue

        record_type = payload[0]

        # ── ClientHello (SNI) ─────────────────────────────────────────────────
        if record_type == 0x16:
            hs_type = payload[5] if len(payload) > 5 else 0

            if hs_type == 0x01:   # ClientHello
                sni = _parse_sni(payload)
                if sni:
                    # Normalise: client is always src here
                    key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    if key not in streams:
                        streams[key] = {
                            "src_ip":   ip.src,
                            "dst_ip":   ip.dst,
                            "dst_port": tcp.dport,
                            "ts":       ts,
                        }
                    streams[key]["sni"] = sni

            elif hs_type == 0x0B:  # Certificate
                cert_info = _parse_certificate_info(payload)
                if cert_info:
                    # Certificate comes server→client, so reverse the key
                    key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                    if key not in streams:
                        streams[key] = {
                            "src_ip":   ip.dst,
                            "dst_ip":   ip.src,
                            "dst_port": tcp.sport,
                            "ts":       ts,
                        }
                    streams[key]["cert"] = cert_info

        # ── TLS Alert ─────────────────────────────────────────────────────────
        elif record_type == 0x15:
            alert = _parse_tls_alert(payload)
            if alert:
                tls_alerts.append(
                    {
                        **alert,
                        "src_ip":   ip.src,
                        "dst_ip":   ip.dst,
                        "dst_port": tcp.dport,
                        "timestamp": ts,
                        "severity": ALERT_SEVERITY.get(alert["description_code"], "MEDIUM"),
                    }
                )

    # ── Correlate SNI + Certificate ───────────────────────────────────────────
    intercepted: list[dict] = []
    mismatches:  list[dict] = []

    for key, stream in streams.items():
        sni  = stream.get("sni")
        cert = stream.get("cert")

        if not cert:
            continue

        filter_product = _match_filter(
            cert.get("issuer_cn", ""), cert.get("issuer_o", "")
        )
        cert_cn = cert.get("subject_cn", "")

        if filter_product:
            intercepted.append(
                {
                    "src_ip":        stream["src_ip"],
                    "dst_ip":        stream["dst_ip"],
                    "dst_port":      stream["dst_port"],
                    "sni":           sni or "(unknown)",
                    "cert_cn":       cert_cn,
                    "issuer_cn":     cert.get("issuer_cn", ""),
                    "issuer_o":      cert.get("issuer_o", ""),
                    "filter_product": filter_product,
                    "cert_expired":  cert.get("expired", False),
                    "cert_not_after": cert.get("not_after", ""),
                    "timestamp":     stream["ts"],
                    "severity":      "INFO",
                }
            )
        elif sni and cert_cn and sni.lower() not in cert_cn.lower():
            # CN doesn't match SNI but not a known filter — possible unknown inspection
            mismatches.append(
                {
                    "src_ip":    stream["src_ip"],
                    "dst_ip":    stream["dst_ip"],
                    "dst_port":  stream["dst_port"],
                    "sni":       sni,
                    "cert_cn":   cert_cn,
                    "issuer_cn": cert.get("issuer_cn", ""),
                    "issuer_o":  cert.get("issuer_o", ""),
                    "cert_expired": cert.get("expired", False),
                    "timestamp": stream["ts"],
                    "severity":  "HIGH" if cert.get("expired") else "MEDIUM",
                }
            )

    # Deduplicate intercepted by filter_product (keep one representative per product)
    products_seen: set[str] = set()
    unique_intercepted: list[dict] = []
    for entry in sorted(intercepted, key=lambda x: x["timestamp"]):
        unique_intercepted.append(entry)
        products_seen.add(entry["filter_product"])

    return {
        "intercepted_connections": unique_intercepted[:200],
        "sni_cert_mismatches":     mismatches[:100],
        "tls_alerts":              tls_alerts[:200],
        "detected_filter_products": sorted(products_seen),
        "summary": {
            "intercepted_count":  len(unique_intercepted),
            "mismatch_count":     len(mismatches),
            "alert_count":        len(tls_alerts),
            "filter_products":    len(products_seen),
        },
    }
