"""
NTLM Hash Extractor
────────────────────
Parses NTLMSSP authentication exchanges from raw TCP streams.
Extracts server challenges and NTLMv2 response hashes formatted
for Hashcat (mode 5600) — giving defenders visibility into which
credentials are flying across the wire in cleartext-equivalent form.

Handles NTLM over:
  • HTTP  (Authorization: NTLM <base64>)
  • SMB / generic TCP payload search
"""
from __future__ import annotations

import base64
import binascii
import re
import struct
from collections import defaultdict
from typing import Any

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

HTTP_NTLM_HEADER = re.compile(
    rb"(?:Authorization|WWW-Authenticate):\s*NTLM\s+([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)


# ── Low-level NTLMSSP parsers ─────────────────────────────────────────────────

def _read_sec_buf(data: bytes, offset: int) -> bytes:
    """Read a Security Buffer structure (length, max-length, offset) → bytes."""
    try:
        length = struct.unpack_from("<H", data, offset)[0]
        buf_offset = struct.unpack_from("<I", data, offset + 4)[0]
        if buf_offset + length > len(data):
            return b""
        return data[buf_offset: buf_offset + length]
    except struct.error:
        return b""


def _parse_negotiate(data: bytes) -> dict | None:
    if len(data) < 32:
        return None
    flags = struct.unpack_from("<I", data, 12)[0]
    return {"type": "NEGOTIATE", "flags": hex(flags)}


def _parse_challenge(data: bytes) -> dict | None:
    """Type 2 — server → client."""
    if len(data) < 56:
        return None
    try:
        challenge_bytes = data[24:32]
        server_challenge = binascii.hexlify(challenge_bytes).decode()
        target_name_raw = _read_sec_buf(data, 12)
        target_name = target_name_raw.decode("utf-16-le", errors="replace")
    except Exception:
        return None

    return {
        "type": "CHALLENGE",
        "server_challenge": server_challenge,
        "target_name": target_name,
    }


def _parse_authenticate(data: bytes) -> dict | None:
    """Type 3 — client → server."""
    if len(data) < 72:
        return None
    try:
        nt_response = _read_sec_buf(data, 20)
        domain = _read_sec_buf(data, 28).decode("utf-16-le", errors="replace")
        username = _read_sec_buf(data, 36).decode("utf-16-le", errors="replace")
        workstation = _read_sec_buf(data, 44).decode("utf-16-le", errors="replace")
    except Exception:
        return None

    result: dict[str, Any] = {
        "type": "AUTHENTICATE",
        "domain": domain,
        "username": username,
        "workstation": workstation,
        "nt_response_hex": binascii.hexlify(nt_response).decode() if nt_response else "",
    }
    return result


def _extract_from_payload(payload: bytes) -> list[dict]:
    """Find all NTLMSSP blobs inside an arbitrary payload."""
    messages: list[dict] = []
    start = 0
    while True:
        idx = payload.find(NTLMSSP_SIGNATURE, start)
        if idx == -1:
            break
        blob = payload[idx:]
        if len(blob) < 12:
            break
        try:
            msg_type = struct.unpack_from("<I", blob, 8)[0]
        except struct.error:
            start = idx + 1
            continue

        parsed: dict | None = None
        if msg_type == 1:
            parsed = _parse_negotiate(blob)
        elif msg_type == 2:
            parsed = _parse_challenge(blob)
        elif msg_type == 3:
            parsed = _parse_authenticate(blob)

        if parsed:
            messages.append(parsed)
        start = idx + len(NTLMSSP_SIGNATURE)
    return messages


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_ntlm(packets: list) -> list[dict[str, Any]]:
    """
    Returns a list of NTLM exchanges with reconstructed Hashcat-ready hashes
    where possible.
    """
    # stream_key → list of NTLM message dicts (with metadata)
    streams: dict[tuple, list[dict]] = defaultdict(list)

    for pkt in packets:
        if "IP" not in pkt:
            continue
        ip = pkt["IP"]

        if "TCP" not in pkt:
            continue
        tcp = pkt["TCP"]

        if "Raw" not in pkt:
            # Check for HTTP NTLM header without Raw layer
            continue

        payload: bytes = bytes(pkt["Raw"])

        # Try HTTP NTLM header extraction first
        header_messages: list[dict] = []
        for m in HTTP_NTLM_HEADER.finditer(payload):
            try:
                decoded = base64.b64decode(m.group(1))
                if NTLMSSP_SIGNATURE in decoded:
                    header_messages.extend(_extract_from_payload(decoded))
            except Exception:
                pass

        raw_messages = _extract_from_payload(payload)
        all_messages = header_messages + raw_messages

        if not all_messages:
            continue

        # Normalise stream direction so challenge and authenticate messages
        # from opposite directions end up in the same stream bucket.
        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)
        stream_key = tuple(sorted([src, dst]))

        for msg in all_messages:
            msg["src_ip"] = ip.src
            msg["dst_ip"] = ip.dst
            msg["timestamp"] = float(pkt.time)
            streams[stream_key].append(msg)

    # ── Correlate challenges with authenticate messages ───────────────────────
    findings: list[dict] = []

    for stream_key, messages in streams.items():
        # Collect all server challenges seen in this stream
        challenges = [
            m["server_challenge"]
            for m in messages
            if m.get("type") == "CHALLENGE" and "server_challenge" in m
        ]
        server_challenge = challenges[0] if challenges else None

        for msg in messages:
            if msg.get("type") not in ("CHALLENGE", "AUTHENTICATE"):
                continue

            entry = {k: v for k, v in msg.items()}

            # Build Hashcat NTLMv2 hash (mode 5600) when possible
            if (
                msg.get("type") == "AUTHENTICATE"
                and server_challenge
                and msg.get("nt_response_hex")
            ):
                nt_resp = bytes.fromhex(msg["nt_response_hex"])
                if len(nt_resp) >= 24:
                    nt_proof = binascii.hexlify(nt_resp[:16]).decode()
                    blob = binascii.hexlify(nt_resp[16:]).decode()
                    user = msg.get("username", "")
                    domain = msg.get("domain", "")
                    entry["hashcat_hash"] = (
                        f"{user}::{domain}:{server_challenge}:{nt_proof}:{blob}"
                    )
                    entry["hashcat_mode"] = 5600
                    entry["severity"] = "CRITICAL"

            findings.append(entry)

    # Sort: authenticate messages (with hashes) first, then by timestamp
    findings.sort(
        key=lambda x: (0 if x.get("type") == "AUTHENTICATE" else 1, x.get("timestamp", 0))
    )
    return findings
