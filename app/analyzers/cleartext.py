"""
Cleartext Credential Detector
──────────────────────────────
Scans packet payloads for credentials transmitted in the clear across:

  • HTTP Basic Auth   (base64-decoded on the spot)
  • HTTP Form POST    (password= field patterns)
  • FTP               (USER / PASS commands)
  • SMTP AUTH LOGIN   (base64-encoded username + password challenge/response)

Credentials are masked in the returned `password_masked` field.
The raw value is available in `password_raw` for incident-response JSON export.
"""
from __future__ import annotations

import base64
import re
from typing import Any


# ── Port sets ────────────────────────────────────────────────────────────────
HTTP_PORTS = {80, 8080, 8000, 8008, 3000, 5000, 8888}
FTP_PORTS = {21}
SMTP_PORTS = {25, 465, 587, 2525}

# ── Regex patterns ────────────────────────────────────────────────────────────
RE_BASIC_AUTH = re.compile(
    rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE
)
# Match common password field names in POST bodies / query strings
RE_PASS_FIELD = re.compile(
    rb"(?:password|passwd|pass|pwd|secret|credential|token)"
    rb"[=]([^&\r\n\"'<>\x00]{1,256})",
    re.IGNORECASE,
)
RE_FTP_USER = re.compile(rb"^USER\s+(.+?)\r?$", re.IGNORECASE | re.MULTILINE)
RE_FTP_PASS = re.compile(rb"^PASS\s+(.+?)\r?$", re.IGNORECASE | re.MULTILINE)
# SMTP 334 challenge response lines (base64 encoded username/password)
RE_SMTP_334 = re.compile(rb"^334\s+([A-Za-z0-9+/=]+)\r?$", re.MULTILINE)
# AUTH LOGIN command
RE_SMTP_AUTH = re.compile(rb"AUTH\s+LOGIN", re.IGNORECASE)


def _mask(value: str) -> str:
    """Show first 2 and last 2 characters; mask the rest."""
    if len(value) <= 5:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _safe_decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip()


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_cleartext_credentials(packets: list) -> list[dict[str, Any]]:
    """
    Returns a list of cleartext credential findings sorted by severity then timestamp.
    """
    findings: list[dict] = []

    # Track stateful FTP / SMTP sessions per stream
    ftp_user_map: dict[tuple, str] = {}
    smtp_state: dict[tuple, dict] = {}  # key → {step, user}

    for pkt in packets:
        if "TCP" not in pkt or "Raw" not in pkt:
            continue
        if "IP" not in pkt:
            continue

        ip = pkt["IP"]
        tcp = pkt["TCP"]
        src_ip: str = ip.src
        dst_ip: str = ip.dst
        dport: int = tcp.dport
        sport: int = tcp.sport
        ts: float = float(pkt.time)
        payload: bytes = bytes(pkt["Raw"])

        stream_key = (src_ip, sport, dst_ip, dport)

        # ── HTTP Basic Auth ───────────────────────────────────────────────────
        if dport in HTTP_PORTS or sport in HTTP_PORTS:
            for m in RE_BASIC_AUTH.finditer(payload):
                try:
                    decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                    if ":" in decoded:
                        user, _, password = decoded.partition(":")
                        user = user.strip()
                        password = password.strip()
                        if user and password:
                            findings.append(
                                {
                                    "type": "HTTP_BASIC_AUTH",
                                    "protocol": "HTTP",
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_port": dport,
                                    "username": user,
                                    "password_masked": _mask(password),
                                    "password_raw": password,
                                    "timestamp": ts,
                                    "severity": "HIGH",
                                }
                            )
                except Exception:
                    pass

            # ── HTTP Form POST password fields ────────────────────────────────
            if b"POST" in payload[:8] or b"password" in payload.lower():
                for m in RE_PASS_FIELD.finditer(payload):
                    val = _safe_decode(m.group(1))
                    # Filter out templating artifacts and obviously non-passwords
                    if val and len(val) >= 3 and not val.startswith("{") and "\n" not in val:
                        field_name = m.group(0).split(b"=")[0].decode("utf-8", errors="replace")
                        findings.append(
                            {
                                "type": "HTTP_FORM_POST",
                                "protocol": "HTTP",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dport,
                                "field": field_name,
                                "username": "(from form)",
                                "password_masked": _mask(val),
                                "password_raw": val,
                                "timestamp": ts,
                                "severity": "HIGH",
                            }
                        )

        # ── FTP ───────────────────────────────────────────────────────────────
        if dport in FTP_PORTS:
            user_m = RE_FTP_USER.search(payload)
            pass_m = RE_FTP_PASS.search(payload)

            if user_m:
                ftp_user_map[stream_key] = _safe_decode(user_m.group(1))

            if pass_m:
                username = ftp_user_map.pop(stream_key, "unknown")
                password = _safe_decode(pass_m.group(1))
                findings.append(
                    {
                        "type": "FTP_CREDENTIALS",
                        "protocol": "FTP",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dport,
                        "username": username,
                        "password_masked": _mask(password),
                        "password_raw": password,
                        "timestamp": ts,
                        "severity": "CRITICAL",
                    }
                )

        # ── SMTP AUTH LOGIN ───────────────────────────────────────────────────
        if dport in SMTP_PORTS or sport in SMTP_PORTS:
            if RE_SMTP_AUTH.search(payload):
                smtp_state[stream_key] = {"step": "user", "user": ""}

            elif stream_key in smtp_state:
                for m in RE_SMTP_334.finditer(payload):
                    try:
                        decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace").strip()
                        state = smtp_state[stream_key]
                        if state["step"] == "user":
                            state["user"] = decoded
                            state["step"] = "password"
                        elif state["step"] == "password":
                            findings.append(
                                {
                                    "type": "SMTP_AUTH_LOGIN",
                                    "protocol": "SMTP",
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_port": dport,
                                    "username": state["user"],
                                    "password_masked": _mask(decoded),
                                    "password_raw": decoded,
                                    "timestamp": ts,
                                    "severity": "HIGH",
                                }
                            )
                            del smtp_state[stream_key]
                    except Exception:
                        pass

    # Sort: CRITICAL first, then by timestamp
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 9), x["timestamp"]))
    return findings
