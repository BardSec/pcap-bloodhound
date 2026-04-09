"""Detect student PII exposure in cleartext network traffic (FERPA/COPPA)."""

import re
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw


# Student data field names commonly found in SIS platforms, APIs, and form POSTs
STUDENT_PII_FIELDS = [
    "student_id", "studentid", "student_number", "studentnumber",
    "student_name", "studentname", "first_name", "last_name",
    "firstname", "lastname", "date_of_birth", "dateofbirth",
    "dob", "birth_date", "birthdate", "grade_level", "gradelevel",
    "parent_email", "parentemail", "guardian_email", "guardianemail",
    "parent_name", "parentname", "guardian_name", "guardianname",
    "iep_status", "iepstatus", "special_ed", "specialed",
    "504_plan", "lunch_status", "lunchstatus", "free_reduced",
    "freereduced", "ethnicity", "race", "gender", "home_address",
    "homeaddress", "phone_number", "phonenumber", "emergency_contact",
    "enrollmentdate", "enrollment_date", "withdrawal",
]

# Regex patterns for structured PII
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
DOB_PATTERN = re.compile(r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b')
STUDENT_ID_PATTERN = re.compile(r'\b(?:student.?id|sid)["\s:=]+\d{4,10}\b', re.IGNORECASE)
STUDENT_EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z]+\d{2,6}@(?:students?\.|k12\.)', re.IGNORECASE
)

# Common SIS/EdTech API paths
SIS_API_PATTERNS = [
    "/api/v", "/oneroster/", "/students", "/enrollments",
    "/demographics", "/sis/", "/powerschool/", "/infinite_campus/",
    "/skyward/", "/aeries/", "/synergy/", "/aspen/",
    "/clever/", "/classlink/",
]

# Ports commonly used by SIS platforms (unencrypted)
SIS_CLEARTEXT_PORTS = {
    80, 8080, 8443, 8081, 3000, 5000,
}


def _is_private(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or a == 127)


def _mask_ssn(ssn):
    return f"***-**-{ssn[-4:]}"


def _classify_severity(pii_type):
    critical = {"ssn", "date_of_birth", "iep_status", "504_plan", "special_ed",
                "lunch_status", "free_reduced"}
    if pii_type in critical:
        return "CRITICAL"
    return "HIGH"


def analyze_student_data_exposure(packets):
    results = {
        "pii_exposures": [],
        "sis_cleartext_flows": [],
        "summary": {
            "total_pii_exposures": 0,
            "ssn_exposures": 0,
            "dob_exposures": 0,
            "student_id_exposures": 0,
            "student_email_exposures": 0,
            "field_name_exposures": 0,
            "sis_cleartext_flows": 0,
            "packets_scanned": 0,
        },
    }

    seen_pii = set()
    seen_sis = set()
    packets_with_payload = 0

    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(Raw):
            continue
        if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        ts = float(pkt.time)

        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
        else:
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport

        # Skip encrypted traffic (HTTPS on 443)
        if dport == 443 or sport == 443:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        packets_with_payload += 1
        payload_lower = payload.lower()

        # Check for SSNs in cleartext
        for match in SSN_PATTERN.finditer(payload):
            ssn = match.group()
            # Basic validation: not 000, 666, or 900-999 in area
            area = int(ssn[:3])
            if area in (0, 666) or area >= 900:
                continue
            key = ("ssn", src, dst, _mask_ssn(ssn))
            if key not in seen_pii:
                seen_pii.add(key)
                results["pii_exposures"].append({
                    "pii_type": "ssn",
                    "src_ip": src,
                    "dst_ip": dst,
                    "port": dport,
                    "value_masked": _mask_ssn(ssn),
                    "timestamp": ts,
                    "severity": "CRITICAL",
                })

        # Check for dates of birth
        for match in DOB_PATTERN.finditer(payload):
            # Only flag if near a student-related keyword
            start = max(0, match.start() - 80)
            context = payload_lower[start:match.end() + 20]
            if any(kw in context for kw in ("student", "dob", "birth", "child", "minor", "pupil")):
                key = ("dob", src, dst, match.group())
                if key not in seen_pii:
                    seen_pii.add(key)
                    results["pii_exposures"].append({
                        "pii_type": "date_of_birth",
                        "src_ip": src,
                        "dst_ip": dst,
                        "port": dport,
                        "value_masked": "**/**/****",
                        "context": "Near student-related keyword",
                        "timestamp": ts,
                        "severity": "CRITICAL",
                    })

        # Check for student IDs in structured data
        for match in STUDENT_ID_PATTERN.finditer(payload):
            key = ("sid", src, dst)
            if key not in seen_pii:
                seen_pii.add(key)
                results["pii_exposures"].append({
                    "pii_type": "student_id",
                    "src_ip": src,
                    "dst_ip": dst,
                    "port": dport,
                    "value_masked": "[student ID]",
                    "timestamp": ts,
                    "severity": "HIGH",
                })

        # Check for student email patterns in cleartext
        for match in STUDENT_EMAIL_PATTERN.finditer(payload):
            key = ("email", src, dst, match.group().split("@")[1])
            if key not in seen_pii:
                seen_pii.add(key)
                results["pii_exposures"].append({
                    "pii_type": "student_email",
                    "src_ip": src,
                    "dst_ip": dst,
                    "port": dport,
                    "value_masked": f"****@{match.group().split('@')[1]}",
                    "timestamp": ts,
                    "severity": "HIGH",
                })

        # Check for student PII field names in cleartext payloads
        for field in STUDENT_PII_FIELDS:
            if field in payload_lower:
                key = ("field", src, dst, field)
                if key not in seen_pii:
                    seen_pii.add(key)
                    results["pii_exposures"].append({
                        "pii_type": field,
                        "src_ip": src,
                        "dst_ip": dst,
                        "port": dport,
                        "value_masked": f"[{field} data present]",
                        "timestamp": ts,
                        "severity": _classify_severity(field),
                    })

        # Check for SIS/EdTech API traffic over cleartext
        for api_path in SIS_API_PATTERNS:
            if api_path in payload_lower:
                flow_key = (src, dst, dport, api_path)
                if flow_key not in seen_sis:
                    seen_sis.add(flow_key)
                    results["sis_cleartext_flows"].append({
                        "src_ip": src,
                        "dst_ip": dst,
                        "port": dport,
                        "api_pattern": api_path,
                        "timestamp": ts,
                        "severity": "CRITICAL",
                    })

    results["summary"]["packets_scanned"] = packets_with_payload
    results["summary"]["ssn_exposures"] = sum(
        1 for e in results["pii_exposures"] if e["pii_type"] == "ssn"
    )
    results["summary"]["dob_exposures"] = sum(
        1 for e in results["pii_exposures"] if e["pii_type"] == "date_of_birth"
    )
    results["summary"]["student_id_exposures"] = sum(
        1 for e in results["pii_exposures"] if e["pii_type"] == "student_id"
    )
    results["summary"]["student_email_exposures"] = sum(
        1 for e in results["pii_exposures"] if e["pii_type"] == "student_email"
    )
    results["summary"]["field_name_exposures"] = sum(
        1 for e in results["pii_exposures"]
        if e["pii_type"] not in ("ssn", "date_of_birth", "student_id", "student_email")
    )
    results["summary"]["total_pii_exposures"] = len(results["pii_exposures"])
    results["summary"]["sis_cleartext_flows"] = len(results["sis_cleartext_flows"])

    return results
