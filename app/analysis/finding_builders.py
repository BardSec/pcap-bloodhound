"""Finding builders — convert raw analyzer output into structured Findings.

Each builder reads an analyzer's raw results (as stored on CaptureResult) plus
capture metadata, and produces a list of Finding objects with indicator-based
confidence scoring, alternative explanations, and entity references.

Existing analyzers are untouched. This layer adds the evidence/confidence
structure on top of their output.
"""

from __future__ import annotations

from app.analysis.findings import Finding, Indicator
from app.analysis.metadata import CaptureMetadata


# ─── C2 Beaconing ────────────────────────────────────────────────────────────

def build_c2_findings(
    raw: list[dict],
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from c2_beaconing analyzer output."""
    findings = []

    for flow in raw:
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        port = flow["dst_port"]
        cv = flow["cv"]
        mean_iat = flow["mean_interval_sec"]
        count = flow["connection_count"]

        indicators = [
            Indicator(
                name="regular_timing",
                description="Connection intervals have low variance (coefficient of variation)",
                weight=0.30,
                met=cv < 0.15,
                value=round(cv, 4),
                threshold=0.15,
                detail=f"CV of {cv:.4f} — values below 0.15 suggest automated timing",
            ),
            Indicator(
                name="very_regular_timing",
                description="Timing variance is extremely low, consistent with implant heartbeats",
                weight=0.15,
                met=cv < 0.05,
                value=round(cv, 4),
                threshold=0.05,
                detail=f"CV of {cv:.4f} — below 0.05 is rare in human-driven traffic",
            ),
            Indicator(
                name="sufficient_sample_size",
                description="Enough connections to make a statistically meaningful assessment",
                weight=0.10,
                met=count >= 20,
                value=count,
                threshold=20,
                detail=f"{count} connections observed (need 20+ for high confidence)",
            ),
            Indicator(
                name="persistent_flow",
                description="Connection recurs over a sustained time period",
                weight=0.10,
                met=mean_iat * count > 1800,  # Total span > 30 min
                value=round(mean_iat * count / 60, 1),
                threshold=30,
                detail=f"Flow spans ~{mean_iat * count / 60:.0f} minutes",
            ),
            Indicator(
                name="sole_internal_contactor",
                description="Only one internal host communicates with this destination",
                weight=0.15,
                met=metadata.is_sole_contactor(src, dst),
                value=metadata.external_fanin(dst),
                threshold=1,
                detail=(
                    "This is the only internal host contacting this destination"
                    if metadata.is_sole_contactor(src, dst)
                    else f"{metadata.external_fanin(dst)} internal hosts contact this destination"
                ),
            ),
            Indicator(
                name="beacon_period_range",
                description="Beacon interval falls in a range typical of C2 implants (10s–24h)",
                weight=0.10,
                met=10 <= mean_iat <= 86400,
                value=round(mean_iat, 1),
                threshold="10–86400s",
                detail=f"Mean interval of {flow.get('beacon_period_display', f'{mean_iat:.1f}s')}",
            ),
        ]

        # Metadata-first: peer comparison for outbound bytes
        bytes_ratio = metadata.host_bytes_ratio(src)
        if bytes_ratio > 1:
            indicators.append(Indicator(
                name="above_average_outbound",
                description="Source host sends more data externally than the capture median",
                weight=0.10,
                met=bytes_ratio > 3.0,
                value=round(bytes_ratio, 1),
                threshold=3.0,
                detail=f"This host's outbound traffic is {bytes_ratio:.1f}x the capture median",
            ))

        confidence = Finding.compute_confidence(indicators)

        # Severity from confidence, not just CV
        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append(Finding(
            id=f"c2_beacon:{src}->{dst}:{port}",
            analyzer="c2_beaconing",
            title="Possible C2 beaconing",
            description=(
                f"{src} connects to {dst}:{port} every "
                f"{flow.get('beacon_period_display', f'{mean_iat:.1f}s')} "
                f"with very regular timing (CV {cv:.4f})"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=[src, dst],
            entity_roles={src: "source_host", dst: "destination"},
            alternative_explanations=[
                "Periodic health checks, heartbeat monitors, or keep-alive mechanisms produce similar timing patterns",
                "NTP synchronization, update checkers, and telemetry clients often beacon at fixed intervals",
                "CDN or API polling from desktop applications can appear highly regular",
            ],
            first_seen=flow.get("rel_timestamps", [None])[0],
            raw_data=flow,
        ))

    return findings


# ─── DNS Tunneling ────────────────────────────────────────────────────────────

def build_dns_tunnel_findings(
    raw: dict,
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from dns_tunneling analyzer output."""
    findings = []

    for domain_data in raw.get("tunnel_domains", []):
        domain = domain_data["domain"]
        query_count = domain_data["query_count"]
        high_ent = domain_data["high_entropy_queries"]
        long_label = domain_data["long_label_queries"]
        susp_qtype = domain_data["suspicious_qtype_queries"]
        exfil_kb = domain_data["estimated_exfil_kb"]

        indicators = [
            Indicator(
                name="high_entropy_subdomains",
                description="Subdomains have high Shannon entropy, suggesting encoded data",
                weight=0.30,
                met=high_ent > 0,
                value=high_ent,
                threshold=1,
                detail=f"{high_ent} queries with subdomain entropy above 3.8 bits",
            ),
            Indicator(
                name="long_subdomain_labels",
                description="Subdomain labels are unusually long, consistent with data encoding",
                weight=0.20,
                met=long_label > 0,
                value=long_label,
                threshold=1,
                detail=f"{long_label} queries with labels exceeding 50 characters",
            ),
            Indicator(
                name="suspicious_record_types",
                description="Queries use record types favored by tunneling tools (TXT, NULL, CNAME, ANY)",
                weight=0.15,
                met=susp_qtype > 0,
                value=susp_qtype,
                threshold=1,
                detail=f"{susp_qtype} queries using suspicious record types: {', '.join(domain_data.get('record_types', {}).keys())}",
            ),
            Indicator(
                name="high_query_volume",
                description="Unusually high number of queries to a single domain",
                weight=0.15,
                met=query_count > 50,
                value=query_count,
                threshold=50,
                detail=f"{query_count} queries to {domain}",
            ),
            Indicator(
                name="significant_estimated_exfil",
                description="Estimated data volume in subdomain labels suggests deliberate exfiltration",
                weight=0.20,
                met=exfil_kb > 10,
                value=round(exfil_kb, 1),
                threshold=10,
                detail=f"~{exfil_kb:.1f} KB estimated data encoded in subdomain labels",
            ),
        ]

        # Metadata-first: check if querying host has unusually high DNS volume
        querying_hosts = list(metadata.domain_to_querying_hosts.get(domain, set()))
        for host in querying_hosts[:3]:  # Check top querying hosts
            dns_ratio = metadata.host_dns_ratio(host)
            if dns_ratio > 1:
                indicators.append(Indicator(
                    name="elevated_dns_volume",
                    description=f"{host} generates more DNS queries than peers",
                    weight=0.10,
                    met=dns_ratio > 3.0,
                    value=round(dns_ratio, 1),
                    threshold=3.0,
                    detail=f"{host} sends {dns_ratio:.1f}x the median DNS query volume",
                ))
                break  # Only add one peer-comparison indicator

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        entities = [domain] + querying_hosts[:5]

        findings.append(Finding(
            id=f"dns_tunnel:{domain}",
            analyzer="dns_tunneling",
            title="Possible DNS tunneling",
            description=(
                f"Domain {domain} shows signs of DNS-based data exfiltration: "
                f"{high_ent} high-entropy queries, {long_label} long labels, "
                f"~{exfil_kb:.1f} KB estimated data"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=entities,
            entity_roles={domain: "tunnel_domain", **{h: "querying_host" for h in querying_hosts[:5]}},
            alternative_explanations=[
                "CDN hostnames and cloud service subdomains often have high entropy (e.g., content hashes)",
                "DKIM, SPF, and DMARC records legitimately use long TXT record queries",
                "Some email security and anti-spam products generate high-entropy DNS lookups",
            ],
            raw_data=domain_data,
        ))

    return findings


# ─── Exfiltration ─────────────────────────────────────────────────────────────

def build_exfil_findings(
    raw: list[dict],
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from exfiltration analyzer output."""
    findings = []

    for flow in raw:
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        port = flow["dst_port"]
        outbound_mb = flow["outbound_mb"]
        outbound_bytes = flow["outbound_bytes"]
        ratio = flow["ratio"]
        duration = flow["duration_sec"]
        bandwidth = flow["bandwidth_kbps"]

        indicators = [
            Indicator(
                name="large_outbound_volume",
                description="Significant amount of data sent to an external destination",
                weight=0.25,
                met=outbound_bytes >= 1_000_000,
                value=round(outbound_mb, 2),
                threshold="1 MB",
                detail=f"{outbound_mb:.2f} MB sent outbound",
            ),
            Indicator(
                name="very_large_volume",
                description="Data volume exceeds 10 MB, a strong exfiltration signal",
                weight=0.10,
                met=outbound_bytes >= 10_000_000,
                value=round(outbound_mb, 2),
                threshold="10 MB",
                detail=f"{outbound_mb:.2f} MB is well above typical flow sizes",
            ),
            Indicator(
                name="high_asymmetry",
                description="Traffic is heavily asymmetric — much more sent than received",
                weight=0.25,
                met=ratio >= 5.0,
                value=round(ratio, 1),
                threshold="5:1",
                detail=f"Send/receive ratio of {ratio:.1f}:1",
            ),
            Indicator(
                name="extreme_asymmetry",
                description="Traffic ratio is extremely one-sided",
                weight=0.10,
                met=ratio >= 20.0,
                value=round(ratio, 1),
                threshold="20:1",
                detail=f"Ratio of {ratio:.1f}:1 far exceeds typical interactive traffic",
            ),
            Indicator(
                name="sustained_transfer",
                description="Transfer persists over a meaningful time period",
                weight=0.15,
                met=duration > 60,
                value=round(duration, 1),
                threshold="60s",
                detail=f"Transfer lasted {duration:.0f} seconds",
            ),
            Indicator(
                name="high_bandwidth",
                description="Transfer rate is elevated, suggesting bulk data movement",
                weight=0.10,
                met=bandwidth > 100,
                value=round(bandwidth, 1),
                threshold="100 KB/s",
                detail=f"Average bandwidth of {bandwidth:.1f} KB/s",
            ),
        ]

        # Metadata-first: is this host an outlier in outbound traffic?
        bytes_ratio = metadata.host_bytes_ratio(src)
        indicators.append(Indicator(
            name="outbound_outlier",
            description="Source host's outbound traffic volume is unusual relative to peers",
            weight=0.10,
            met=bytes_ratio > 5.0,
            value=round(bytes_ratio, 1),
            threshold=5.0,
            detail=(
                f"This host sends {bytes_ratio:.1f}x the capture median outbound bytes"
                if bytes_ratio > 1 else "Outbound volume is within normal range for this capture"
            ),
        ))

        # Metadata-first: sole contactor check
        sole = metadata.is_sole_contactor(src, dst)
        if sole:
            indicators.append(Indicator(
                name="unique_destination",
                description="No other internal host communicates with this external IP",
                weight=0.10,
                met=True,
                value=1,
                threshold=1,
                detail="This is the only internal host sending data to this destination",
            ))

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        findings.append(Finding(
            id=f"exfil:{src}->{dst}:{port}",
            analyzer="exfiltration",
            title="Possible data exfiltration",
            description=(
                f"{src} sent {outbound_mb:.2f} MB to {dst}:{port} "
                f"with a {ratio:.0f}:1 send/receive ratio over {duration:.0f}s"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=[src, dst],
            entity_roles={src: "source_host", dst: "destination"},
            alternative_explanations=[
                "Cloud backup, file sync, and video uploads produce large asymmetric outbound flows",
                "Software distribution from internal mirrors to external CDNs",
                "Large email attachments or file-sharing uploads",
            ],
            raw_data=flow,
        ))

    return findings


# ─── DGA Detection ────────────────────────────────────────────────────────────

def build_dga_findings(
    raw: dict,
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from dga_detection analyzer output."""
    findings = []

    for domain_data in raw.get("suspicious_domains", []):
        domain = domain_data["domain"]
        sld = domain_data["sld"]
        dga_score = domain_data["dga_score"]
        entropy = domain_data["entropy"]
        consonant_ratio = domain_data["consonant_ratio"]
        query_count = domain_data["query_count"]
        clients = domain_data.get("clients", [])

        indicators = [
            Indicator(
                name="high_dga_score",
                description="Domain scores high on multi-factor DGA heuristics",
                weight=0.30,
                met=dga_score >= 7,
                value=dga_score,
                threshold=7,
                detail=f"Composite DGA score of {dga_score}/14",
            ),
            Indicator(
                name="elevated_dga_score",
                description="Domain exceeds the minimum DGA detection threshold",
                weight=0.15,
                met=dga_score >= 4,
                value=dga_score,
                threshold=4,
                detail=f"Score of {dga_score} (minimum detection threshold is 4)",
            ),
            Indicator(
                name="high_entropy",
                description="Domain label has high Shannon entropy, suggesting random generation",
                weight=0.20,
                met=entropy > 3.5,
                value=round(entropy, 2),
                threshold=3.5,
                detail=f"Entropy of {entropy:.2f} bits (normal domains are typically 2.5–3.2)",
            ),
            Indicator(
                name="high_consonant_ratio",
                description="Domain has an unusual ratio of consonants, unlike natural language",
                weight=0.15,
                met=consonant_ratio > 0.65,
                value=round(consonant_ratio, 2),
                threshold=0.65,
                detail=f"Consonant ratio of {consonant_ratio:.2f} (English words average ~0.55)",
            ),
            Indicator(
                name="multiple_queries",
                description="Domain was queried multiple times, suggesting active use",
                weight=0.10,
                met=query_count >= 3,
                value=query_count,
                threshold=3,
                detail=f"Queried {query_count} time{'s' if query_count != 1 else ''}",
            ),
            Indicator(
                name="single_client",
                description="Only one host queries this domain, consistent with malware on a single endpoint",
                weight=0.10,
                met=len(clients) == 1,
                value=len(clients),
                threshold=1,
                detail=(
                    f"Queried by a single host ({clients[0]})"
                    if len(clients) == 1
                    else f"Queried by {len(clients)} hosts"
                ),
            ),
        ]

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        entities = [domain] + clients[:5]

        findings.append(Finding(
            id=f"dga:{domain}",
            analyzer="dga_detection",
            title="Possible algorithmically generated domain",
            description=(
                f"Domain \"{sld}\" has characteristics of DGA output: "
                f"entropy {entropy:.2f}, consonant ratio {consonant_ratio:.2f}, "
                f"score {dga_score}/14"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=entities,
            entity_roles={domain: "dga_domain", **{c: "querying_host" for c in clients[:5]}},
            alternative_explanations=[
                "Legitimate services sometimes use hash-based or random-looking subdomains (e.g., CDN cache keys)",
                "URL shorteners and link-tracking services often resolve to random-looking domains",
                "Internationalized domain names transliterated to ASCII can appear random",
            ],
            first_seen=domain_data.get("timestamp"),
            raw_data=domain_data,
        ))

    return findings


# ─── Lateral Movement ─────────────────────────────────────────────────────────

def build_lateral_movement_findings(
    raw: dict,
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from lateral_movement analyzer output."""
    findings = []

    # Build findings from scan patterns (highest signal)
    for scan in raw.get("scan_patterns", []):
        src = scan["src_ip"]
        port = scan["dst_port"]
        protocol = scan["protocol"]
        targets = scan.get("targets", [])
        unique_targets = scan["unique_targets"]

        indicators = [
            Indicator(
                name="multi_target_scan",
                description="Single host contacting many internal peers on the same service port",
                weight=0.35,
                met=unique_targets >= 5,
                value=unique_targets,
                threshold=5,
                detail=f"Contacted {unique_targets} internal hosts on {protocol} (port {port})",
            ),
            Indicator(
                name="wide_scan",
                description="Target count suggests systematic network enumeration",
                weight=0.15,
                met=unique_targets >= 10,
                value=unique_targets,
                threshold=10,
                detail=f"{unique_targets} targets exceeds typical administrative access patterns",
            ),
            Indicator(
                name="sensitive_protocol",
                description="Protocol is commonly exploited for lateral movement",
                weight=0.25,
                met=protocol in ("SMB", "WinRM", "WinRM HTTPS", "DCOM/WMI", "RDP"),
                value=protocol,
                threshold="SMB, WinRM, DCOM, RDP",
                detail=f"{protocol} is frequently used in post-exploitation lateral movement",
            ),
            Indicator(
                name="high_risk_protocol",
                description="WinRM or DCOM indicate likely remote execution capability",
                weight=0.15,
                met=protocol in ("WinRM", "WinRM HTTPS", "DCOM/WMI"),
                value=protocol,
                threshold="WinRM, DCOM",
                detail=f"{protocol} enables remote code execution",
            ),
        ]

        # Metadata-first: is this host unusually active internally?
        profile = metadata.get_host(src)
        if profile:
            peer_count = len(profile.unique_internal_peers)
            indicators.append(Indicator(
                name="high_internal_fanout",
                description="Source host communicates with an unusually high number of internal peers",
                weight=0.10,
                met=peer_count >= 10,
                value=peer_count,
                threshold=10,
                detail=f"This host has contacted {peer_count} internal peers in this capture",
            ))

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        entities = [src] + targets[:10]

        findings.append(Finding(
            id=f"lateral_scan:{src}:{port}",
            analyzer="lateral_movement",
            title=f"Possible lateral movement scan ({protocol})",
            description=(
                f"{src} contacted {unique_targets} internal hosts on {protocol} "
                f"(port {port}), suggesting network enumeration or mass exploitation"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=entities,
            entity_roles={src: "scanner", **{t: "scan_target" for t in targets[:10]}},
            alternative_explanations=[
                "IT management tools (SCCM, PDQ Deploy, Ansible) routinely connect to many hosts via SMB/WinRM",
                "Vulnerability scanners and inventory tools during authorized assessments",
                "Network monitoring agents checking service availability across hosts",
            ],
            first_seen=None,
            raw_data=scan,
        ))

    # Build findings from individual high-severity lateral connections (no scan pattern)
    scan_srcs = {s["src_ip"] for s in raw.get("scan_patterns", [])}
    for conn in raw.get("lateral_connections", []):
        src = conn["src_ip"]
        if src in scan_srcs:
            continue  # Already covered by scan pattern finding

        protocol = conn["protocol"]
        if protocol not in ("WinRM", "WinRM HTTPS", "DCOM/WMI"):
            continue  # Only build findings for highest-risk individual connections

        dst = conn["dst_ip"]
        port = conn["dst_port"]

        indicators = [
            Indicator(
                name="sensitive_protocol",
                description="Protocol enables remote code execution",
                weight=0.40,
                met=True,
                value=protocol,
                threshold="WinRM, DCOM",
                detail=f"{protocol} on port {port} is a high-risk lateral movement vector",
            ),
            Indicator(
                name="significant_traffic",
                description="Connection has enough traffic to suggest active use, not just a probe",
                weight=0.25,
                met=conn["packets"] > 10,
                value=conn["packets"],
                threshold=10,
                detail=f"{conn['packets']} packets and {conn['bytes']} bytes exchanged",
            ),
            Indicator(
                name="sustained_connection",
                description="Connection persists beyond a quick probe",
                weight=0.20,
                met=conn["duration_sec"] > 5,
                value=round(conn["duration_sec"], 1),
                threshold="5s",
                detail=f"Connection lasted {conn['duration_sec']:.1f}s",
            ),
        ]

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        findings.append(Finding(
            id=f"lateral_conn:{src}->{dst}:{port}",
            analyzer="lateral_movement",
            title=f"Possible lateral movement ({protocol})",
            description=(
                f"{src} connected to {dst} via {protocol} (port {port}) — "
                f"{conn['packets']} packets over {conn['duration_sec']:.1f}s"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=[src, dst],
            entity_roles={src: "source_host", dst: "target_host"},
            alternative_explanations=[
                "Remote administration tools (RSAT, PowerShell remoting) used by IT staff",
                "Automated deployment or configuration management systems",
            ],
            first_seen=conn.get("timestamp"),
            raw_data=conn,
        ))

    return findings


# ─── Suspicious User-Agents ──────────────────────────────────────────────────

def build_useragent_findings(
    raw: dict,
    metadata: CaptureMetadata,
) -> list[Finding]:
    """Build findings from suspicious_useragents analyzer output."""
    findings = []

    for agent in raw.get("suspicious_agents", []):
        ua = agent["user_agent"]
        tool = agent["matched_tool"]
        category = agent["category"]
        request_count = agent["request_count"]
        clients = agent.get("clients", [])
        unique_dsts = agent.get("unique_destinations", 0)

        # Build indicators based on what category this tool falls into.
        # Only include the category indicator that applies, so confidence
        # isn't diluted by mutually exclusive unmet categories.
        indicators = []

        if category in ("c2", "attack", "pentesting"):
            indicators.append(Indicator(
                name="known_offensive_tool",
                description="User-Agent matches a known offensive or exploitation tool",
                weight=0.45,
                met=True,
                value=tool,
                threshold="C2/attack/pentesting tools",
                detail=f"Matched: {tool} (category: {category})",
            ))
        elif category == "scanning":
            indicators.append(Indicator(
                name="scanning_tool",
                description="User-Agent matches a known scanning or enumeration tool",
                weight=0.35,
                met=True,
                value=tool,
                threshold="scanning tools",
                detail=f"Matched: {tool}",
            ))
        else:
            indicators.append(Indicator(
                name="scripting_library",
                description="User-Agent is a scripting/automation library rather than a browser",
                weight=0.25,
                met=True,
                value=tool,
                threshold="scripting libraries",
                detail=f"Matched: {tool} — not a standard browser",
            ))

        indicators.extend([
            Indicator(
                name="high_request_volume",
                description="Tool made a significant number of requests",
                weight=0.25,
                met=request_count >= 10,
                value=request_count,
                threshold=10,
                detail=f"{request_count} HTTP requests with this User-Agent",
            ),
            Indicator(
                name="multiple_destinations",
                description="Tool contacted many different destinations, suggesting scanning",
                weight=0.20,
                met=unique_dsts >= 5,
                value=unique_dsts,
                threshold=5,
                detail=f"Requests sent to {unique_dsts} unique destination(s)",
            ),
            Indicator(
                name="single_client",
                description="Traffic from a single host, consistent with a compromised endpoint",
                weight=0.10,
                met=len(clients) == 1,
                value=len(clients),
                threshold=1,
                detail=(
                    f"All requests from a single host ({clients[0]})"
                    if len(clients) == 1
                    else f"Requests from {len(clients)} hosts"
                ),
            ),
        ])

        confidence = Finding.compute_confidence(indicators)

        if confidence >= 80:
            severity = "CRITICAL"
        elif confidence >= 60:
            severity = "HIGH"
        elif confidence >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        entities = clients[:5]
        truncated_ua = ua[:80] + ("..." if len(ua) > 80 else "")

        findings.append(Finding(
            id=f"useragent:{tool}:{','.join(clients[:3])}",
            analyzer="suspicious_useragents",
            title=f"Suspicious User-Agent: {tool}",
            description=(
                f"HTTP traffic using {tool} ({category}) detected from "
                f"{len(clients)} host(s) — {request_count} requests to "
                f"{unique_dsts} destination(s)"
            ),
            confidence=confidence,
            severity=severity,
            indicators=indicators,
            entities=entities,
            entity_roles={c: "client_host" for c in clients[:5]},
            alternative_explanations=[
                "Scripting libraries (python-requests, curl) are used in legitimate automation and monitoring",
                "Internal health-check and API integration scripts often use non-browser User-Agents",
                "Security teams may run authorized scans that produce these signatures",
            ],
            first_seen=agent.get("timestamp"),
            raw_data=agent,
        ))

    return findings


# ─── Registry ────────────────────────────────────────────────────────────────

# Maps analyzer attr name -> (builder_function, raw_data_type)
# raw_data_type: "list" or "dict" — how the analyzer stores results on CaptureResult
FINDING_BUILDERS: dict[str, tuple] = {
    "c2_beaconing": (build_c2_findings, "list"),
    "dns_tunneling": (build_dns_tunnel_findings, "dict"),
    "exfiltration": (build_exfil_findings, "list"),
    "dga_detection": (build_dga_findings, "dict"),
    "lateral_movement": (build_lateral_movement_findings, "dict"),
    "suspicious_useragents": (build_useragent_findings, "dict"),
}


def build_all_findings(result, metadata: CaptureMetadata) -> list[Finding]:
    """Run all registered finding builders against a CaptureResult."""
    all_findings = []

    for attr_name, (builder_fn, _) in FINDING_BUILDERS.items():
        raw = getattr(result, attr_name, None)
        if not raw:
            continue
        try:
            findings = builder_fn(raw, metadata)
            all_findings.extend(findings)
        except Exception:
            pass  # Don't let a builder failure break the pipeline

    return all_findings
