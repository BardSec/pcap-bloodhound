"""Investigation thread builder — groups findings by entity and generates narratives.

Runs after finding builders complete. Correlates findings across analyzers,
builds per-entity timelines from raw analyzer results, and generates
human-readable summaries for the investigation UI.
"""

from __future__ import annotations

from collections import defaultdict

from app.analysis.findings import Finding, InvestigationThread, TimelineEvent
from app.analysis.metadata import CaptureMetadata


def _build_timeline_events(
    entity: str,
    findings: list[Finding],
    result,
    metadata: CaptureMetadata,
) -> list[TimelineEvent]:
    """Build timeline events for an entity from raw analyzer data and findings.

    Pulls timestamps from raw results to construct a chronological event stream.
    """
    events: list[TimelineEvent] = []

    for finding in findings:
        # Add the finding itself as a detection event
        ts = finding.first_seen
        if ts is not None:
            events.append(TimelineEvent(
                timestamp=ts,
                event_type="detection",
                description=finding.title,
                source_analyzer=finding.analyzer,
                severity=finding.severity,
                details={"confidence": finding.confidence, "finding_id": finding.id},
            ))

    # Pull DNS events from dns_tunneling raw data if entity is a domain
    dns_data = getattr(result, "dns_tunneling", {})
    for query in dns_data.get("suspicious_queries", []):
        if entity in (query.get("base_domain", ""), query.get("qname", "")):
            events.append(TimelineEvent(
                timestamp=query["timestamp"],
                event_type="dns_query",
                description=f"Suspicious DNS query: {query.get('qname', '')[:60]}",
                source_analyzer="dns_tunneling",
                severity=query.get("severity", "MEDIUM"),
                details={"entropy": query.get("entropy"), "qtype": query.get("qtype")},
            ))

    # Pull beaconing connection timestamps if entity is an IP
    for beacon in getattr(result, "c2_beaconing", []):
        if entity in (beacon.get("src_ip"), beacon.get("dst_ip")):
            rel_ts = beacon.get("rel_timestamps", [])
            if rel_ts and len(rel_ts) > 1:
                # Add first and last beacon event (not every tick)
                events.append(TimelineEvent(
                    timestamp=rel_ts[0],
                    event_type="beacon_start",
                    description=(
                        f"Beaconing flow begins: {beacon['src_ip']} -> "
                        f"{beacon['dst_ip']}:{beacon['dst_port']} "
                        f"every {beacon.get('beacon_period_display', '?')}"
                    ),
                    source_analyzer="c2_beaconing",
                    severity=beacon.get("severity", "HIGH"),
                ))

    # Pull exfiltration flow events
    for exfil in getattr(result, "exfiltration", []):
        if entity in (exfil.get("src_ip"), exfil.get("dst_ip")):
            events.append(TimelineEvent(
                timestamp=0,  # Exfil doesn't store timestamps per-flow
                event_type="exfil_flow",
                description=(
                    f"Large outbound transfer: {exfil['outbound_mb']:.1f} MB to "
                    f"{exfil['dst_ip']}:{exfil['dst_port']}"
                ),
                source_analyzer="exfiltration",
                severity=exfil.get("severity", "HIGH"),
                details={"outbound_mb": exfil["outbound_mb"], "ratio": exfil["ratio"]},
            ))

    # Pull lateral movement events — scan patterns
    lat_data = getattr(result, "lateral_movement", {})
    for scan in lat_data.get("scan_patterns", []):
        if entity == scan.get("src_ip"):
            events.append(TimelineEvent(
                timestamp=0,
                event_type="lateral_scan",
                description=(
                    f"Scan: {entity} contacted {scan['unique_targets']} hosts "
                    f"on {scan['protocol']} (port {scan['dst_port']})"
                ),
                source_analyzer="lateral_movement",
                severity="CRITICAL",
            ))
        elif entity in scan.get("targets", []):
            events.append(TimelineEvent(
                timestamp=0,
                event_type="scan_target",
                description=f"Targeted by {scan['src_ip']} in {scan['protocol']} scan",
                source_analyzer="lateral_movement",
                severity="HIGH",
            ))

    # Pull lateral movement events — individual connections
    for conn in lat_data.get("lateral_connections", []):
        if entity in (conn.get("src_ip"), conn.get("dst_ip")):
            direction = "from" if entity == conn.get("dst_ip") else "to"
            peer = conn["dst_ip"] if entity == conn["src_ip"] else conn["src_ip"]
            events.append(TimelineEvent(
                timestamp=conn.get("timestamp", 0),
                event_type="lateral_movement",
                description=(
                    f"{conn['protocol']} connection {direction} {peer} "
                    f"(port {conn['dst_port']}, {conn['packets']} pkts)"
                ),
                source_analyzer="lateral_movement",
                severity=conn.get("severity", "HIGH"),
            ))

    # Pull suspicious user-agent events
    ua_data = getattr(result, "suspicious_useragents", {})
    for ua in ua_data.get("suspicious_agents", []):
        clients = ua.get("clients", [])
        if entity in clients:
            events.append(TimelineEvent(
                timestamp=ua.get("timestamp", 0),
                event_type="suspicious_useragent",
                description=(
                    f"Suspicious User-Agent: {ua.get('matched_tool', 'unknown')} "
                    f"({ua.get('category', '')}) — {ua.get('request_count', 0)} requests"
                ),
                source_analyzer="suspicious_useragents",
                severity=ua.get("severity", "MEDIUM"),
            ))

    # Pull DGA events
    dga_data = getattr(result, "dga_detection", {})
    for dga in dga_data.get("suspicious_domains", []):
        clients = dga.get("clients", [])
        domain = dga.get("domain", "")
        if entity in clients:
            events.append(TimelineEvent(
                timestamp=dga.get("timestamp", 0),
                event_type="dga_query",
                description=(
                    f"DGA-like domain query: {domain[:40]} "
                    f"(score {dga.get('dga_score', '?')}/14, entropy {dga.get('entropy', '?')})"
                ),
                source_analyzer="dga_detection",
                severity=dga.get("severity", "MEDIUM"),
            ))
        elif entity == domain:
            events.append(TimelineEvent(
                timestamp=dga.get("timestamp", 0),
                event_type="dga_domain",
                description=f"Domain flagged as DGA (score {dga.get('dga_score', '?')}/14)",
                source_analyzer="dga_detection",
                severity=dga.get("severity", "MEDIUM"),
            ))

    events.sort(key=lambda e: e.timestamp)
    return events


def _generate_summary(
    entity: str,
    entity_type: str,
    findings: list[Finding],
    metadata: CaptureMetadata,
) -> str:
    """Generate a human-readable narrative summary for a thread."""
    parts = []

    # Count by analyzer type
    analyzer_counts = defaultdict(int)
    for f in findings:
        analyzer_counts[f.analyzer] += 1

    # Lead with the strongest signal
    top_finding = max(findings, key=lambda f: f.confidence)

    if entity_type == "internal_host":
        profile = metadata.get_host(entity)
        if profile:
            parts.append(
                f"Internal host with {profile.packet_count} packets "
                f"and {len(profile.unique_external_dsts)} external destinations."
            )

        if "c2_beaconing" in analyzer_counts:
            parts.append(
                f"Shows periodic outbound connection patterns consistent with "
                f"possible C2 communication (confidence {top_finding.confidence}%)."
            )
        if "exfiltration" in analyzer_counts:
            exfil_findings = [f for f in findings if f.analyzer == "exfiltration"]
            total_mb = sum(f.raw_data.get("outbound_mb", 0) for f in exfil_findings)
            parts.append(f"Involved in {total_mb:.1f} MB of asymmetric outbound transfers.")
        if "dns_tunneling" in analyzer_counts:
            parts.append("Associated with domains showing DNS tunneling indicators.")
        if "lateral_movement" in analyzer_counts:
            parts.append("Involved in internal lateral movement activity.")
        if "dga_detection" in analyzer_counts:
            parts.append("Queried domains with characteristics of algorithmic generation.")
        if "suspicious_useragents" in analyzer_counts:
            parts.append("Generated HTTP traffic with non-browser or offensive tool User-Agents.")

    elif entity_type == "external_host":
        fanin = metadata.external_fanin(entity)
        parts.append(f"External endpoint contacted by {fanin} internal host(s).")

        if "c2_beaconing" in analyzer_counts:
            parts.append("Receives periodic connections with regular timing.")
        if "exfiltration" in analyzer_counts:
            parts.append("Destination for large asymmetric data transfers.")

    elif entity_type == "domain":
        hosts = metadata.domain_to_querying_hosts.get(entity, set())
        parts.append(f"Domain queried by {len(hosts)} internal host(s).")
        if "dns_tunneling" in analyzer_counts:
            parts.append("Query patterns suggest possible DNS-based data tunneling.")
        if "dga_detection" in analyzer_counts:
            parts.append("Domain name has characteristics of algorithmic generation (DGA).")

    if not parts:
        parts.append(f"Entity with {len(findings)} related finding(s).")

    return " ".join(parts)


def build_threads(
    findings: list[Finding],
    result,
    metadata: CaptureMetadata,
    min_findings: int = 1,
    min_confidence: int = 40,
) -> list[InvestigationThread]:
    """Build investigation threads by grouping findings around entities.

    A thread is created when an entity has at least `min_findings` findings
    with at least one having confidence >= `min_confidence`.
    """
    # Group findings by entity
    entity_findings: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for entity in finding.entities:
            entity_findings[entity].append(finding)

    threads = []
    seen_entities = set()

    for entity, e_findings in entity_findings.items():
        if entity in seen_entities:
            continue

        # Filter: need enough signals
        if len(e_findings) < min_findings:
            continue
        if not any(f.confidence >= min_confidence for f in e_findings):
            continue

        # Determine entity type
        profile = metadata.get_host(entity)
        if profile:
            entity_type = "internal_host" if profile.is_internal else "external_host"
        elif "." in entity and not entity.replace(".", "").isdigit():
            entity_type = "domain"
        else:
            entity_type = "unknown"

        # Deduplicate findings (same finding may appear via multiple entities)
        unique_findings = list({f.id: f for f in e_findings}.values())
        unique_findings.sort(key=lambda f: f.confidence, reverse=True)

        # Collect related entities
        related = set()
        for f in unique_findings:
            related.update(f.entities)
        related.discard(entity)

        # Build timeline
        timeline = _build_timeline_events(entity, unique_findings, result, metadata)

        # Generate narrative
        summary = _generate_summary(entity, entity_type, unique_findings, metadata)

        # Compute risk score
        risk_score = InvestigationThread.compute_risk_score(unique_findings)

        # Host metadata for the thread
        host_meta = {}
        if profile:
            host_meta = profile.to_summary()

        threads.append(InvestigationThread(
            entity=entity,
            entity_type=entity_type,
            summary=summary,
            risk_score=risk_score,
            findings=unique_findings,
            timeline=timeline,
            related_entities=sorted(related),
            metadata=host_meta,
        ))

        seen_entities.add(entity)

    # Sort by risk score descending
    threads.sort(key=lambda t: t.risk_score, reverse=True)
    return threads
