"""Metadata extraction layer for capture-relative baselining and entity profiling.

Runs once per capture after packet loading, before finding builders. Provides
per-host stats, DNS baselines, flow relationships, and outlier context that
finding builders use to add peer-comparison indicators.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any


def _is_private(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    a = parts[0]
    if a == 10:
        return True
    if a == 172 and 16 <= parts[1] <= 31:
        return True
    if a == 192 and parts[1] == 168:
        return True
    if a == 127:
        return True
    if a == 169 and parts[1] == 254:
        return True
    return False


@dataclass
class HostProfile:
    """Per-host metadata derived from packet-level analysis."""
    ip: str
    is_internal: bool
    packet_count: int = 0
    bytes_total: int = 0
    bytes_outbound: int = 0         # Sent to external hosts
    bytes_inbound: int = 0          # Received from external hosts
    unique_external_dsts: set = field(default_factory=set)
    unique_internal_peers: set = field(default_factory=set)
    dns_query_count: int = 0
    dns_unique_domains: set = field(default_factory=set)
    dns_entropy_values: list = field(default_factory=list)
    protocols_used: set = field(default_factory=set)    # "TCP", "UDP", "ICMP"
    ports_contacted: set = field(default_factory=set)   # Destination ports
    first_seen: float | None = None
    last_seen: float | None = None

    def to_summary(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "is_internal": self.is_internal,
            "packets": self.packet_count,
            "bytes": self.bytes_total,
            "bytes_outbound": self.bytes_outbound,
            "bytes_inbound": self.bytes_inbound,
            "external_destinations": len(self.unique_external_dsts),
            "internal_peers": len(self.unique_internal_peers),
            "dns_queries": self.dns_query_count,
            "unique_domains": len(self.dns_unique_domains),
            "protocols": sorted(self.protocols_used),
        }


@dataclass
class CaptureMetadata:
    """Capture-wide metadata and baselines for peer comparison."""
    host_profiles: dict[str, HostProfile] = field(default_factory=dict)

    # Capture-level baselines (medians across internal hosts)
    median_packets_per_host: float = 0
    median_bytes_per_host: float = 0
    median_dns_queries_per_host: float = 0
    median_external_dsts_per_host: float = 0

    # Relationship maps
    external_ip_to_internal_hosts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    domain_to_querying_hosts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def get_host(self, ip: str) -> HostProfile | None:
        return self.host_profiles.get(ip)

    def external_fanin(self, external_ip: str) -> int:
        """How many internal hosts contact this external IP."""
        return len(self.external_ip_to_internal_hosts.get(external_ip, set()))

    def host_dns_ratio(self, ip: str) -> float:
        """Ratio of this host's DNS queries vs. capture median. >1 means above average."""
        profile = self.host_profiles.get(ip)
        if not profile or self.median_dns_queries_per_host == 0:
            return 1.0
        return profile.dns_query_count / self.median_dns_queries_per_host

    def host_bytes_ratio(self, ip: str) -> float:
        """Ratio of this host's outbound bytes vs. capture median."""
        profile = self.host_profiles.get(ip)
        if not profile or self.median_bytes_per_host == 0:
            return 1.0
        return profile.bytes_outbound / max(self.median_bytes_per_host, 1)

    def host_fanout(self, ip: str) -> int:
        """How many unique external destinations this host contacts."""
        profile = self.host_profiles.get(ip)
        return len(profile.unique_external_dsts) if profile else 0

    def is_sole_contactor(self, internal_ip: str, external_ip: str) -> bool:
        """True if internal_ip is the only host contacting external_ip."""
        hosts = self.external_ip_to_internal_hosts.get(external_ip, set())
        return hosts == {internal_ip}

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_count": len(self.host_profiles),
            "internal_hosts": sum(1 for h in self.host_profiles.values() if h.is_internal),
            "median_packets_per_host": self.median_packets_per_host,
            "median_bytes_per_host": self.median_bytes_per_host,
            "median_dns_queries_per_host": self.median_dns_queries_per_host,
        }


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def extract_metadata(packets: list) -> CaptureMetadata:
    """Extract per-host profiles and capture baselines from raw packets.

    This runs once per capture and provides context that finding builders
    use for peer-comparison indicators and outlier detection.
    """
    meta = CaptureMetadata()

    for pkt in packets:
        if "IP" not in pkt:
            continue

        src = pkt["IP"].src
        dst = pkt["IP"].dst
        pkt_len = len(pkt)
        ts = float(pkt.time)

        src_private = _is_private(src)
        dst_private = _is_private(dst)

        # Determine protocol
        proto = None
        dport = None
        if "TCP" in pkt:
            proto = "TCP"
            dport = pkt["TCP"].dport
        elif "UDP" in pkt:
            proto = "UDP"
            dport = pkt["UDP"].dport
        elif "ICMP" in pkt:
            proto = "ICMP"

        # Update source host profile
        for ip, is_sender in [(src, True), (dst, False)]:
            if ip not in meta.host_profiles:
                meta.host_profiles[ip] = HostProfile(ip=ip, is_internal=_is_private(ip))
            profile = meta.host_profiles[ip]
            profile.packet_count += 1
            profile.bytes_total += pkt_len
            if profile.first_seen is None or ts < profile.first_seen:
                profile.first_seen = ts
            if profile.last_seen is None or ts > profile.last_seen:
                profile.last_seen = ts

        # Track directional bytes and relationships
        src_profile = meta.host_profiles[src]
        dst_profile = meta.host_profiles[dst]

        if proto:
            src_profile.protocols_used.add(proto)
        if dport and _is_private(src):
            src_profile.ports_contacted.add(dport)

        if src_private and not dst_private:
            # Outbound
            src_profile.bytes_outbound += pkt_len
            src_profile.unique_external_dsts.add(dst)
            meta.external_ip_to_internal_hosts[dst].add(src)
        elif not src_private and dst_private:
            # Inbound
            dst_profile.bytes_inbound += pkt_len
        elif src_private and dst_private:
            # Internal
            src_profile.unique_internal_peers.add(dst)
            dst_profile.unique_internal_peers.add(src)

        # DNS tracking
        if "DNS" in pkt and pkt["DNS"].qr == 0 and pkt["DNS"].qd:
            try:
                qname = pkt["DNS"].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                labels = qname.split(".")
                if len(labels) >= 2:
                    base_domain = ".".join(labels[-2:]).lower()
                    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""

                    querier = src if src_private else dst
                    q_profile = meta.host_profiles.get(querier)
                    if q_profile:
                        q_profile.dns_query_count += 1
                        q_profile.dns_unique_domains.add(base_domain)
                        if subdomain:
                            q_profile.dns_entropy_values.append(_shannon_entropy(subdomain))

                    meta.domain_to_querying_hosts[base_domain].add(querier)
            except Exception:
                pass

    # Compute baselines from internal hosts only
    internal_profiles = [p for p in meta.host_profiles.values() if p.is_internal]
    if internal_profiles:
        meta.median_packets_per_host = _median([p.packet_count for p in internal_profiles])
        meta.median_bytes_per_host = _median([p.bytes_outbound for p in internal_profiles])
        meta.median_dns_queries_per_host = _median([p.dns_query_count for p in internal_profiles])
        meta.median_external_dsts_per_host = _median(
            [len(p.unique_external_dsts) for p in internal_profiles]
        )

    return meta
