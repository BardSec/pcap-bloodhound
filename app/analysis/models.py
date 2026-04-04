from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CaptureResult:
    """Holds all analysis results for a single PCAP file."""

    filename: str
    file_path: str
    file_size: int = 0
    packet_count: int = 0
    status: str = "pending"  # pending, processing, complete, failed
    error: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None

    # Threat hunting results
    c2_beaconing: list[dict[str, Any]] = field(default_factory=list)
    dns_tunneling: dict[str, Any] = field(default_factory=dict)
    ntlm: list[dict[str, Any]] = field(default_factory=list)
    cleartext_creds: list[dict[str, Any]] = field(default_factory=list)
    exfiltration: list[dict[str, Any]] = field(default_factory=list)

    # Additional threat hunting
    lateral_movement: dict[str, Any] = field(default_factory=dict)
    dga_detection: dict[str, Any] = field(default_factory=dict)
    data_staging: dict[str, Any] = field(default_factory=dict)
    suspicious_useragents: dict[str, Any] = field(default_factory=dict)
    powershell_wmi: dict[str, Any] = field(default_factory=dict)

    # K-12 specific
    content_filter_bypass: dict[str, Any] = field(default_factory=dict)
    cipa_compliance: dict[str, Any] = field(default_factory=dict)

    # Network visibility
    connection_failures: dict[str, Any] = field(default_factory=dict)
    dns_health: dict[str, Any] = field(default_factory=dict)
    tls_inspection: dict[str, Any] = field(default_factory=dict)
    traffic_timeline: dict[str, Any] = field(default_factory=dict)
    vlan_traffic: dict[str, Any] = field(default_factory=dict)
    dhcp: dict[str, Any] = field(default_factory=dict)
    broadcast_storms: dict[str, Any] = field(default_factory=dict)
    services: dict[str, Any] = field(default_factory=dict)

    def finding_count(self, analyzer: str) -> int:
        """Return the number of findings for a given analyzer."""
        data = getattr(self, analyzer, None)
        if data is None:
            return 0
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            # Sum list lengths in dict values
            total = 0
            for v in data.values():
                if isinstance(v, list):
                    total += len(v)
            return total
        return 0

    def to_export_dict(self) -> dict[str, Any]:
        """Serialize all results for JSON export (includes raw passwords)."""
        return {
            "filename": self.filename,
            "file_size": self.file_size,
            "packet_count": self.packet_count,
            "analyzed_at": self.completed_at.isoformat() if self.completed_at else None,
            "threat_hunting": {
                "c2_beaconing": self.c2_beaconing,
                "dns_tunneling": self.dns_tunneling,
                "ntlm_hashes": self.ntlm,
                "cleartext_credentials": self.cleartext_creds,
                "exfiltration": self.exfiltration,
            },
            "additional_threat_hunting": {
                "lateral_movement": self.lateral_movement,
                "dga_detection": self.dga_detection,
                "data_staging": self.data_staging,
                "suspicious_useragents": self.suspicious_useragents,
                "powershell_wmi": self.powershell_wmi,
            },
            "k12_specific": {
                "content_filter_bypass": self.content_filter_bypass,
                "cipa_compliance": self.cipa_compliance,
            },
            "network_visibility": {
                "connection_failures": self.connection_failures,
                "dns_health": self.dns_health,
                "tls_inspection": self.tls_inspection,
                "traffic_timeline": self.traffic_timeline,
                "vlan_traffic": self.vlan_traffic,
                "dhcp": self.dhcp,
                "broadcast_storms": self.broadcast_storms,
                "services": self.services,
            },
        }
