import json
import logging
import os
from datetime import datetime

from PySide6.QtCore import QThread, Signal

from scapy.all import PcapReader

from app.analysis.models import CaptureResult
from app.analyzers import (
    analyze_c2_beaconing,
    analyze_cleartext_credentials,
    analyze_connection_failures,
    analyze_dns_health,
    analyze_dns_tunneling,
    analyze_exfiltration,
    analyze_ntlm,
    analyze_tls_inspection,
    analyze_traffic_timeline,
    analyze_content_filter_bypass,
    analyze_cipa_compliance,
    analyze_vlan_traffic,
    analyze_dhcp,
    analyze_broadcast_storms,
    analyze_services,
    analyze_lateral_movement,
    analyze_dga,
    analyze_data_staging,
    analyze_suspicious_useragents,
    analyze_powershell_wmi,
    analyze_pci_compliance,
    analyze_financial_protocols,
    analyze_hipaa_compliance,
    analyze_medical_devices,
    analyze_ics_scada,
    analyze_it_ot_segmentation,
    analyze_student_data_exposure,
    analyze_vendor_traffic,
)
from app.analysis.finding_builders import build_all_findings
from app.analysis.metadata import extract_metadata
from app.analysis.threads import build_threads
from app.settings import get_enabled_analyzers

logger = logging.getLogger(__name__)

ANALYZER_NAMES = [
    ("Loading packets", None),
    # Threat hunting
    ("C2 Beaconing", "c2_beaconing"),
    ("DNS Tunneling", "dns_tunneling"),
    ("NTLM Hashes", "ntlm"),
    ("Cleartext Credentials", "cleartext_creds"),
    ("Exfiltration", "exfiltration"),
    ("Lateral Movement", "lateral_movement"),
    ("DGA Detection", "dga_detection"),
    ("Data Staging", "data_staging"),
    ("Suspicious User-Agents", "suspicious_useragents"),
    ("PowerShell/WMI", "powershell_wmi"),
    # K-12
    ("Content Filter Bypass", "content_filter_bypass"),
    ("CIPA Compliance", "cipa_compliance"),
    ("Student Data Exposure", "student_data_exposure"),
    ("Vendor Traffic", "vendor_traffic"),
    # Financial Services
    ("PCI DSS Compliance", "pci_compliance"),
    ("Financial Protocols", "financial_protocols"),
    # Healthcare
    ("HIPAA Compliance", "hipaa_compliance"),
    ("Medical Devices", "medical_devices"),
    # Energy / Utilities
    ("ICS/SCADA Protocols", "ics_scada"),
    ("IT/OT Segmentation", "it_ot_segmentation"),
    # Network visibility
    ("Connection Failures", "connection_failures"),
    ("DNS Health", "dns_health"),
    ("TLS/SSL Inspection", "tls_inspection"),
    ("Traffic Timeline", "traffic_timeline"),
    ("VLAN Traffic", "vlan_traffic"),
    ("DHCP Analysis", "dhcp"),
    ("Broadcast Storms", "broadcast_storms"),
    ("Service Discovery", "services"),
]


class AnalysisWorker(QThread):
    """Runs PCAP analysis in a background thread."""

    progress = Signal(str, int)  # (stage_name, percent)
    finished = Signal(CaptureResult)
    error = Signal(str)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        result = CaptureResult(
            filename=os.path.basename(self.file_path),
            file_path=self.file_path,
            file_size=os.path.getsize(self.file_path),
            status="processing",
        )

        try:
            total_steps = len(ANALYZER_NAMES)

            # Step 1: Load packets
            self.progress.emit("Loading packets...", int(100 / total_steps))
            packets = list(PcapReader(self.file_path))
            result.packet_count = len(packets)

            if not packets:
                result.status = "complete"
                result.completed_at = datetime.now()
                self.finished.emit(result)
                return

            # Step 2-10: Run each analyzer
            analyzers = {
                "c2_beaconing": analyze_c2_beaconing,
                "dns_tunneling": analyze_dns_tunneling,
                "ntlm": analyze_ntlm,
                "cleartext_creds": analyze_cleartext_credentials,
                "exfiltration": analyze_exfiltration,
                "lateral_movement": analyze_lateral_movement,
                "dga_detection": analyze_dga,
                "data_staging": analyze_data_staging,
                "suspicious_useragents": analyze_suspicious_useragents,
                "powershell_wmi": analyze_powershell_wmi,
                "content_filter_bypass": analyze_content_filter_bypass,
                "cipa_compliance": analyze_cipa_compliance,
                "student_data_exposure": analyze_student_data_exposure,
                "vendor_traffic": analyze_vendor_traffic,
                "pci_compliance": analyze_pci_compliance,
                "financial_protocols": analyze_financial_protocols,
                "hipaa_compliance": analyze_hipaa_compliance,
                "medical_devices": analyze_medical_devices,
                "ics_scada": analyze_ics_scada,
                "it_ot_segmentation": analyze_it_ot_segmentation,
                "connection_failures": analyze_connection_failures,
                "dns_health": analyze_dns_health,
                "tls_inspection": analyze_tls_inspection,
                "traffic_timeline": analyze_traffic_timeline,
                "vlan_traffic": analyze_vlan_traffic,
                "dhcp": analyze_dhcp,
                "broadcast_storms": analyze_broadcast_storms,
                "services": analyze_services,
            }

            enabled = get_enabled_analyzers()

            for i, (display_name, attr_name) in enumerate(ANALYZER_NAMES):
                if attr_name is None:
                    continue  # Skip the "Loading packets" entry

                # Skip industry-specific analyzers that aren't enabled
                if attr_name in analyzers and attr_name not in enabled and attr_name in (
                    "content_filter_bypass", "cipa_compliance",
                    "student_data_exposure", "vendor_traffic",
                    "pci_compliance", "financial_protocols",
                    "hipaa_compliance", "medical_devices",
                    "ics_scada", "it_ot_segmentation",
                ):
                    continue

                pct = int(((i + 1) / total_steps) * 100)
                self.progress.emit(f"Analyzing: {display_name}...", pct)

                try:
                    analyzer_fn = analyzers[attr_name]
                    analyzer_result = analyzer_fn(packets)
                    setattr(result, attr_name, analyzer_result)
                except Exception as e:
                    logger.warning(f"Analyzer {display_name} failed: {e}")
                    setattr(result, attr_name, [] if attr_name in (
                        "c2_beaconing", "ntlm", "cleartext_creds", "exfiltration"
                    ) else {})

            # ── Post-processing: metadata, findings, investigation threads ──
            self.progress.emit("Extracting metadata...", 92)
            try:
                meta = extract_metadata(packets)
                result.capture_metadata = meta
            except Exception as e:
                logger.warning(f"Metadata extraction failed: {e}")
                meta = None

            if meta:
                self.progress.emit("Building findings...", 95)
                try:
                    result.findings = build_all_findings(result, meta)
                except Exception as e:
                    logger.warning(f"Finding builder failed: {e}")

                self.progress.emit("Building investigation threads...", 98)
                try:
                    result.investigation_threads = build_threads(
                        result.findings, result, meta,
                    )
                except Exception as e:
                    logger.warning(f"Thread builder failed: {e}")

            result.status = "complete"
            result.completed_at = datetime.now()
            self.progress.emit("Analysis complete", 100)
            self.finished.emit(result)

        except Exception as e:
            logger.exception(f"Analysis failed: {e}")
            result.status = "failed"
            result.error = str(e)
            self.error.emit(str(e))
