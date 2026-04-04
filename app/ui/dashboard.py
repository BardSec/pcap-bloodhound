import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.analysis.models import CaptureResult
from app.ui.panels.c2_beacon import C2BeaconPanel
from app.ui.panels.cleartext import CleartextPanel
from app.ui.panels.connection_failures import ConnectionFailuresPanel
from app.ui.panels.dns_health import DnsHealthPanel
from app.ui.panels.dns_tunnel import DnsTunnelPanel
from app.ui.panels.exfil import ExfilPanel
from app.ui.panels.ntlm import NtlmPanel
from app.ui.panels.tls_inspect import TlsInspectPanel
from app.ui.panels.traffic_timeline import TrafficTimelinePanel
from app.ui.panels.generic import GenericDictPanel
from app.ui.theme import COLORS


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._result: CaptureResult | None = None
        self._build_ui()

    def _build_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Welcome screen (shown when no capture is selected)
        self.welcome = QWidget()
        welcome_layout = QVBoxLayout(self.welcome)
        welcome_layout.setAlignment(Qt.AlignCenter)

        title = QLabel("Open a PCAP file to begin")
        title.setStyleSheet(f"font-size: 20px; color: {COLORS['text_muted']}; font-weight: 600;")
        title.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(title)

        subtitle = QLabel("Supports .pcap, .pcapng, and .cap files")
        subtitle.setStyleSheet(f"font-size: 13px; color: {COLORS['text_muted']};")
        subtitle.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(subtitle)

        # Dashboard (shown when a capture is selected)
        self.dashboard_widget = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard_widget)
        self.dashboard_layout.setContentsMargins(16, 16, 16, 16)
        self.dashboard_layout.setSpacing(12)

        # Header bar
        self.header = QWidget()
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        self.filename_label = QLabel("")
        self.filename_label.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {COLORS['text']};")
        header_layout.addWidget(self.filename_label)

        self.meta_label = QLabel("")
        self.meta_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_muted']};")
        header_layout.addWidget(self.meta_label)

        header_layout.addStretch()

        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setProperty("class", "outline")
        self.export_btn.clicked.connect(self._export_json)
        header_layout.addWidget(self.export_btn)

        self.dashboard_layout.addWidget(self.header)

        # Tabs
        self.tabs = QTabWidget()
        self.dashboard_layout.addWidget(self.tabs, 1)

        # Stack
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.dashboard_widget)
        self.layout.addWidget(self.stack)

    def show_results(self, result: CaptureResult):
        self._result = result

        # Update header
        self.filename_label.setText(result.filename)
        size_mb = result.file_size / (1024 * 1024)
        ts = result.completed_at.strftime("%Y-%m-%d %H:%M") if result.completed_at else ""
        self.meta_label.setText(f"{result.packet_count:,} packets  \u2022  {size_mb:.1f} MB  \u2022  {ts}")

        # Clear and rebuild tabs
        self.tabs.clear()

        # Custom panels (have charts or special layouts)
        custom_panels = [
            ("C2 Beaconing", "c2_beaconing", C2BeaconPanel, True),
            ("DNS Tunneling", "dns_tunneling", DnsTunnelPanel, False),
            ("NTLM Hashes", "ntlm", NtlmPanel, True),
            ("Cleartext Creds", "cleartext_creds", CleartextPanel, True),
            ("Exfiltration", "exfiltration", ExfilPanel, True),
            ("Blocked Connections", "connection_failures", ConnectionFailuresPanel, False),
            ("DNS Health", "dns_health", DnsHealthPanel, False),
            ("TLS/SSL", "tls_inspection", TlsInspectPanel, False),
            ("Traffic Timeline", "traffic_timeline", TrafficTimelinePanel, False),
        ]

        # Generic panels (cards + tables auto-layout)
        generic_panels = [
            ("Lateral Movement", "lateral_movement", "No lateral movement detected."),
            ("DGA Detection", "dga_detection", "No DGA domains detected."),
            ("Data Staging", "data_staging", "No data staging patterns detected."),
            ("User-Agents", "suspicious_useragents", "No suspicious user agents detected."),
            ("PS/WMI", "powershell_wmi", "No PowerShell/WMI network activity detected."),
            ("Filter Bypass", "content_filter_bypass", "No content filter bypass attempts detected."),
            ("CIPA Compliance", "cipa_compliance", "No web traffic to analyze for CIPA compliance."),
            ("VLAN Traffic", "vlan_traffic", "No VLAN-tagged traffic detected."),
            ("DHCP", "dhcp", "No DHCP traffic detected."),
            ("Broadcast/Multicast", "broadcast_storms", "No broadcast storm indicators."),
            ("Services", "services", "No network services detected."),
        ]

        for label, attr, panel_class, is_list in custom_panels:
            panel = panel_class()
            data = getattr(result, attr, [] if is_list else {})
            panel.load(data)
            count = result.finding_count(attr)
            tab_label = f"{label} ({count})" if count > 0 else label
            self.tabs.addTab(panel, tab_label)

        for label, attr, empty_msg in generic_panels:
            panel = GenericDictPanel(empty_message=empty_msg)
            data = getattr(result, attr, {})
            panel.load(data)
            count = result.finding_count(attr)
            tab_label = f"{label} ({count})" if count > 0 else label
            self.tabs.addTab(panel, tab_label)

        self.stack.setCurrentIndex(1)

    def _export_json(self):
        if not self._result:
            return

        base_name = self._result.filename.rsplit(".", 1)[0]
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"{base_name}_analysis.json",
            "JSON Files (*.json)",
        )
        if not file_path:
            return

        with open(file_path, "w") as f:
            json.dump(self._result.to_export_dict(), f, indent=2, default=str)
