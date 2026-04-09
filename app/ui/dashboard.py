import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
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
from app.ui.panels.investigation import InvestigationPanel
from app.ui.panels.base import make_card, make_card_row, make_description_banner, make_section_header, set_investigate_callback
from app.ui.theme import COLORS
from app.settings import load_settings, INDUSTRY_PACKS

# Each entry: (label, attr, PanelClass, is_list, description) for custom panels
#             (label, attr, None, empty_message, description) for generic panels
ANALYZER_CATEGORIES = [
    {
        "name": "Threat Hunting",
        "analyzers": [
            ("C2 Beaconing", "c2_beaconing", C2BeaconPanel, True,
             "Detects command-and-control beaconing by identifying outbound flows with highly regular timing intervals. "
             "Flows with low coefficient of variation (CV < 0.15) in inter-arrival times suggest automated callbacks rather than human browsing."),
            ("DNS Tunneling", "dns_tunneling", DnsTunnelPanel, False,
             "Identifies data exfiltration through DNS by looking for queries with high-entropy subdomains, unusually long labels, "
             "and suspicious record types (TXT, NULL, CNAME). Estimates the volume of data that could be tunneled."),
            ("NTLM Hashes", "ntlm", NtlmPanel, True,
             "Extracts NTLM authentication exchanges (Negotiate, Challenge, Authenticate) from network traffic. "
             "Recovered hashes are formatted for offline cracking with Hashcat (mode 5600)."),
            ("Cleartext Creds", "cleartext_creds", CleartextPanel, True,
             "Finds credentials transmitted without encryption — HTTP Basic Auth, form POST passwords, FTP USER/PASS, "
             "and SMTP AUTH LOGIN sequences. Any match means credentials are exposed on the wire."),
            ("Exfiltration", "exfiltration", ExfilPanel, True,
             "Flags outbound flows with large asymmetric transfers — significant data leaving the network with minimal inbound traffic. "
             "Flows exceeding 1 MB outbound with a 5:1 ratio are suspicious; over 10 MB is critical."),
        ],
    },
    {
        "name": "Attack Path",
        "analyzers": [
            ("Lateral Movement", "lateral_movement", None, "No lateral movement detected.",
             "Monitors internal-to-internal connections on protocols commonly used for lateral movement: SMB (445), RDP (3389), "
             "WinRM (5985/5986), SSH (22), and Telnet (23). A single host scanning 5+ targets on the same port triggers a critical alert."),
            ("DGA Detection", "dga_detection", None, "No DGA domains detected.",
             "Identifies algorithmically generated domains using entropy analysis, consonant ratios, digit density, and label length. "
             "High-scoring domains suggest malware using a Domain Generation Algorithm to locate its C2 infrastructure."),
            ("Data Staging", "data_staging", None, "No data staging patterns detected.",
             "Detects a two-phase exfiltration pattern: large internal transfers (staging) followed by external uploads within a 10-minute window. "
             "This mimics an attacker collecting data on a pivot host before sending it out."),
            ("User-Agents", "suspicious_useragents", None, "No suspicious user agents detected.",
             "Flags HTTP requests using non-browser User-Agent strings such as scripting libraries (python-requests, curl), "
             "scanners (nmap, nikto), or known offensive tools (sqlmap, Cobalt Strike)."),
            ("PS/WMI", "powershell_wmi", None, "No PowerShell/WMI network activity detected.",
             "Detects PowerShell Remoting (WinRM on 5985/5986) and WMI/DCOM lateral movement (port 135) by matching "
             "protocol signatures like WSMAN schemas, DCE/RPC headers, and IWbemServices interfaces in payloads."),
        ],
    },
    {
        "name": "K-12 Specific",
        "pack": "k12",
        "analyzers": [
            ("Filter Bypass", "content_filter_bypass", None, "No content filter bypass attempts detected.",
             "Identifies attempts to circumvent content filters using VPN/proxy services (NordVPN, Psiphon, Ultrasurf), "
             "public DNS resolvers (8.8.8.8, 1.1.1.1), or encrypted DNS (DoH/DoT) that bypasses district DNS filtering."),
            ("CIPA Compliance", "cipa_compliance", None, "No web traffic to analyze for CIPA compliance.",
             "Checks whether outbound web traffic passes through a recognized content filter (Lightspeed, GoGuardian, Securly, Cisco Umbrella, etc.). "
             "Unfiltered HTTPS connections from student devices may indicate a CIPA compliance gap."),
            ("Student Data", "student_data_exposure", None, "No student data exposure detected.",
             "Scans cleartext traffic for student PII — SSNs, dates of birth, student IDs, and student email patterns. "
             "Also detects unencrypted SIS/EdTech API traffic (PowerSchool, Infinite Campus, Clever, etc.). Any student data in cleartext is a FERPA concern."),
            ("Vendor Traffic", "vendor_traffic", None, "No EdTech vendor traffic detected.",
             "Identifies traffic to known EdTech vendors (SIS, LMS, SSO, assessment platforms) and flags unencrypted connections, "
             "bulk data exports (>500 KB), and third-party analytics/tracking domains that may be collecting student data without consent."),
        ],
    },
    {
        "name": "Financial Services",
        "pack": "financial",
        "analyzers": [
            ("PCI DSS Compliance", "pci_compliance", None, "No PCI DSS compliance issues detected.",
             "Scans cleartext packet payloads for credit card Primary Account Numbers (PANs) validated with the Luhn algorithm. "
             "Flags unencrypted connections to payment processing ports. Any PAN in cleartext is a PCI DSS violation."),
            ("Financial Protocols", "financial_protocols", None, "No financial protocol traffic detected.",
             "Detects FIX protocol (trading), Bloomberg terminal, and SWIFT messaging traffic. "
             "Flags unencrypted financial protocol usage that could expose sensitive transaction data."),
        ],
    },
    {
        "name": "Healthcare",
        "pack": "healthcare",
        "analyzers": [
            ("HIPAA Compliance", "hipaa_compliance", None, "No HIPAA compliance issues detected.",
             "Scans cleartext payloads for Protected Health Information patterns — SSNs, dates of birth, and Medical Record Numbers. "
             "Flags unencrypted HL7 (port 2575) and DICOM (port 104) traffic. PHI values are masked in all output."),
            ("Medical Devices", "medical_devices", None, "No medical device traffic detected.",
             "Identifies medical devices by detecting HL7v2 message segments, DICOM imaging associations, and Ethernet MAC "
             "addresses from known medical device manufacturers (GE, Philips, Siemens, Medtronic, etc.)."),
        ],
    },
    {
        "name": "Energy / Utilities",
        "pack": "energy",
        "analyzers": [
            ("ICS/SCADA Protocols", "ics_scada", None, "No ICS/SCADA protocol traffic detected.",
             "Detects industrial control system protocols: Modbus TCP (502), DNP3 (20000), OPC UA (4840), "
             "EtherNet/IP (44818), BACnet (47808), IEC 61850 MMS, and IEC 60870-5-104. Inventories all ICS protocol flows."),
            ("IT/OT Segmentation", "it_ot_segmentation", None, "No IT/OT segmentation issues detected.",
             "Classifies hosts as IT or OT based on protocol usage, then identifies boundary crossings between the two zones. "
             "Flags OT hosts with outbound internet access — a critical risk in industrial environments."),
        ],
    },
    {
        "name": "Network Visibility",
        "analyzers": [
            ("Blocked Connections", "connection_failures", ConnectionFailuresPanel, False,
             "Aggregates evidence of network filtering: ICMP unreachable messages (especially firewall-prohibited codes), "
             "TCP RST floods to specific destinations, and SYN packets that received no response (silently dropped)."),
            ("DNS Health", "dns_health", DnsHealthPanel, False,
             "Monitors DNS response quality — NXDOMAIN (missing records), SERVFAIL (resolver errors), REFUSED (policy blocks), "
             "timeouts (no response), and slow queries (>500ms). Helps diagnose DNS infrastructure issues."),
            ("TLS/SSL", "tls_inspection", TlsInspectPanel, False,
             "Analyzes TLS handshakes to detect SSL inspection appliances, certificate mismatches between SNI and certificate CN, "
             "and TLS alert errors (bad certificate, unknown CA). Identifies which filter product is performing HTTPS inspection."),
            ("Traffic Timeline", "traffic_timeline", TrafficTimelinePanel, False,
             "Visualizes traffic volume over time, detecting bursts (>3x average packets/sec) and gaps (periods of silence). "
             "Also ranks top conversations and endpoints by total bytes transferred."),
            ("VLAN Traffic", "vlan_traffic", None, "No VLAN-tagged traffic detected.",
             "Maps VLAN-tagged (802.1Q) traffic to build a per-VLAN host inventory and identifies cross-VLAN communication flows "
             "that may indicate misconfigured trunking or unauthorized inter-VLAN routing."),
            ("DHCP", "dhcp", None, "No DHCP traffic detected.",
             "Tracks DHCP lease activity (Discover, Offer, Request, ACK) and flags anomalies like multiple DHCP servers "
             "(possible rogue server), declined leases, or NAK responses indicating address conflicts."),
            ("Broadcast/Multicast", "broadcast_storms", None, "No broadcast storm indicators.",
             "Detects broadcast storms by measuring broadcast/multicast packet rates. A single source exceeding 100 packets/sec "
             "or broadcast traffic comprising over 30% of total traffic triggers an alert."),
            ("Services", "services", None, "No network services detected.",
             "Inventories network services by observing TCP SYN-ACK responses and UDP replies from well-known ports "
             "(SSH, HTTP, SMB, LDAP, RDP, MySQL, Redis, MongoDB, etc.) to map what is running on the network."),
        ],
    },
]


class OverviewPanel(QScrollArea):
    """Summary dashboard showing finding counts for all analyzers."""

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: CaptureResult, active_categories: list[dict] | None = None):
        categories = active_categories if active_categories is not None else ANALYZER_CATEGORIES
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(16)

        for category in categories:
            layout.addWidget(make_section_header(category["name"]))

            cards = []
            for analyzer in category["analyzers"]:
                label, attr = analyzer[0], analyzer[1]
                count = result.finding_count(attr)

                if count > 0:
                    if category["name"] == "Threat Hunting":
                        color = COLORS["danger"]
                    else:
                        color = COLORS["warning"]
                else:
                    color = COLORS["success"]

                cards.append(make_card(label, str(count), color))

                # Flush row at 4 cards
                if len(cards) == 4:
                    layout.addWidget(make_card_row(cards))
                    cards = []

            if cards:
                layout.addWidget(make_card_row(cards))

        layout.addStretch()
        self.setWidget(container)


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._result: CaptureResult | None = None
        self._nav_to_stack: dict[int, int] = {}
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

        # Content area: nav list + panel stack
        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setHandleWidth(1)

        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(210)
        self.nav_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS['bg_panel']};
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-top: 1px solid {COLORS['border']};
                border-top-left-radius: 6px;
                outline: none;
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 7px 12px 7px 16px;
                border: none;
                border-bottom: none;
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['accent']}18;
                color: {COLORS['accent']};
                border-left: 3px solid {COLORS['accent']};
                padding-left: 13px;
            }}
            QListWidget::item:hover:!selected {{
                background-color: {COLORS['bg_card']};
            }}
        """)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)

        self.panel_stack = QStackedWidget()
        self.panel_stack.setStyleSheet(f"""
            QStackedWidget {{
                border: 1px solid {COLORS['border']};
                border-left: none;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
                background-color: {COLORS['bg_panel']};
            }}
        """)

        content_splitter.addWidget(self.nav_list)
        content_splitter.addWidget(self.panel_stack)
        content_splitter.setStretchFactor(0, 0)
        content_splitter.setStretchFactor(1, 1)

        self.dashboard_layout.addWidget(content_splitter, 1)

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

        # Clear previous state
        self.nav_list.clear()
        while self.panel_stack.count():
            w = self.panel_stack.widget(0)
            self.panel_stack.removeWidget(w)
            w.deleteLater()
        self._nav_to_stack.clear()

        # Filter categories by enabled industry packs
        settings = load_settings()
        enabled_packs = set(settings.get("enabled_packs", []))
        active_categories = [
            cat for cat in ANALYZER_CATEGORIES
            if "pack" not in cat or cat["pack"] in enabled_packs
        ]

        # Stack index 0: Overview panel
        overview = OverviewPanel()
        overview.load(result, active_categories)
        self.panel_stack.addWidget(overview)

        # Stack index 1: Investigation Threads panel
        self._investigation_panel = InvestigationPanel()
        self._investigation_panel.load(result.investigation_threads)
        self.panel_stack.addWidget(self._investigation_panel)

        # Register global investigate callback for right-click pivots from any table
        set_investigate_callback(self._pivot_to_entity)

        # Build analyzer panels (stack indices 2+)
        stack_idx = 2
        for category in active_categories:
            for analyzer in category["analyzers"]:
                label, attr, panel_class_or_none = analyzer[0], analyzer[1], analyzer[2]
                fourth = analyzer[3]
                description = analyzer[4] if len(analyzer) > 4 else ""

                if panel_class_or_none is not None:
                    # Custom panel
                    panel = panel_class_or_none()
                    is_list = fourth
                    data = getattr(result, attr, [] if is_list else {})
                    panel.load(data, description=description)
                else:
                    # Generic panel
                    empty_msg = fourth
                    panel = GenericDictPanel(empty_message=empty_msg)
                    data = getattr(result, attr, {})
                    panel.load(data, description=description)

                self.panel_stack.addWidget(panel)
                stack_idx += 1

        # Build nav list
        self._build_nav_list(result, active_categories)

        # Select overview
        self.nav_list.setCurrentRow(0)

        self.stack.setCurrentIndex(1)

    def _build_nav_list(self, result: CaptureResult, active_categories: list[dict]):
        nav_row = 0

        # Overview item
        overview_item = QListWidgetItem("Overview")
        overview_font = QFont()
        overview_font.setBold(True)
        overview_item.setFont(overview_font)
        self.nav_list.addItem(overview_item)
        self._nav_to_stack[nav_row] = 0
        nav_row += 1

        # Investigation Threads item
        thread_count = len(result.investigation_threads)
        thread_label = f"Investigation ({thread_count})" if thread_count else "Investigation"
        thread_item = QListWidgetItem(thread_label)
        thread_font = QFont()
        thread_font.setBold(True)
        thread_item.setFont(thread_font)
        self.nav_list.addItem(thread_item)
        self._nav_to_stack[nav_row] = 1
        nav_row += 1

        stack_idx = 2
        for category in active_categories:
            # Category header (non-selectable)
            header_item = QListWidgetItem(category["name"].upper())
            header_item.setFlags(Qt.NoItemFlags)
            header_font = QFont()
            header_font.setBold(True)
            header_font.setPointSize(10)
            header_item.setFont(header_font)
            header_item.setForeground(Qt.gray)
            self.nav_list.addItem(header_item)
            nav_row += 1

            for analyzer in category["analyzers"]:
                label, attr = analyzer[0], analyzer[1]
                count = result.finding_count(attr)
                display = f"  {label} ({count})" if count > 0 else f"  {label}"

                item = QListWidgetItem(display)
                self.nav_list.addItem(item)
                self._nav_to_stack[nav_row] = stack_idx
                nav_row += 1
                stack_idx += 1

    def _on_nav_changed(self, row: int):
        if row in self._nav_to_stack:
            self.panel_stack.setCurrentIndex(self._nav_to_stack[row])

    def _pivot_to_entity(self, entity: str):
        """Navigate to the Investigation Threads panel and select the given entity."""
        if not hasattr(self, "_investigation_panel"):
            return
        # Find the nav row that maps to stack index 1 (Investigation panel)
        inv_nav_row = None
        for nav_row, stack_idx in self._nav_to_stack.items():
            if stack_idx == 1:
                inv_nav_row = nav_row
                break
        if inv_nav_row is not None:
            self.nav_list.setCurrentRow(inv_nav_row)
        self._investigation_panel.navigate_to_entity(entity)

    def _export_json(self):
        if not self._result:
            return

        # Warn if export will contain sensitive credential data
        has_creds = bool(self._result.cleartext_creds or self._result.ntlm)
        if has_creds:
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.warning(
                self,
                "Sensitive Data Warning",
                "This export will contain captured credentials (passwords and/or "
                "NTLM hashes) in plaintext.\n\nTreat the exported file as sensitive. "
                "Continue?",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if reply != QMessageBox.Yes:
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
