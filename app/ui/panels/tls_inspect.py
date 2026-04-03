from PySide6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class TlsInspectPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        intercepted = data.get("intercepted_connections", [])
        mismatches = data.get("sni_cert_mismatches", [])
        alerts = data.get("tls_alerts", [])
        products = data.get("detected_filter_products", [])
        summary = data.get("summary", {})

        if not intercepted and not mismatches and not alerts:
            layout.addWidget(make_empty_state("No TLS/SSL issues detected."))
            self.setWidget(container)
            return

        layout.addWidget(make_card_row([
            make_card("Intercepted", str(summary.get("intercepted_count", len(intercepted))), COLORS["warning"]),
            make_card("Mismatches", str(summary.get("mismatch_count", len(mismatches))), COLORS["danger"]),
            make_card("TLS Alerts", str(summary.get("alert_count", len(alerts))), COLORS["critical"]),
        ]))

        if products:
            banner = QLabel(f"Detected filter products: {', '.join(products)}")
            banner.setStyleSheet(f"""
                background-color: {COLORS['warning']}22;
                color: {COLORS['warning']};
                border: 1px solid {COLORS['warning']}44;
                border-radius: 6px;
                padding: 10px 16px;
                font-weight: 600;
            """)
            layout.addWidget(banner)

        if intercepted:
            layout.addWidget(make_section_header("Intercepted Connections"))
            rows = [[
                d.get("src_ip", ""), f"{d.get('dst_ip', '')}:{d.get('dst_port', '')}",
                d.get("sni", ""), d.get("cert_cn", ""),
                d.get("issuer_cn", ""), d.get("filter_product", ""),
                d.get("severity", ""),
            ] for d in intercepted[:100]]
            layout.addWidget(make_table(
                ["Source", "Destination", "SNI", "Cert CN", "Issuer", "Product", "Severity"], rows
            ))

        if mismatches:
            layout.addWidget(make_section_header("SNI / Certificate Mismatches"))
            rows = [[
                d.get("src_ip", ""), f"{d.get('dst_ip', '')}:{d.get('dst_port', '')}",
                d.get("sni", ""), d.get("cert_cn", ""),
                d.get("issuer_cn", ""), d.get("severity", ""),
            ] for d in mismatches[:100]]
            layout.addWidget(make_table(
                ["Source", "Destination", "SNI", "Cert CN", "Issuer", "Severity"], rows
            ))

        if alerts:
            layout.addWidget(make_section_header("TLS Alerts"))
            rows = [[
                d.get("src_ip", ""), f"{d.get('dst_ip', '')}:{d.get('dst_port', '')}",
                d.get("level", ""), d.get("description", ""),
                d.get("severity", ""),
            ] for d in alerts[:100]]
            layout.addWidget(make_table(
                ["Source", "Destination", "Level", "Description", "Severity"], rows
            ))

        layout.addStretch()
        self.setWidget(container)
