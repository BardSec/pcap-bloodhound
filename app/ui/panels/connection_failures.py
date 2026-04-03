from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class ConnectionFailuresPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        icmp = data.get("icmp_unreachables", [])
        resets = data.get("tcp_resets", [])
        dropped = data.get("silently_dropped", [])
        summary = data.get("summary", {})

        if not icmp and not resets and not dropped:
            layout.addWidget(make_empty_state("No connection failures detected."))
            self.setWidget(container)
            return

        layout.addWidget(make_card_row([
            make_card("ICMP Unreachable", str(summary.get("icmp_unreachable_count", len(icmp))), COLORS["warning"]),
            make_card("TCP Resets", str(summary.get("tcp_reset_count", len(resets))), COLORS["danger"]),
            make_card("Silently Dropped", str(summary.get("silent_drop_count", len(dropped))), COLORS["critical"]),
        ]))

        if icmp:
            layout.addWidget(make_section_header("ICMP Destination Unreachable"))
            rows = [[
                d.get("reporter_ip", ""), d.get("orig_src_ip", ""),
                f"{d.get('orig_dst_ip', '')}:{d.get('orig_dst_port', '')}",
                d.get("reason", ""),
                "Yes" if d.get("is_firewall_block") else "No",
                d.get("severity", ""),
            ] for d in icmp]
            layout.addWidget(make_table(
                ["Reporter", "Source", "Destination", "Reason", "Firewall", "Severity"], rows
            ))

        if resets:
            layout.addWidget(make_section_header("TCP Resets"))
            rows = [[
                d.get("dst_ip", ""), str(d.get("dst_port", "")),
                str(d.get("reset_count", "")),
                str(d.get("affected_clients", "")),
                d.get("severity", ""),
            ] for d in resets]
            layout.addWidget(make_table(
                ["Dest IP", "Port", "Reset Count", "Affected Clients", "Severity"], rows
            ))

        if dropped:
            layout.addWidget(make_section_header("Silently Dropped (No Response)"))
            rows = [[
                d.get("dst_ip", ""), str(d.get("dst_port", "")),
                str(d.get("drop_count", "")),
                str(d.get("affected_clients", "")),
                d.get("severity", ""),
            ] for d in dropped]
            layout.addWidget(make_table(
                ["Dest IP", "Port", "Drop Count", "Affected Clients", "Severity"], rows
            ))

        layout.addStretch()
        self.setWidget(container)
