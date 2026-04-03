from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class DnsHealthPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        failures = data.get("failures", [])
        timeouts = data.get("timeouts", [])
        slow = data.get("slow_queries", [])
        top_failing = data.get("top_failing_domains", [])
        summary = data.get("summary", {})

        if not failures and not timeouts and not slow:
            layout.addWidget(make_empty_state("No DNS health issues detected."))
            self.setWidget(container)
            return

        layout.addWidget(make_card_row([
            make_card("NXDOMAIN", str(summary.get("nxdomain_count", 0)), COLORS["warning"]),
            make_card("SERVFAIL", str(summary.get("servfail_count", 0)), COLORS["danger"]),
            make_card("Timeouts", str(summary.get("timeout_count", len(timeouts))), COLORS["critical"]),
            make_card("Slow (>500ms)", str(summary.get("slow_count", len(slow))), COLORS["medium"]),
        ]))

        if top_failing:
            layout.addWidget(make_section_header("Top Failing Domains"))
            rows = [[d.get("domain", ""), str(d.get("failures", 0)), str(d.get("total", 0))]
                    for d in top_failing[:20]]
            layout.addWidget(make_table(["Domain", "Failures", "Total Queries"], rows))

        if failures:
            layout.addWidget(make_section_header(f"DNS Failures ({len(failures)})"))
            rows = [[
                d.get("qname", ""), d.get("rcode_name", ""), d.get("qtype", ""),
                d.get("client_ip", ""), d.get("resolver_ip", ""), d.get("severity", ""),
            ] for d in failures[:100]]
            layout.addWidget(make_table(
                ["Query", "Response", "Type", "Client", "Resolver", "Severity"], rows
            ))

        if slow:
            layout.addWidget(make_section_header(f"Slow Queries ({len(slow)})"))
            rows = [[
                d.get("qname", ""), d.get("qtype", ""),
                f"{d.get('rtt_ms', 0):.0f} ms",
                d.get("client_ip", ""), d.get("resolver_ip", ""),
            ] for d in slow[:50]]
            layout.addWidget(make_table(["Query", "Type", "RTT", "Client", "Resolver"], rows))

        layout.addStretch()
        self.setWidget(container)
