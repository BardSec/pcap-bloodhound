from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class DnsTunnelPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        queries = data.get("suspicious_queries", [])
        domains = data.get("tunnel_domains", [])
        total = data.get("total_suspicious", 0)

        if not queries and not domains:
            layout.addWidget(make_empty_state("No DNS tunneling indicators detected."))
            self.setWidget(container)
            return

        layout.addWidget(make_card_row([
            make_card("Suspicious Queries", str(total), COLORS["danger"]),
            make_card("Suspect Domains", str(len(domains)), COLORS["warning"]),
        ]))

        if domains:
            layout.addWidget(make_section_header("Tunnel Domains"))
            rows = []
            for d in domains:
                rows.append([
                    d.get("domain", ""),
                    str(d.get("query_count", 0)),
                    str(d.get("high_entropy_queries", 0)),
                    str(d.get("long_label_queries", 0)),
                    f"{d.get('estimated_exfil_kb', 0):.1f} KB",
                    d.get("severity", ""),
                ])
            table = make_table(
                ["Domain", "Queries", "High Entropy", "Long Labels", "Est. Exfil", "Severity"],
                rows,
            )
            layout.addWidget(table)

        if queries:
            layout.addWidget(make_section_header("Suspicious Queries"))
            rows = []
            for q in queries[:100]:
                rows.append([
                    q.get("qname", ""),
                    f"{q.get('entropy', 0):.2f}",
                    str(q.get("subdomain_length", 0)),
                    q.get("qtype", ""),
                    ", ".join(q.get("reasons", [])),
                    q.get("severity", ""),
                ])
            table = make_table(
                ["Query Name", "Entropy", "Length", "Type", "Reasons", "Severity"],
                rows,
            )
            layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
