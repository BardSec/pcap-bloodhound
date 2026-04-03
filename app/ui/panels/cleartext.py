from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class CleartextPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: list[dict]):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not data:
            layout.addWidget(make_empty_state("No cleartext credentials detected."))
            self.setWidget(container)
            return

        protocols = set(d.get("protocol", "") for d in data)
        critical = sum(1 for d in data if d.get("severity") in ("CRITICAL", "HIGH"))

        layout.addWidget(make_card_row([
            make_card("Credentials Found", str(len(data)), COLORS["danger"]),
            make_card("Critical/High", str(critical), COLORS["critical"]),
            make_card("Protocols", ", ".join(sorted(protocols)), COLORS["warning"]),
        ]))

        layout.addWidget(make_section_header("Captured Credentials"))
        rows = []
        for d in data:
            rows.append([
                d.get("protocol", ""),
                d.get("type", ""),
                d.get("username", ""),
                d.get("password_masked", ""),
                d.get("src_ip", ""),
                f"{d.get('dst_ip', '')}:{d.get('dst_port', '')}",
                d.get("severity", ""),
            ])
        table = make_table(
            ["Protocol", "Type", "Username", "Password", "Source", "Destination", "Severity"],
            rows,
        )
        layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
