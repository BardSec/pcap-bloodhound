from functools import partial

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QCheckBox, QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_description_banner, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class CleartextPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self._data: list[dict] = []
        self._description = ""

    def load(self, data: list[dict], description: str = ""):
        self._data = data
        self._description = description
        self._render(reveal=False)

    def _render(self, reveal: bool = False):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if self._description:
            layout.addWidget(make_description_banner(self._description))

        if not self._data:
            layout.addWidget(make_empty_state("No cleartext credentials detected."))
            self.setWidget(container)
            return

        protocols = set(d.get("protocol", "") for d in self._data)
        critical = sum(1 for d in self._data if d.get("severity") in ("CRITICAL", "HIGH"))

        layout.addWidget(make_card_row([
            make_card("Credentials Found", str(len(self._data)), COLORS["danger"]),
            make_card("Critical/High", str(critical), COLORS["critical"]),
            make_card("Protocols", ", ".join(sorted(protocols)), COLORS["warning"]),
        ]))

        layout.addWidget(make_section_header("Captured Credentials"))

        # Toggle to reveal/hide raw passwords.
        # Uses QTimer.singleShot to defer re-render so the checkbox's signal
        # handler completes before the widget tree is replaced.
        toggle = QCheckBox("Reveal passwords")
        toggle.setChecked(reveal)
        toggle.setStyleSheet(f"""
            QCheckBox {{
                color: {COLORS['text_muted']};
                font-size: 12px;
                spacing: 6px;
            }}
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                background-color: {COLORS['bg_input']};
            }}
            QCheckBox::indicator:checked {{
                background-color: {COLORS['warning']};
                border-color: {COLORS['warning']};
            }}
        """)
        toggle.toggled.connect(
            lambda checked: QTimer.singleShot(0, partial(self._render, reveal=checked))
        )
        layout.addWidget(toggle)

        rows = []
        for d in self._data:
            if reveal:
                password = d.get("password_raw", d.get("password_masked", ""))
            else:
                password = d.get("password_masked", "********")
            rows.append([
                d.get("protocol", ""),
                d.get("type", ""),
                d.get("username", ""),
                password,
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
