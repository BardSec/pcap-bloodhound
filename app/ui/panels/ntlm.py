from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QScrollArea, QVBoxLayout, QHBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class NtlmPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: list[dict]):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        hashes = [d for d in data if d.get("hashcat_hash")]
        auths = [d for d in data if d.get("type") == "AUTHENTICATE"]

        if not data:
            layout.addWidget(make_empty_state("No NTLM authentication exchanges detected."))
            self.setWidget(container)
            return

        layout.addWidget(make_card_row([
            make_card("NTLM Exchanges", str(len(data)), COLORS["warning"]),
            make_card("Crackable Hashes", str(len(hashes)), COLORS["danger"]),
        ]))

        if hashes:
            layout.addWidget(make_section_header("Extracted Hashes (Hashcat mode 5600)"))
            for h in hashes:
                layout.addWidget(self._make_hash_card(h))

        if auths:
            layout.addWidget(make_section_header("Authentication Details"))
            rows = []
            for a in auths:
                rows.append([
                    a.get("username", ""),
                    a.get("domain", ""),
                    a.get("workstation", ""),
                    a.get("src_ip", ""),
                    a.get("dst_ip", ""),
                    a.get("severity", ""),
                ])
            table = make_table(
                ["Username", "Domain", "Workstation", "Source IP", "Dest IP", "Severity"],
                rows,
            )
            layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)

    def _make_hash_card(self, h: dict) -> QWidget:
        card = QWidget()
        card.setStyleSheet(f"""
            QWidget {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)

        header = QLabel(f"{h.get('username', '')}@{h.get('domain', '')}  \u2192  {h.get('dst_ip', '')}")
        header.setStyleSheet(f"font-weight: 600; color: {COLORS['text']}; border: none;")
        card_layout.addWidget(header)

        hash_text = QLabel(h.get("hashcat_hash", ""))
        hash_text.setWordWrap(True)
        hash_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        hash_text.setStyleSheet(f"""
            font-family: monospace;
            font-size: 11px;
            color: {COLORS['warning']};
            background-color: {COLORS['bg_input']};
            padding: 8px;
            border-radius: 4px;
            border: none;
        """)
        card_layout.addWidget(hash_text)

        copy_btn = QPushButton("Copy Hash")
        copy_btn.setFixedWidth(100)
        copy_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
                color: {COLORS['text']};
            }}
            QPushButton:hover {{ background-color: {COLORS['border']}; }}
        """)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(h.get("hashcat_hash", "")))
        card_layout.addWidget(copy_btn)

        return card
