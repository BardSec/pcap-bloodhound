"""Settings dialog — toggle industry analyzer packs."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QVBoxLayout,
)

from app.settings import INDUSTRY_PACKS, load_settings, save_settings
from app.ui.theme import COLORS


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Industry Analyzer Packs")
        self.setMinimumWidth(420)
        self.setStyleSheet(f"background-color: {COLORS['bg_dark']}; color: {COLORS['text']};")

        self.changed = False
        self._original_packs: list[str] = []
        self._checkboxes: dict[str, QCheckBox] = {}

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QLabel("Enable the industry packs relevant to your environment.")
        header.setWordWrap(True)
        header.setStyleSheet(f"font-size: 13px; color: {COLORS['text_muted']};")
        layout.addWidget(header)

        settings = load_settings()
        self._original_packs = list(settings.get("enabled_packs", []))

        for pack_id, pack in INDUSTRY_PACKS.items():
            checkbox = QCheckBox(pack["label"])
            checkbox.setChecked(pack_id in self._original_packs)
            checkbox.setStyleSheet(f"""
                QCheckBox {{
                    font-size: 14px;
                    font-weight: 600;
                    color: {COLORS['text']};
                    spacing: 8px;
                }}
                QCheckBox::indicator {{
                    width: 18px;
                    height: 18px;
                    border: 2px solid {COLORS['border']};
                    border-radius: 4px;
                    background-color: {COLORS['bg_input']};
                }}
                QCheckBox::indicator:checked {{
                    background-color: {COLORS['accent']};
                    border-color: {COLORS['accent']};
                }}
            """)
            layout.addWidget(checkbox)

            desc = QLabel(pack["description"])
            desc.setWordWrap(True)
            desc.setStyleSheet(
                f"font-size: 11px; color: {COLORS['text_muted']}; "
                f"margin-left: 26px; margin-bottom: 8px;"
            )
            layout.addWidget(desc)

            self._checkboxes[pack_id] = checkbox

        layout.addStretch()

        note = QLabel("Changes take effect on next analysis run.")
        note.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']}; font-style: italic;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setStyleSheet(f"""
            QPushButton {{
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 600;
            }}
        """)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self):
        new_packs = [pid for pid, cb in self._checkboxes.items() if cb.isChecked()]
        self.changed = sorted(new_packs) != sorted(self._original_packs)
        if self.changed:
            save_settings({"enabled_packs": new_packs})
        self.accept()
