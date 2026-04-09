"""Shared UI helpers for analyzer panels."""

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import COLORS, SEVERITY_COLORS

# Pattern matching IPs and domain-like strings for pivot actions
_IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$')

# Global callback for entity investigation pivots — set by Dashboard
_investigate_callback = None


def set_investigate_callback(callback):
    """Register a global callback for 'Investigate' pivot actions from tables."""
    global _investigate_callback
    _investigate_callback = callback


def make_card(title: str, value: str, color: str = COLORS["accent"]) -> QWidget:
    """Create a stat card widget."""
    card = QWidget()
    card.setStyleSheet(f"""
        QWidget {{
            background-color: {COLORS['bg_card']};
            border: 1px solid {COLORS['border']};
            border-radius: 8px;
            padding: 16px;
        }}
    """)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 12, 16, 12)

    lbl_title = QLabel(title)
    lbl_title.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; font-weight: 600; border: none;")
    layout.addWidget(lbl_title)

    lbl_value = QLabel(value)
    lbl_value.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: 700; border: none;")
    layout.addWidget(lbl_value)

    return card


def make_severity_badge(severity: str) -> QLabel:
    """Create a colored severity badge."""
    color = SEVERITY_COLORS.get(severity, COLORS["text_muted"])
    badge = QLabel(severity)
    badge.setStyleSheet(f"""
        background-color: {color}22;
        color: {color};
        border: 1px solid {color}44;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 10px;
        font-weight: 700;
    """)
    badge.setAlignment(Qt.AlignCenter)
    badge.setFixedHeight(22)
    return badge


class RowDetailDialog(QDialog):
    """Modal dialog showing full details for a table row."""

    def __init__(self, headers: list[str], values: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Row Details")
        self.setMinimumWidth(520)
        self.setMaximumHeight(600)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text']};
            }}
        """)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        for header, value in zip(headers, values):
            field = QWidget()
            field.setStyleSheet(f"""
                QWidget {{
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {COLORS['border']};
                    border-radius: 6px;
                }}
            """)
            field_layout = QVBoxLayout(field)
            field_layout.setContentsMargins(12, 10, 12, 10)
            field_layout.setSpacing(4)

            lbl_header = QLabel(header)
            lbl_header.setStyleSheet(f"""
                color: {COLORS['text_muted']};
                font-size: 10px;
                font-weight: 700;
                text-transform: uppercase;
                border: none;
            """)
            field_layout.addWidget(lbl_header)

            lbl_value = QLabel(str(value))
            lbl_value.setWordWrap(True)
            lbl_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lbl_value.setStyleSheet(f"""
                color: {COLORS['text']};
                font-size: 13px;
                border: none;
            """)
            field_layout.addWidget(lbl_value)

            layout.addWidget(field)

        layout.addStretch()
        scroll.setWidget(container)
        outer.addWidget(scroll)


def make_table(headers: list[str], rows: list[list[str]], sortable: bool = True) -> QTableWidget:
    """Create a styled data table. Double-click a row to see full details."""
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(False)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setToolTip("Double-click a row to view full details")

    if sortable:
        table.setSortingEnabled(True)

    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            table.setItem(r, c, item)

    def _on_double_click(item):
        row_idx = item.row()
        col_count = table.columnCount()
        row_values = [table.item(row_idx, c).text() if table.item(row_idx, c) else "" for c in range(col_count)]
        dlg = RowDetailDialog(headers, row_values, parent=table)
        dlg.exec()

    table.itemDoubleClicked.connect(_on_double_click)

    # Right-click context menu for entity investigation pivots
    table.setContextMenuPolicy(Qt.CustomContextMenu)

    def _on_context_menu(pos):
        item = table.itemAt(pos)
        if not item:
            return
        text = item.text().strip()
        if not (_IP_PATTERN.match(text) or _DOMAIN_PATTERN.match(text)):
            return
        if not _investigate_callback:
            return

        menu = QMenu(table)
        action = menu.addAction(f"Investigate {text}")
        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen == action:
            _investigate_callback(text)

    table.customContextMenuRequested.connect(_on_context_menu)

    return table


def make_section_header(text: str) -> QLabel:
    """Create a section header label."""
    label = QLabel(text)
    label.setStyleSheet(f"""
        font-size: 15px;
        font-weight: 700;
        color: {COLORS['text']};
        padding: 8px 0;
    """)
    return label


def make_card_row(cards: list[QWidget]) -> QWidget:
    """Layout multiple stat cards in a horizontal row."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(12)
    for card in cards:
        layout.addWidget(card)
    return row


def make_description_banner(text: str) -> QWidget:
    """Create an informational banner explaining what an analyzer does."""
    banner = QLabel(text)
    banner.setWordWrap(True)
    banner.setStyleSheet(f"""
        background-color: {COLORS['accent']}12;
        color: {COLORS['text_muted']};
        border: 1px solid {COLORS['accent']}25;
        border-radius: 6px;
        padding: 10px 14px;
        font-size: 12px;
        line-height: 1.4;
    """)
    return banner


def make_empty_state(message: str) -> QWidget:
    """Create an empty state placeholder."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setAlignment(Qt.AlignCenter)
    label = QLabel(message)
    label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px;")
    label.setAlignment(Qt.AlignCenter)
    layout.addWidget(label)
    return widget
