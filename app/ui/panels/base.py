"""Shared UI helpers for analyzer panels."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.ui.theme import COLORS, SEVERITY_COLORS


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


def make_table(headers: list[str], rows: list[list[str]], sortable: bool = True) -> QTableWidget:
    """Create a styled data table."""
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(False)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setEditTriggers(QTableWidget.NoEditTriggers)

    if sortable:
        table.setSortingEnabled(True)

    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            table.setItem(r, c, item)

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
