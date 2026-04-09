"""Investigation Threads panel — entity-centric investigation view.

Groups findings around hosts, domains, and endpoints. Each thread shows a
narrative summary, confidence-scored findings with indicator evidence,
and a timeline of related events.
"""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QColor, QCursor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.analysis.findings import Finding, InvestigationThread, TimelineEvent
from app.ui.panels.base import make_card, make_card_row, make_section_header
from app.ui.theme import COLORS, SEVERITY_COLORS


# ─── Small UI helpers ─────────────────────────────────────────────────────────

def _confidence_badge(confidence: int) -> QLabel:
    """Colored badge showing confidence percentage."""
    if confidence >= 80:
        bg, fg = COLORS["critical"], "#fff"
    elif confidence >= 60:
        bg, fg = COLORS["high"], "#fff"
    elif confidence >= 40:
        bg, fg = COLORS["warning"], "#000"
    else:
        bg, fg = COLORS["info"], "#fff"

    badge = QLabel(f"{confidence}%")
    badge.setAlignment(Qt.AlignCenter)
    badge.setFixedSize(44, 22)
    badge.setStyleSheet(f"""
        background-color: {bg};
        color: {fg};
        border-radius: 4px;
        font-size: 11px;
        font-weight: 700;
    """)
    return badge


def _severity_pill(severity: str) -> QLabel:
    color = SEVERITY_COLORS.get(severity, COLORS["text_muted"])
    pill = QLabel(severity)
    pill.setAlignment(Qt.AlignCenter)
    pill.setFixedHeight(20)
    pill.setStyleSheet(f"""
        background-color: {color}22;
        color: {color};
        border: 1px solid {color}44;
        border-radius: 3px;
        padding: 1px 8px;
        font-size: 10px;
        font-weight: 700;
    """)
    return pill


def _make_entity_link(entity: str, on_click=None) -> QLabel:
    """Create a clickable entity label that triggers a pivot callback."""
    label = QLabel(entity)
    label.setStyleSheet(f"""
        color: {COLORS['accent']};
        font-size: 12px;
        font-weight: 500;
        padding: 2px 6px;
        border: 1px solid {COLORS['accent']}33;
        border-radius: 3px;
        background-color: {COLORS['accent']}0d;
    """)
    label.setCursor(QCursor(Qt.PointingHandCursor))
    if on_click:
        label.mousePressEvent = lambda _event, e=entity: on_click(e)
    return label


def _entity_type_label(entity_type: str) -> str:
    return {
        "internal_host": "Internal Host",
        "external_host": "External Endpoint",
        "domain": "Domain",
    }.get(entity_type, entity_type.replace("_", " ").title())


def _risk_color(score: int) -> str:
    if score >= 80:
        return COLORS["critical"]
    if score >= 60:
        return COLORS["high"]
    if score >= 40:
        return COLORS["warning"]
    return COLORS["info"]


# ─── Finding Card ─────────────────────────────────────────────────────────────

def _make_finding_card(finding: Finding, on_entity_click=None) -> QWidget:
    """Render a single finding with confidence, indicators, and explanations."""
    card = QWidget()
    card.setStyleSheet(f"""
        QWidget#findingCard {{
            background-color: {COLORS['bg_card']};
            border: 1px solid {COLORS['border']};
            border-radius: 8px;
        }}
    """)
    card.setObjectName("findingCard")

    layout = QVBoxLayout(card)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)

    # Header row: title + badges
    header = QHBoxLayout()
    header.setSpacing(8)

    title = QLabel(finding.title)
    title.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px; font-weight: 600; border: none;")
    header.addWidget(title, 1)

    header.addWidget(_confidence_badge(finding.confidence))
    header.addWidget(_severity_pill(finding.severity))
    layout.addLayout(header)

    # Description
    desc = QLabel(finding.description)
    desc.setWordWrap(True)
    desc.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px; border: none; line-height: 1.3;")
    layout.addWidget(desc)

    # Indicators section: "Why was this flagged?"
    ind_header = QLabel("Why was this flagged?")
    ind_header.setStyleSheet(f"""
        color: {COLORS['text_muted']};
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding-top: 4px;
        border: none;
    """)
    layout.addWidget(ind_header)

    for indicator in finding.indicators:
        ind_row = QHBoxLayout()
        ind_row.setContentsMargins(0, 0, 0, 0)
        ind_row.setSpacing(6)

        # Met/unmet icon
        icon_text = "+" if indicator.met else "-"
        icon_color = COLORS["success"] if indicator.met else COLORS["text_muted"]
        icon = QLabel(icon_text)
        icon.setFixedWidth(14)
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet(f"color: {icon_color}; font-size: 13px; font-weight: 700; border: none;")
        ind_row.addWidget(icon)

        # Description + detail
        if indicator.detail:
            text = f"{indicator.description} — {indicator.detail}"
        else:
            text = indicator.description
        ind_label = QLabel(text)
        ind_label.setWordWrap(True)
        color = COLORS["text"] if indicator.met else COLORS["text_muted"]
        ind_label.setStyleSheet(f"color: {color}; font-size: 11px; border: none;")
        ind_row.addWidget(ind_label, 1)

        ind_container = QWidget()
        ind_container.setLayout(ind_row)
        ind_container.setStyleSheet("border: none;")
        layout.addWidget(ind_container)

    # Alternative explanations
    if finding.alternative_explanations:
        alt_header = QLabel("Could also be")
        alt_header.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding-top: 4px;
            border: none;
        """)
        layout.addWidget(alt_header)

        for explanation in finding.alternative_explanations:
            alt = QLabel(f"  {explanation}")
            alt.setWordWrap(True)
            alt.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border: none;")
            layout.addWidget(alt)

    # Clickable entity pills
    if finding.entities and on_entity_click:
        ent_row = QHBoxLayout()
        ent_row.setContentsMargins(0, 4, 0, 0)
        ent_row.setSpacing(4)
        ent_label = QLabel("Entities:")
        ent_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px; font-weight: 700; border: none;")
        ent_label.setFixedWidth(52)
        ent_row.addWidget(ent_label)
        for entity in finding.entities[:8]:
            ent_row.addWidget(_make_entity_link(entity, on_entity_click))
        ent_row.addStretch()
        ent_container = QWidget()
        ent_container.setLayout(ent_row)
        ent_container.setStyleSheet("border: none;")
        layout.addWidget(ent_container)

    return card


# ─── Timeline ─────────────────────────────────────────────────────────────────

def _make_timeline(events: list[TimelineEvent]) -> QWidget:
    """Render a vertical timeline of events."""
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)

    for event in events[:50]:  # Cap at 50 events
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        # Severity dot
        dot_color = SEVERITY_COLORS.get(event.severity, COLORS["text_muted"])
        dot = QLabel("\u25cf")
        dot.setFixedWidth(12)
        dot.setStyleSheet(f"color: {dot_color}; font-size: 10px; border: none;")
        dot.setAlignment(Qt.AlignCenter | Qt.AlignTop)
        row.addWidget(dot)

        # Event type tag
        tag = QLabel(event.event_type.replace("_", " "))
        tag.setFixedWidth(90)
        tag.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 10px;
            font-weight: 600;
            border: none;
        """)
        tag.setAlignment(Qt.AlignRight | Qt.AlignTop)
        row.addWidget(tag)

        # Description
        desc = QLabel(event.description)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {COLORS['text']}; font-size: 11px; border: none;")
        row.addWidget(desc, 1)

        row_widget = QWidget()
        row_widget.setLayout(row)
        row_widget.setStyleSheet(f"""
            QWidget {{
                border-bottom: 1px solid {COLORS['border']};
                padding: 6px 0;
            }}
        """)
        layout.addWidget(row_widget)

    if not events:
        empty = QLabel("No timeline events available")
        empty.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        empty.setAlignment(Qt.AlignCenter)
        layout.addWidget(empty)

    return container


# ─── Thread Detail ────────────────────────────────────────────────────────────

def _make_thread_detail(thread: InvestigationThread, on_entity_click=None) -> QWidget:
    """Render the full detail view for a single investigation thread."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.NoFrame)

    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(16, 12, 16, 16)
    layout.setSpacing(12)

    # Entity header
    entity_header = QHBoxLayout()

    entity_label = QLabel(thread.entity)
    entity_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 18px; font-weight: 700;")
    entity_header.addWidget(entity_label)

    type_label = QLabel(_entity_type_label(thread.entity_type))
    type_label.setStyleSheet(f"""
        color: {COLORS['text_muted']};
        font-size: 11px;
        background-color: {COLORS['bg_input']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        padding: 2px 8px;
    """)
    entity_header.addWidget(type_label)

    entity_header.addStretch()

    # Risk score badge
    risk_color = _risk_color(thread.risk_score)
    risk_badge = QLabel(f"Risk: {thread.risk_score}")
    risk_badge.setAlignment(Qt.AlignCenter)
    risk_badge.setStyleSheet(f"""
        background-color: {risk_color}22;
        color: {risk_color};
        border: 1px solid {risk_color}44;
        border-radius: 4px;
        padding: 4px 12px;
        font-size: 12px;
        font-weight: 700;
    """)
    entity_header.addWidget(risk_badge)

    layout.addLayout(entity_header)

    # Summary
    summary = QLabel(thread.summary)
    summary.setWordWrap(True)
    summary.setStyleSheet(f"""
        color: {COLORS['text']};
        font-size: 12px;
        background-color: {COLORS['bg_card']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 10px 14px;
        line-height: 1.4;
    """)
    layout.addWidget(summary)

    # Stats cards
    cards = [
        make_card("Findings", str(len(thread.findings)), _risk_color(thread.risk_score)),
        make_card("Timeline Events", str(len(thread.timeline)), COLORS["accent"]),
        make_card("Related Entities", str(len(thread.related_entities)), COLORS["info"]),
    ]
    if thread.metadata:
        packets = thread.metadata.get("packets", 0)
        if packets:
            cards.append(make_card("Packets", f"{packets:,}", COLORS["text_muted"]))
    layout.addWidget(make_card_row(cards))

    # Related entities (clickable)
    if thread.related_entities:
        layout.addWidget(make_section_header("Related Entities"))
        related_container = QWidget()
        related_container.setStyleSheet(f"""
            QWidget#relatedBox {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
        """)
        related_container.setObjectName("relatedBox")
        related_layout = QHBoxLayout(related_container)
        related_layout.setContentsMargins(10, 8, 10, 8)
        related_layout.setSpacing(6)
        for ent in thread.related_entities[:15]:
            related_layout.addWidget(_make_entity_link(ent, on_entity_click))
        related_layout.addStretch()
        layout.addWidget(related_container)

    # Findings
    layout.addWidget(make_section_header(f"Findings ({len(thread.findings)})"))
    for finding in thread.findings:
        layout.addWidget(_make_finding_card(finding, on_entity_click=on_entity_click))

    # Timeline
    if thread.timeline:
        layout.addWidget(make_section_header(f"Timeline ({len(thread.timeline)} events)"))
        layout.addWidget(_make_timeline(thread.timeline))

    layout.addStretch()
    scroll.setWidget(container)
    return scroll


# ─── Main Panel ───────────────────────────────────────────────────────────────

class InvestigationPanel(QWidget):
    """Investigation Threads panel — split view with thread list and detail."""

    # Emitted when user clicks an entity that has no thread in this panel.
    # The dashboard can listen to this if needed for future cross-panel pivots.
    entity_pivot_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self._threads: list[InvestigationThread] = []
        self._detail_widgets: dict[int, QWidget] = {}
        self._entity_to_row: dict[str, int] = {}
        self._build_ui()

    def _build_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)

        # Thread list (left)
        self._thread_list = QListWidget()
        self._thread_list.setFixedWidth(280)
        self._thread_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS['bg_panel']};
                border: none;
                border-right: 1px solid {COLORS['border']};
                outline: none;
            }}
            QListWidget::item {{
                padding: 4px 6px;
                border-bottom: 1px solid {COLORS['border']};
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['accent']}18;
                border-left: 3px solid {COLORS['accent']};
                padding-left: 3px;
            }}
            QListWidget::item:hover:!selected {{
                background-color: {COLORS['bg_card']};
            }}
        """)
        self._thread_list.currentRowChanged.connect(self._on_thread_selected)
        splitter.addWidget(self._thread_list)

        # Detail area (right)
        self._detail_area = QWidget()
        self._detail_layout = QVBoxLayout(self._detail_area)
        self._detail_layout.setContentsMargins(0, 0, 0, 0)

        # Empty state
        self._empty = QLabel("Select a thread to view details")
        self._empty.setAlignment(Qt.AlignCenter)
        self._empty.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px;")
        self._detail_layout.addWidget(self._empty)

        splitter.addWidget(self._detail_area)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def load(self, threads: list[InvestigationThread], description: str = ""):
        self._threads = threads
        self._detail_widgets.clear()
        self._entity_to_row.clear()
        self._thread_list.clear()

        # Clear detail area
        while self._detail_layout.count():
            child = self._detail_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not threads:
            empty = QLabel(
                "No investigation threads generated.\n\n"
                "Threads are created when detections with sufficient confidence "
                "can be correlated around a common entity (host, domain, or endpoint)."
            )
            empty.setAlignment(Qt.AlignCenter)
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px; padding: 40px;")
            self._detail_layout.addWidget(empty)
            return

        # Build entity -> row index for pivot navigation
        for i, thread in enumerate(threads):
            self._entity_to_row[thread.entity] = i

        # Populate thread list
        for thread in threads:
            risk_color = _risk_color(thread.risk_score)
            finding_count = len(thread.findings)

            item = QListWidgetItem()
            item_widget = QWidget()
            item_layout = QVBoxLayout(item_widget)
            item_layout.setContentsMargins(8, 6, 8, 6)
            item_layout.setSpacing(3)

            # Entity name + risk
            top_row = QHBoxLayout()
            top_row.setContentsMargins(0, 0, 0, 0)
            top_row.setSpacing(6)
            name = QLabel(thread.entity)
            name.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px; font-weight: 600;")
            top_row.addWidget(name, 1)

            score = QLabel(str(thread.risk_score))
            score.setAlignment(Qt.AlignCenter)
            score.setFixedSize(32, 20)
            score.setStyleSheet(f"""
                background-color: {risk_color}33;
                color: {risk_color};
                border-radius: 3px;
                font-size: 11px;
                font-weight: 700;
            """)
            top_row.addWidget(score)
            item_layout.addLayout(top_row)

            # Type + finding count
            meta = QLabel(f"{_entity_type_label(thread.entity_type)} \u2022 {finding_count} finding{'s' if finding_count != 1 else ''}")
            meta.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
            item_layout.addWidget(meta)

            item.setSizeHint(QSize(260, 52))
            self._thread_list.addItem(item)
            self._thread_list.setItemWidget(item, item_widget)

        # Show empty state in detail
        self._empty = QLabel("Select a thread to view details")
        self._empty.setAlignment(Qt.AlignCenter)
        self._empty.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px;")
        self._detail_layout.addWidget(self._empty)

        # Auto-select first thread
        if threads:
            self._thread_list.setCurrentRow(0)

    def navigate_to_entity(self, entity: str):
        """Navigate to the thread for the given entity, if one exists."""
        row = self._entity_to_row.get(entity)
        if row is not None:
            self._thread_list.setCurrentRow(row)
        else:
            self.entity_pivot_requested.emit(entity)

    def _on_entity_clicked(self, entity: str):
        """Handle click on an entity link within a thread detail."""
        self.navigate_to_entity(entity)

    def _on_thread_selected(self, row: int):
        if row < 0 or row >= len(self._threads):
            return

        # Clear detail area
        while self._detail_layout.count():
            child = self._detail_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Build or reuse detail widget
        if row not in self._detail_widgets:
            self._detail_widgets[row] = _make_thread_detail(
                self._threads[row],
                on_entity_click=self._on_entity_clicked,
            )
        self._detail_layout.addWidget(self._detail_widgets[row])
