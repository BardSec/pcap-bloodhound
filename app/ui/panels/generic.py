"""Generic analyzer panel — renders any dict-of-lists analyzer result as cards + tables."""

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget, QLabel

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class GenericDictPanel(QScrollArea):
    """Renders a dict result with summary cards and tables for each list key."""

    def __init__(self, empty_message="No findings detected."):
        super().__init__()
        self.setWidgetResizable(True)
        self._empty_message = empty_message

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not data:
            layout.addWidget(make_empty_state(self._empty_message))
            self.setWidget(container)
            return

        # Summary cards from "summary" key
        summary = data.get("summary", {})
        if summary:
            cards = []
            for key, value in summary.items():
                label = key.replace("_", " ").title()
                if isinstance(value, bool):
                    color = COLORS["danger"] if value else COLORS["success"]
                    display = "Yes" if value else "No"
                elif isinstance(value, (int, float)):
                    color = COLORS["danger"] if value > 0 else COLORS["success"]
                    display = f"{value:,}" if isinstance(value, int) else f"{value:.1f}"
                elif isinstance(value, list):
                    color = COLORS["accent"]
                    display = ", ".join(str(v) for v in value) if value else "None"
                else:
                    color = COLORS["accent"]
                    display = str(value)
                cards.append(make_card(label, display, color))

            # Show up to 4 cards per row
            for i in range(0, len(cards), 4):
                layout.addWidget(make_card_row(cards[i:i + 4]))

        # Special banners
        if "detected_filter" in data and data["detected_filter"]:
            banner = QLabel(f"Detected content filter: {data['detected_filter']}")
            banner.setStyleSheet(f"""
                background-color: {COLORS['success']}22;
                color: {COLORS['success']};
                border: 1px solid {COLORS['success']}44;
                border-radius: 6px;
                padding: 10px 16px;
                font-weight: 600;
            """)
            layout.addWidget(banner)

        if data.get("summary", {}).get("storm_detected"):
            banner = QLabel("Broadcast storm detected!")
            banner.setStyleSheet(f"""
                background-color: {COLORS['critical']}22;
                color: {COLORS['critical']};
                border: 1px solid {COLORS['critical']}44;
                border-radius: 6px;
                padding: 10px 16px;
                font-weight: 600;
            """)
            layout.addWidget(banner)

        # Render each list key as a table
        for key, value in data.items():
            if key == "summary" or not isinstance(value, list) or not value:
                continue

            # Skip non-dict lists
            if not isinstance(value[0], dict):
                continue

            section_title = key.replace("_", " ").title()
            layout.addWidget(make_section_header(f"{section_title} ({len(value)})"))

            # Build table from dict keys
            headers = [k.replace("_", " ").title() for k in value[0].keys()
                       if k not in ("timestamp", "first_seen", "last_seen")
                       and not isinstance(value[0][k], (list, dict))]
            raw_keys = [k for k in value[0].keys()
                        if k not in ("timestamp", "first_seen", "last_seen")
                        and not isinstance(value[0][k], (list, dict))]

            rows = []
            for item in value[:100]:
                row = []
                for k in raw_keys:
                    v = item.get(k, "")
                    if isinstance(v, float):
                        row.append(f"{v:.2f}")
                    elif isinstance(v, bool):
                        row.append("Yes" if v else "No")
                    else:
                        row.append(str(v))
                rows.append(row)

            table = make_table(headers, rows)
            layout.addWidget(table)

        layout.addStretch()
        self.setWidget(container)
