"""Dark theme colors and stylesheet for the application."""

COLORS = {
    "bg_dark": "#0a0a0f",
    "bg_panel": "#111118",
    "bg_card": "#1a1a24",
    "bg_input": "#22222e",
    "border": "#2a2a3a",
    "text": "#e4e4ed",
    "text_muted": "#8888a0",
    "accent": "#3b82f6",
    "accent_hover": "#2563eb",
    "success": "#22c55e",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6366f1",
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["critical"],
    "HIGH": COLORS["high"],
    "MEDIUM": COLORS["medium"],
    "LOW": COLORS["low"],
    "INFO": COLORS["info"],
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text']};
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 13px;
}}

QLabel {{
    color: {COLORS['text']};
}}

QLabel[class="muted"] {{
    color: {COLORS['text_muted']};
}}

QPushButton {{
    background-color: {COLORS['accent']};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
}}

QPushButton:hover {{
    background-color: {COLORS['accent_hover']};
}}

QPushButton:disabled {{
    background-color: {COLORS['bg_input']};
    color: {COLORS['text_muted']};
}}

QPushButton[class="outline"] {{
    background-color: transparent;
    border: 1px solid {COLORS['border']};
    color: {COLORS['text']};
}}

QPushButton[class="outline"]:hover {{
    background-color: {COLORS['bg_card']};
}}

QPushButton[class="danger"] {{
    background-color: {COLORS['danger']};
}}

QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    background-color: {COLORS['bg_panel']};
}}

QTabBar::tab {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_muted']};
    border: 1px solid {COLORS['border']};
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-size: 12px;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['accent']};
    border-bottom: 2px solid {COLORS['accent']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS['bg_input']};
}}

QTableWidget {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    gridline-color: {COLORS['border']};
    selection-background-color: {COLORS['bg_input']};
    font-size: 12px;
}}

QTableWidget::item {{
    padding: 6px 8px;
}}

QHeaderView::section {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_muted']};
    border: none;
    border-bottom: 1px solid {COLORS['border']};
    padding: 8px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
}}

QScrollBar:vertical {{
    background-color: {COLORS['bg_dark']};
    width: 8px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['border']};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['text_muted']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar:horizontal {{
    background-color: {COLORS['bg_dark']};
    height: 8px;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS['border']};
    border-radius: 4px;
    min-width: 30px;
}}

QProgressBar {{
    background-color: {COLORS['bg_input']};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {COLORS['accent']};
    border-radius: 4px;
}}

QListWidget {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text']};
    border: none;
    outline: none;
    font-size: 12px;
}}

QListWidget::item {{
    padding: 10px 12px;
    border-bottom: 1px solid {COLORS['border']};
}}

QListWidget::item:selected {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['accent']};
}}

QListWidget::item:hover:!selected {{
    background-color: {COLORS['bg_input']};
}}

QSplitter::handle {{
    background-color: {COLORS['border']};
    width: 1px;
}}
"""
