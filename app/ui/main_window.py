import json
import os
import sys

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.analysis.models import CaptureResult
from app.analysis.runner import AnalysisWorker
from app.ui.capture_dialog import CaptureDialog
from app.ui.dashboard import Dashboard
from app.ui.settings_dialog import SettingsDialog
from app.ui.theme import COLORS


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PCAP Detective")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self.captures: list[CaptureResult] = []
        self.current_worker: AnalysisWorker | None = None

        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)

        # Sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(264)
        sidebar.setStyleSheet(f"background-color: {COLORS['bg_panel']};")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Logo
        logo_container = QWidget()
        logo_container.setStyleSheet(f"background-color: {COLORS['bg_card']}; padding: 16px;")
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(16, 16, 16, 16)

        logo = QLabel("PCAP Detective")
        logo.setStyleSheet("font-size: 16px; font-weight: 700; color: white;")
        logo_layout.addWidget(logo)

        subtitle = QLabel("Desktop Threat Hunter")
        subtitle.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']};")
        logo_layout.addWidget(subtitle)

        sidebar_layout.addWidget(logo_container)

        # Open file button
        open_btn = QPushButton("Open PCAP File")
        open_btn.setStyleSheet(f"""
            QPushButton {{
                margin: 12px;
                padding: 10px;
                background-color: {COLORS['accent']};
                border-radius: 6px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_hover']}; }}
        """)
        open_btn.clicked.connect(self._open_file)
        sidebar_layout.addWidget(open_btn)

        # Live capture button
        capture_btn = QPushButton("Live Capture")
        capture_btn.setStyleSheet(f"""
            QPushButton {{
                margin: 0 12px 12px 12px;
                padding: 10px;
                background-color: transparent;
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                font-weight: 600;
                color: {COLORS['text']};
            }}
            QPushButton:hover {{ background-color: {COLORS['bg_card']}; }}
        """)
        capture_btn.clicked.connect(self._start_live_capture)
        sidebar_layout.addWidget(capture_btn)

        # Settings button
        settings_btn = QPushButton("Industry Packs")
        settings_btn.setStyleSheet(f"""
            QPushButton {{
                margin: 0 12px 12px 12px;
                padding: 10px;
                background-color: transparent;
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                font-weight: 600;
                color: {COLORS['text']};
            }}
            QPushButton:hover {{ background-color: {COLORS['bg_card']}; }}
        """)
        settings_btn.clicked.connect(self._open_settings)
        sidebar_layout.addWidget(settings_btn)

        # Progress bar
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; padding: 0 12px; font-size: 11px;")
        self.progress_label.hide()
        sidebar_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("margin: 4px 12px;")
        self.progress_bar.hide()
        sidebar_layout.addWidget(self.progress_bar)

        # Capture list
        list_header = QLabel("CAPTURES")
        list_header.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 12px 12px 6px 12px;
        """)
        sidebar_layout.addWidget(list_header)

        self.capture_list = QListWidget()
        self.capture_list.currentRowChanged.connect(self._on_capture_selected)
        sidebar_layout.addWidget(self.capture_list, 1)

        # Footer with logo and copyright
        footer = QWidget()
        footer.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-top: 1px solid {COLORS['border']};")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(12, 10, 12, 10)
        footer_layout.setSpacing(4)
        footer_layout.setAlignment(Qt.AlignCenter)

        # Logo — small and subtle
        logo_label = QLabel()
        logo_path = self._resource_path("app/resources/logo.png")
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaledToHeight(32, Qt.SmoothTransformation))
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setStyleSheet("border: none;")
        footer_layout.addWidget(logo_label)

        # Website link
        link = QLabel(f'<a href="https://bardsec.com" style="color: {COLORS["text_muted"]}; font-size: 10px; text-decoration: none;">bardsec.com</a>')
        link.setAlignment(Qt.AlignCenter)
        link.setOpenExternalLinks(True)
        link.setStyleSheet("border: none;")
        footer_layout.addWidget(link)

        # Copyright
        copyright_label = QLabel("\u00a9 2026 BardSec. All rights reserved.")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 9px; border: none; opacity: 0.6;")
        footer_layout.addWidget(copyright_label)

        sidebar_layout.addWidget(footer)

        splitter.addWidget(sidebar)

        # Main content
        self.dashboard = Dashboard()
        splitter.addWidget(self.dashboard)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def _open_settings(self):
        dialog = SettingsDialog(parent=self)
        dialog.exec()
        if dialog.changed and self.captures:
            reply = QMessageBox.question(
                self,
                "Settings Changed",
                "Industry packs changed. Re-analyze the current capture?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                idx = self.capture_list.currentRow()
                if 0 <= idx < len(self.captures):
                    cap = self.captures[idx]
                    self._start_analysis(cap.file_path)
        elif dialog.changed:
            # No capture loaded, just refresh dashboard if visible
            pass

    def _open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)",
        )
        if not file_path:
            return

        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.warning(
                self, "Analysis Running",
                "Please wait for the current analysis to complete."
            )
            return

        self._start_analysis(file_path)

    def _start_analysis(self, file_path: str):
        self.progress_label.setText("Loading...")
        self.progress_label.show()
        self.progress_bar.setValue(0)
        self.progress_bar.show()

        self.current_worker = AnalysisWorker(file_path)
        self.current_worker.progress.connect(self._on_progress)
        self.current_worker.finished.connect(self._on_analysis_complete)
        self.current_worker.error.connect(self._on_analysis_error)
        self.current_worker.start()

    def _on_progress(self, stage: str, percent: int):
        self.progress_label.setText(stage)
        self.progress_bar.setValue(percent)

    def _on_analysis_complete(self, result: CaptureResult):
        self.progress_label.hide()
        self.progress_bar.hide()
        self.current_worker = None

        self.captures.append(result)
        self._update_capture_list()

        # Select the new capture
        self.capture_list.setCurrentRow(len(self.captures) - 1)

    def _on_analysis_error(self, error_msg: str):
        self.progress_label.hide()
        self.progress_bar.hide()
        self.current_worker = None

        QMessageBox.critical(
            self, "Analysis Failed",
            f"Error analyzing PCAP file:\n\n{error_msg}"
        )

    def _update_capture_list(self):
        self.capture_list.clear()
        for capture in self.captures:
            status_icon = {
                "complete": "\u2705",
                "failed": "\u274c",
                "processing": "\u23f3",
            }.get(capture.status, "\u2022")

            size_mb = capture.file_size / (1024 * 1024)
            text = f"{status_icon}  {capture.filename}\n     {capture.packet_count:,} packets \u2022 {size_mb:.1f} MB"

            item = QListWidgetItem(text)
            self.capture_list.addItem(item)

    def _start_live_capture(self):
        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.warning(
                self, "Analysis Running",
                "Please wait for the current analysis to complete."
            )
            return

        dialog = CaptureDialog(self)
        if dialog.exec() and dialog.result_path:
            self._start_analysis(dialog.result_path)

    def _on_capture_selected(self, row: int):
        if 0 <= row < len(self.captures):
            self.dashboard.show_results(self.captures[row])

    @staticmethod
    def _resource_path(relative_path: str) -> str:
        """Get absolute path to resource, works for dev and PyInstaller."""
        if getattr(sys, "frozen", False):
            base = sys._MEIPASS
        else:
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        return os.path.join(base, relative_path)
