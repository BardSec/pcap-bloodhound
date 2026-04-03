from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class C2BeaconPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: list[dict]):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not data:
            layout.addWidget(make_empty_state("No C2 beaconing patterns detected."))
            self.setWidget(container)
            return

        # Summary cards
        layout.addWidget(make_card_row([
            make_card("Suspicious Flows", str(len(data)), COLORS["danger"]),
            make_card("Lowest CV", f"{min(d['cv'] for d in data):.3f}", COLORS["warning"]),
        ]))

        # Table
        layout.addWidget(make_section_header("Detected Beacon Flows"))
        rows = []
        for d in data:
            rows.append([
                d.get("src_ip", ""),
                d.get("dst_ip", ""),
                str(d.get("dst_port", "")),
                d.get("protocol", ""),
                f"{d.get('cv', 0):.4f}",
                f"{d.get('mean_interval_sec', 0):.1f}s",
                str(d.get("connection_count", "")),
                d.get("severity", ""),
            ])
        table = make_table(
            ["Source IP", "Dest IP", "Port", "Proto", "CV", "Mean Interval", "Connections", "Severity"],
            rows,
        )
        layout.addWidget(table)

        # Chart for first beacon flow
        if data and data[0].get("interval_series"):
            layout.addWidget(make_section_header("Inter-Arrival Times (Top Flow)"))
            chart = self._make_interval_chart(data[0])
            layout.addWidget(chart)

        layout.addStretch()
        self.setWidget(container)

    def _make_interval_chart(self, flow: dict) -> QChartView:
        series = QLineSeries()
        intervals = flow.get("interval_series", [])
        for i, val in enumerate(intervals):
            series.append(i, val)

        pen = QPen(QColor(COLORS["accent"]))
        pen.setWidth(2)
        series.setPen(pen)

        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("Inter-Arrival Time (seconds)")
        chart.setTitleBrush(QColor(COLORS["text"]))
        chart.setBackgroundBrush(QColor(COLORS["bg_card"]))
        chart.legend().hide()

        axis_x = QValueAxis()
        axis_x.setTitleText("Packet #")
        axis_x.setLabelFormat("%d")
        axis_x.setLabelsColor(QColor(COLORS["text_muted"]))
        axis_x.setTitleBrush(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setTitleText("Seconds")
        axis_y.setLabelFormat("%.1f")
        axis_y.setLabelsColor(QColor(COLORS["text_muted"]))
        axis_y.setTitleBrush(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        view = QChartView(chart)
        view.setMinimumHeight(300)
        view.setStyleSheet(f"background-color: {COLORS['bg_card']}; border-radius: 8px;")
        return view
