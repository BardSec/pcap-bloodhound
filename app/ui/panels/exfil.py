from PySide6.QtCharts import QBarSeries, QBarSet, QChart, QChartView, QBarCategoryAxis, QValueAxis
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class ExfilPanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: list[dict]):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        if not data:
            layout.addWidget(make_empty_state("No exfiltration indicators detected."))
            self.setWidget(container)
            return

        total_mb = sum(d.get("outbound_mb", 0) for d in data)
        layout.addWidget(make_card_row([
            make_card("Suspicious Flows", str(len(data)), COLORS["danger"]),
            make_card("Total Outbound", f"{total_mb:.1f} MB", COLORS["warning"]),
        ]))

        layout.addWidget(make_section_header("Exfiltration Flows"))
        rows = []
        for d in data:
            rows.append([
                d.get("src_ip", ""),
                d.get("dst_ip", ""),
                str(d.get("dst_port", "")),
                f"{d.get('outbound_mb', 0):.2f} MB",
                f"{d.get('inbound_kb', 0):.0f} KB",
                f"{d.get('ratio', 0):.1f}:1",
                f"{d.get('duration_sec', 0):.0f}s",
                d.get("severity", ""),
            ])
        table = make_table(
            ["Source", "Dest", "Port", "Outbound", "Inbound", "Ratio", "Duration", "Severity"],
            rows,
        )
        layout.addWidget(table)

        # Bar chart for top flows
        if len(data) > 0:
            layout.addWidget(make_section_header("Outbound vs Inbound (MB)"))
            chart = self._make_bar_chart(data[:10])
            layout.addWidget(chart)

        layout.addStretch()
        self.setWidget(container)

    def _make_bar_chart(self, flows: list[dict]) -> QChartView:
        outbound = QBarSet("Outbound")
        inbound = QBarSet("Inbound")
        outbound.setColor(QColor(COLORS["danger"]))
        inbound.setColor(QColor(COLORS["accent"]))

        categories = []
        for f in flows:
            outbound.append(f.get("outbound_mb", 0))
            inbound.append(f.get("inbound_kb", 0) / 1024)
            categories.append(f"{f.get('dst_ip', '')}:{f.get('dst_port', '')}")

        series = QBarSeries()
        series.append(outbound)
        series.append(inbound)

        chart = QChart()
        chart.addSeries(series)
        chart.setBackgroundBrush(QColor(COLORS["bg_card"]))
        chart.setTitleBrush(QColor(COLORS["text"]))
        chart.legend().setLabelColor(QColor(COLORS["text_muted"]))

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setTitleText("MB")
        axis_y.setLabelsColor(QColor(COLORS["text_muted"]))
        axis_y.setTitleBrush(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        view = QChartView(chart)
        view.setMinimumHeight(300)
        return view
