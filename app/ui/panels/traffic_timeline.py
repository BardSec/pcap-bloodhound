from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from app.ui.panels.base import make_card, make_card_row, make_empty_state, make_section_header, make_table
from app.ui.theme import COLORS


class TrafficTimelinePanel(QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)

    def load(self, data: dict):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        timeline = data.get("timeline", [])
        spikes = data.get("spikes", [])
        gaps = data.get("gaps", [])
        conversations = data.get("top_conversations", [])
        endpoints = data.get("top_endpoints", [])
        summary = data.get("summary", {})

        if not timeline:
            layout.addWidget(make_empty_state("No traffic timeline data available."))
            self.setWidget(container)
            return

        total_bytes = summary.get("total_bytes", 0)
        total_pkts = summary.get("total_packets", 0)
        duration = summary.get("duration_sec", 0)

        layout.addWidget(make_card_row([
            make_card("Total Packets", f"{total_pkts:,}", COLORS["accent"]),
            make_card("Total Bytes", self._format_bytes(total_bytes), COLORS["accent"]),
            make_card("Duration", f"{duration:.1f}s", COLORS["accent"]),
            make_card("Spikes", str(len(spikes)), COLORS["warning"]),
        ]))

        # IO Graph
        layout.addWidget(make_section_header("Packets Per Second"))
        chart = self._make_timeline_chart(timeline, "pps", "PPS", COLORS["accent"])
        layout.addWidget(chart)

        layout.addWidget(make_section_header("Bytes Per Second"))
        chart2 = self._make_timeline_chart(timeline, "bps", "BPS", COLORS["success"])
        layout.addWidget(chart2)

        if spikes:
            layout.addWidget(make_section_header(f"Traffic Spikes ({len(spikes)})"))
            rows = [[
                f"{s.get('t', 0):.1f}s", str(s.get("pkts", 0)),
                f"{s.get('pps', 0):.0f}", f"{s.get('ratio', 0):.1f}x",
            ] for s in spikes[:20]]
            layout.addWidget(make_table(["Time", "Packets", "PPS", "Ratio vs Avg"], rows))

        if conversations:
            layout.addWidget(make_section_header("Top Conversations"))
            rows = [[
                f"{c.get('ip_a', '')}:{c.get('port_a', '')}",
                f"{c.get('ip_b', '')}:{c.get('port_b', '')}",
                c.get("proto", ""), str(c.get("packets", 0)),
                self._format_bytes(c.get("bytes", 0)),
                f"{c.get('duration_s', 0):.1f}s",
            ] for c in conversations[:20]]
            layout.addWidget(make_table(
                ["Endpoint A", "Endpoint B", "Proto", "Packets", "Bytes", "Duration"], rows
            ))

        if endpoints:
            layout.addWidget(make_section_header("Top Endpoints"))
            rows = [[
                e.get("ip", ""), self._format_bytes(e.get("bytes_total", 0)),
                self._format_bytes(e.get("bytes_sent", 0)),
                self._format_bytes(e.get("bytes_recv", 0)),
                str(e.get("pkts_total", 0)),
            ] for e in endpoints[:20]]
            layout.addWidget(make_table(
                ["IP", "Total Bytes", "Sent", "Received", "Packets"], rows
            ))

        layout.addStretch()
        self.setWidget(container)

    def _make_timeline_chart(self, timeline: list[dict], key: str, title: str, color: str) -> QChartView:
        series = QLineSeries()
        for point in timeline:
            series.append(point.get("t", 0), point.get(key, 0))

        pen = QPen(QColor(color))
        pen.setWidth(2)
        series.setPen(pen)

        chart = QChart()
        chart.addSeries(series)
        chart.setBackgroundBrush(QColor(COLORS["bg_card"]))
        chart.legend().hide()

        axis_x = QValueAxis()
        axis_x.setTitleText("Time (seconds)")
        axis_x.setLabelsColor(QColor(COLORS["text_muted"]))
        axis_x.setTitleBrush(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setTitleText(title)
        axis_y.setLabelsColor(QColor(COLORS["text_muted"]))
        axis_y.setTitleBrush(QColor(COLORS["text_muted"]))
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        view = QChartView(chart)
        view.setMinimumHeight(250)
        return view

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b >= 1_073_741_824:
            return f"{b / 1_073_741_824:.1f} GB"
        if b >= 1_048_576:
            return f"{b / 1_048_576:.1f} MB"
        if b >= 1024:
            return f"{b / 1024:.1f} KB"
        return f"{b} B"
