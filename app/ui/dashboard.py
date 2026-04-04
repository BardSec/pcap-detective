import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.analysis.models import CaptureResult
from app.ui.panels.c2_beacon import C2BeaconPanel
from app.ui.panels.cleartext import CleartextPanel
from app.ui.panels.connection_failures import ConnectionFailuresPanel
from app.ui.panels.dns_health import DnsHealthPanel
from app.ui.panels.dns_tunnel import DnsTunnelPanel
from app.ui.panels.exfil import ExfilPanel
from app.ui.panels.ntlm import NtlmPanel
from app.ui.panels.tls_inspect import TlsInspectPanel
from app.ui.panels.traffic_timeline import TrafficTimelinePanel
from app.ui.panels.generic import GenericDictPanel
from app.ui.panels.base import make_card, make_card_row, make_section_header
from app.ui.theme import COLORS

# Each entry: (label, attr, PanelClass, is_list) for custom panels
#             (label, attr, None, empty_message) for generic panels
ANALYZER_CATEGORIES = [
    {
        "name": "Threat Hunting",
        "analyzers": [
            ("C2 Beaconing", "c2_beaconing", C2BeaconPanel, True),
            ("DNS Tunneling", "dns_tunneling", DnsTunnelPanel, False),
            ("NTLM Hashes", "ntlm", NtlmPanel, True),
            ("Cleartext Creds", "cleartext_creds", CleartextPanel, True),
            ("Exfiltration", "exfiltration", ExfilPanel, True),
        ],
    },
    {
        "name": "Attack Path",
        "analyzers": [
            ("Lateral Movement", "lateral_movement", None, "No lateral movement detected."),
            ("DGA Detection", "dga_detection", None, "No DGA domains detected."),
            ("Data Staging", "data_staging", None, "No data staging patterns detected."),
            ("User-Agents", "suspicious_useragents", None, "No suspicious user agents detected."),
            ("PS/WMI", "powershell_wmi", None, "No PowerShell/WMI network activity detected."),
        ],
    },
    {
        "name": "K-12 Specific",
        "analyzers": [
            ("Filter Bypass", "content_filter_bypass", None, "No content filter bypass attempts detected."),
            ("CIPA Compliance", "cipa_compliance", None, "No web traffic to analyze for CIPA compliance."),
        ],
    },
    {
        "name": "Network Visibility",
        "analyzers": [
            ("Blocked Connections", "connection_failures", ConnectionFailuresPanel, False),
            ("DNS Health", "dns_health", DnsHealthPanel, False),
            ("TLS/SSL", "tls_inspection", TlsInspectPanel, False),
            ("Traffic Timeline", "traffic_timeline", TrafficTimelinePanel, False),
            ("VLAN Traffic", "vlan_traffic", None, "No VLAN-tagged traffic detected."),
            ("DHCP", "dhcp", None, "No DHCP traffic detected."),
            ("Broadcast/Multicast", "broadcast_storms", None, "No broadcast storm indicators."),
            ("Services", "services", None, "No network services detected."),
        ],
    },
]


class OverviewPanel(QScrollArea):
    """Summary dashboard showing finding counts for all analyzers."""

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)

    def load(self, result: CaptureResult):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 8, 16, 16)
        layout.setSpacing(16)

        for category in ANALYZER_CATEGORIES:
            layout.addWidget(make_section_header(category["name"]))

            cards = []
            for analyzer in category["analyzers"]:
                label, attr = analyzer[0], analyzer[1]
                count = result.finding_count(attr)

                if count > 0:
                    if category["name"] == "Threat Hunting":
                        color = COLORS["danger"]
                    else:
                        color = COLORS["warning"]
                else:
                    color = COLORS["success"]

                cards.append(make_card(label, str(count), color))

                # Flush row at 4 cards
                if len(cards) == 4:
                    layout.addWidget(make_card_row(cards))
                    cards = []

            if cards:
                layout.addWidget(make_card_row(cards))

        layout.addStretch()
        self.setWidget(container)


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self._result: CaptureResult | None = None
        self._nav_to_stack: dict[int, int] = {}
        self._build_ui()

    def _build_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Welcome screen (shown when no capture is selected)
        self.welcome = QWidget()
        welcome_layout = QVBoxLayout(self.welcome)
        welcome_layout.setAlignment(Qt.AlignCenter)

        title = QLabel("Open a PCAP file to begin")
        title.setStyleSheet(f"font-size: 20px; color: {COLORS['text_muted']}; font-weight: 600;")
        title.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(title)

        subtitle = QLabel("Supports .pcap, .pcapng, and .cap files")
        subtitle.setStyleSheet(f"font-size: 13px; color: {COLORS['text_muted']};")
        subtitle.setAlignment(Qt.AlignCenter)
        welcome_layout.addWidget(subtitle)

        # Dashboard (shown when a capture is selected)
        self.dashboard_widget = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard_widget)
        self.dashboard_layout.setContentsMargins(16, 16, 16, 16)
        self.dashboard_layout.setSpacing(12)

        # Header bar
        self.header = QWidget()
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(0, 0, 0, 0)

        self.filename_label = QLabel("")
        self.filename_label.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {COLORS['text']};")
        header_layout.addWidget(self.filename_label)

        self.meta_label = QLabel("")
        self.meta_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_muted']};")
        header_layout.addWidget(self.meta_label)

        header_layout.addStretch()

        self.export_btn = QPushButton("Export JSON")
        self.export_btn.setProperty("class", "outline")
        self.export_btn.clicked.connect(self._export_json)
        header_layout.addWidget(self.export_btn)

        self.dashboard_layout.addWidget(self.header)

        # Content area: nav list + panel stack
        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setHandleWidth(1)

        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(210)
        self.nav_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS['bg_panel']};
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-top: 1px solid {COLORS['border']};
                border-top-left-radius: 6px;
                outline: none;
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 7px 12px 7px 16px;
                border: none;
                border-bottom: none;
            }}
            QListWidget::item:selected {{
                background-color: {COLORS['accent']}18;
                color: {COLORS['accent']};
                border-left: 3px solid {COLORS['accent']};
                padding-left: 13px;
            }}
            QListWidget::item:hover:!selected {{
                background-color: {COLORS['bg_card']};
            }}
        """)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)

        self.panel_stack = QStackedWidget()
        self.panel_stack.setStyleSheet(f"""
            QStackedWidget {{
                border: 1px solid {COLORS['border']};
                border-left: none;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
                background-color: {COLORS['bg_panel']};
            }}
        """)

        content_splitter.addWidget(self.nav_list)
        content_splitter.addWidget(self.panel_stack)
        content_splitter.setStretchFactor(0, 0)
        content_splitter.setStretchFactor(1, 1)

        self.dashboard_layout.addWidget(content_splitter, 1)

        # Stack
        self.stack = QStackedWidget()
        self.stack.addWidget(self.welcome)
        self.stack.addWidget(self.dashboard_widget)
        self.layout.addWidget(self.stack)

    def show_results(self, result: CaptureResult):
        self._result = result

        # Update header
        self.filename_label.setText(result.filename)
        size_mb = result.file_size / (1024 * 1024)
        ts = result.completed_at.strftime("%Y-%m-%d %H:%M") if result.completed_at else ""
        self.meta_label.setText(f"{result.packet_count:,} packets  \u2022  {size_mb:.1f} MB  \u2022  {ts}")

        # Clear previous state
        self.nav_list.clear()
        while self.panel_stack.count():
            w = self.panel_stack.widget(0)
            self.panel_stack.removeWidget(w)
            w.deleteLater()
        self._nav_to_stack.clear()

        # Stack index 0: Overview panel
        overview = OverviewPanel()
        overview.load(result)
        self.panel_stack.addWidget(overview)

        # Build analyzer panels (stack indices 1+)
        stack_idx = 1
        for category in ANALYZER_CATEGORIES:
            for analyzer in category["analyzers"]:
                label, attr, panel_class_or_none = analyzer[0], analyzer[1], analyzer[2]
                fourth = analyzer[3]

                if panel_class_or_none is not None:
                    # Custom panel
                    panel = panel_class_or_none()
                    is_list = fourth
                    data = getattr(result, attr, [] if is_list else {})
                    panel.load(data)
                else:
                    # Generic panel
                    empty_msg = fourth
                    panel = GenericDictPanel(empty_message=empty_msg)
                    data = getattr(result, attr, {})
                    panel.load(data)

                self.panel_stack.addWidget(panel)
                stack_idx += 1

        # Build nav list
        self._build_nav_list(result)

        # Select overview
        self.nav_list.setCurrentRow(0)

        self.stack.setCurrentIndex(1)

    def _build_nav_list(self, result: CaptureResult):
        nav_row = 0

        # Overview item
        overview_item = QListWidgetItem("Overview")
        overview_font = QFont()
        overview_font.setBold(True)
        overview_item.setFont(overview_font)
        self.nav_list.addItem(overview_item)
        self._nav_to_stack[nav_row] = 0
        nav_row += 1

        stack_idx = 1
        for category in ANALYZER_CATEGORIES:
            # Category header (non-selectable)
            header_item = QListWidgetItem(category["name"].upper())
            header_item.setFlags(Qt.NoItemFlags)
            header_font = QFont()
            header_font.setBold(True)
            header_font.setPointSize(10)
            header_item.setFont(header_font)
            header_item.setForeground(Qt.gray)
            self.nav_list.addItem(header_item)
            nav_row += 1

            for analyzer in category["analyzers"]:
                label, attr = analyzer[0], analyzer[1]
                count = result.finding_count(attr)
                display = f"  {label} ({count})" if count > 0 else f"  {label}"

                item = QListWidgetItem(display)
                self.nav_list.addItem(item)
                self._nav_to_stack[nav_row] = stack_idx
                nav_row += 1
                stack_idx += 1

    def _on_nav_changed(self, row: int):
        if row in self._nav_to_stack:
            self.panel_stack.setCurrentIndex(self._nav_to_stack[row])

    def _export_json(self):
        if not self._result:
            return

        base_name = self._result.filename.rsplit(".", 1)[0]
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"{base_name}_analysis.json",
            "JSON Files (*.json)",
        )
        if not file_path:
            return

        with open(file_path, "w") as f:
            json.dump(self._result.to_export_dict(), f, indent=2, default=str)
