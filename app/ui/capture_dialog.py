"""Live capture dialog — interface selection, start/stop, packet counter."""

import os
import tempfile
from datetime import datetime

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.analysis.capture import CaptureWorker, check_capture_permissions, get_available_interfaces
from app.ui.theme import COLORS


class CaptureDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Live Packet Capture")
        self.setMinimumWidth(480)
        self.setStyleSheet(f"background-color: {COLORS['bg_dark']}; color: {COLORS['text']};")

        self._worker: CaptureWorker | None = None
        self._capture_path: str | None = None
        self._elapsed = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

        self.result_path: str | None = None  # Set when capture completes

        self._build_ui()
        self._check_permissions()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Permission status
        self.perm_label = QLabel("")
        self.perm_label.setWordWrap(True)
        self.perm_label.setStyleSheet(f"font-size: 12px; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.perm_label)

        # Interface selection
        iface_group = QGroupBox("Network Interface")
        iface_group.setStyleSheet(f"""
            QGroupBox {{
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 16px;
                font-weight: 600;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                color: {COLORS['text_muted']};
            }}
        """)
        iface_layout = QVBoxLayout(iface_group)

        self.iface_combo = QComboBox()
        self.iface_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px 12px;
                color: {COLORS['text']};
                font-size: 13px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text']};
                selection-background-color: {COLORS['accent']};
            }}
        """)
        iface_layout.addWidget(self.iface_combo)
        layout.addWidget(iface_group)

        # Capture options
        options_group = QGroupBox("Options")
        options_group.setStyleSheet(iface_group.styleSheet())
        options_layout = QHBoxLayout(options_group)

        # Max packets
        options_layout.addWidget(QLabel("Max packets:"))
        self.max_packets = QSpinBox()
        self.max_packets.setRange(0, 10_000_000)
        self.max_packets.setValue(0)
        self.max_packets.setSpecialValueText("Unlimited")
        self.max_packets.setStyleSheet(f"""
            QSpinBox {{
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
                color: {COLORS['text']};
            }}
        """)
        options_layout.addWidget(self.max_packets)

        options_layout.addSpacing(16)

        # Duration
        options_layout.addWidget(QLabel("Duration (sec):"))
        self.duration = QSpinBox()
        self.duration.setRange(0, 3600)
        self.duration.setValue(0)
        self.duration.setSpecialValueText("Unlimited")
        self.duration.setStyleSheet(self.max_packets.styleSheet())
        options_layout.addWidget(self.duration)

        layout.addWidget(options_group)

        # Live stats
        stats = QWidget()
        stats_layout = QHBoxLayout(stats)
        stats_layout.setContentsMargins(0, 0, 0, 0)

        self.packet_label = QLabel("Packets: 0")
        self.packet_label.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {COLORS['accent']};")
        stats_layout.addWidget(self.packet_label)

        stats_layout.addStretch()

        self.elapsed_label = QLabel("00:00")
        self.elapsed_label.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {COLORS['text_muted']};")
        stats_layout.addWidget(self.elapsed_label)

        layout.addWidget(stats)

        # Buttons
        btn_row = QWidget()
        btn_layout = QHBoxLayout(btn_row)
        btn_layout.setContentsMargins(0, 0, 0, 0)

        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-weight: 600;
                font-size: 14px;
            }}
            QPushButton:hover {{ background-color: #16a34a; }}
            QPushButton:disabled {{ background-color: {COLORS['bg_input']}; color: {COLORS['text_muted']}; }}
        """)
        self.start_btn.clicked.connect(self._start_capture)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-weight: 600;
                font-size: 14px;
            }}
            QPushButton:hover {{ background-color: #dc2626; }}
            QPushButton:disabled {{ background-color: {COLORS['bg_input']}; color: {COLORS['text_muted']}; }}
        """)
        self.stop_btn.clicked.connect(self._stop_capture)
        btn_layout.addWidget(self.stop_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setProperty("class", "outline")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addWidget(btn_row)

    def _check_permissions(self):
        can_capture, message = check_capture_permissions()

        if can_capture:
            self.perm_label.setText(f"Ready to capture: {message}")
            self.perm_label.setStyleSheet(f"""
                background-color: {COLORS['success']}22;
                color: {COLORS['success']};
                border: 1px solid {COLORS['success']}44;
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
            """)

            # Populate interfaces
            interfaces = get_available_interfaces()
            for name, desc in interfaces:
                self.iface_combo.addItem(desc, name)
        else:
            self.perm_label.setText(message)
            self.perm_label.setStyleSheet(f"""
                background-color: {COLORS['warning']}22;
                color: {COLORS['warning']};
                border: 1px solid {COLORS['warning']}44;
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
            """)
            self.start_btn.setEnabled(False)
            self.start_btn.setToolTip("Capture prerequisites not met — see message above")

    def _start_capture(self):
        iface = self.iface_combo.currentData()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface.")
            return

        # Create temp file for capture
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._capture_path = os.path.join(
            tempfile.gettempdir(),
            f"bloodhound_capture_{timestamp}.pcap",
        )

        self._worker = CaptureWorker(
            interface=iface,
            output_path=self._capture_path,
            max_packets=self.max_packets.value(),
            duration=self.duration.value(),
        )
        self._worker.packet_count_updated.connect(self._on_packet_count)
        self._worker.capture_finished.connect(self._on_capture_finished)
        self._worker.capture_error.connect(self._on_capture_error)

        self._worker.start()

        # Update UI state
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.max_packets.setEnabled(False)
        self.duration.setEnabled(False)
        self._elapsed = 0
        self._timer.start(1000)

    def _stop_capture(self):
        if self._worker:
            self._worker.stop_capture()
        self.stop_btn.setEnabled(False)
        self.stop_btn.setText("Stopping...")

    def _tick(self):
        self._elapsed += 1
        minutes = self._elapsed // 60
        seconds = self._elapsed % 60
        self.elapsed_label.setText(f"{minutes:02d}:{seconds:02d}")

    def _on_packet_count(self, count: int):
        self.packet_label.setText(f"Packets: {count:,}")

    def _on_capture_finished(self, path: str):
        self._timer.stop()
        self._worker = None

        # Ask user where to save (or auto-analyze)
        reply = QMessageBox.question(
            self,
            "Capture Complete",
            f"Captured packets saved.\n\n"
            f"Would you like to analyze the capture now?",
            QMessageBox.Yes | QMessageBox.Save | QMessageBox.Cancel,
        )

        if reply == QMessageBox.Yes:
            self.result_path = path
            self.accept()
        elif reply == QMessageBox.Save:
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Capture",
                f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
                "PCAP Files (*.pcap)",
            )
            if save_path:
                import shutil
                shutil.copy2(path, save_path)
            self.reject()
        else:
            self.reject()

    def _on_capture_error(self, error: str):
        self._timer.stop()
        self._worker = None

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setText("Stop Capture")
        self.iface_combo.setEnabled(True)
        self.max_packets.setEnabled(True)
        self.duration.setEnabled(True)

        QMessageBox.critical(self, "Capture Error", error)
