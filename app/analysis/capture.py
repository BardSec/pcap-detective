"""Live packet capture — sniff packets and save to PCAP file."""

import logging
import os
import platform
import subprocess
import sys
import tempfile
from datetime import datetime

from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


def get_available_interfaces():
    """Return list of (name, description) tuples for available network interfaces."""
    interfaces = []
    try:
        from scapy.all import get_if_list, get_if_hwaddr, conf

        for iface in get_if_list():
            # Skip loopback and virtual interfaces that are usually noise
            if iface == "lo":
                continue
            try:
                mac = get_if_hwaddr(iface)
                desc = f"{iface} ({mac})" if mac and mac != "00:00:00:00:00:00" else iface
            except Exception:
                desc = iface
            interfaces.append((iface, desc))
    except Exception as e:
        logger.warning(f"Failed to enumerate interfaces: {e}")

    return interfaces


def check_capture_permissions():
    """Check if the current process can capture packets.

    Returns:
        (can_capture: bool, message: str)
    """
    system = platform.system()

    if system == "Darwin":
        # macOS: need BPF access
        # Check if /dev/bpf0 is readable
        if os.path.exists("/dev/bpf0"):
            if os.access("/dev/bpf0", os.R_OK):
                return True, "BPF access available"
            else:
                return False, (
                    "Packet capture requires BPF access.\n\n"
                    "Option 1: Install Wireshark (includes BPF helper)\n"
                    "Option 2: Run with sudo\n"
                    "Option 3: Add yourself to the 'access_bpf' group:\n"
                    "  sudo dseditgroup -o edit -a $USER -t user access_bpf"
                )
        else:
            return False, "BPF devices not found. Install Wireshark or Xcode command line tools."

    elif system == "Windows":
        # Windows: need Npcap
        npcap_paths = [
            os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "Npcap"),
            os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wpcap.dll"),
        ]
        for path in npcap_paths:
            if os.path.exists(path):
                return True, "Npcap detected"

        return False, (
            "Packet capture requires Npcap.\n\n"
            "Download and install from: https://npcap.com\n"
            "During installation, check 'Install in WinPcap API-compatible mode'"
        )

    elif system == "Linux":
        # Linux: need CAP_NET_RAW or root
        if os.geteuid() == 0:
            return True, "Running as root"

        try:
            result = subprocess.run(
                ["getcap", sys.executable],
                capture_output=True, text=True, timeout=5,
            )
            if "cap_net_raw" in result.stdout:
                return True, "CAP_NET_RAW capability set"
        except Exception:
            pass

        return False, (
            "Packet capture requires elevated privileges.\n\n"
            "Option 1: Run with sudo\n"
            "Option 2: Set capability:\n"
            "  sudo setcap cap_net_raw+ep $(which python3)"
        )

    return False, f"Unsupported platform: {system}"


class CaptureWorker(QThread):
    """Captures packets in a background thread."""

    packet_count_updated = Signal(int)  # emits current packet count
    capture_finished = Signal(str)      # emits path to saved PCAP file
    capture_error = Signal(str)

    def __init__(self, interface: str, output_path: str, max_packets: int = 0, duration: int = 0):
        super().__init__()
        self.interface = interface
        self.output_path = output_path
        self.max_packets = max_packets  # 0 = unlimited
        self.duration = duration        # 0 = unlimited
        self._stop_requested = False
        self._packet_count = 0

    def stop_capture(self):
        """Signal the capture to stop."""
        self._stop_requested = True

    def run(self):
        try:
            from scapy.all import sniff, wrpcap

            self._packet_count = 0
            self._stop_requested = False
            captured_packets = []

            def packet_callback(pkt):
                self._packet_count += 1
                captured_packets.append(pkt)

                # Emit count every 100 packets to avoid signal flooding
                if self._packet_count % 100 == 0:
                    self.packet_count_updated.emit(self._packet_count)

                if self.max_packets > 0 and self._packet_count >= self.max_packets:
                    return True  # Stop capture

            def stop_filter(_):
                return self._stop_requested

            # Build sniff kwargs
            kwargs = {
                "iface": self.interface,
                "prn": packet_callback,
                "store": 0,  # Don't store in scapy's internal list (we do it ourselves)
                "stop_filter": stop_filter,
            }

            if self.duration > 0:
                kwargs["timeout"] = self.duration

            if self.max_packets > 0:
                kwargs["count"] = self.max_packets

            sniff(**kwargs)

            # Final count update
            self.packet_count_updated.emit(self._packet_count)

            # Save to PCAP file
            if captured_packets:
                wrpcap(self.output_path, captured_packets)
                self.capture_finished.emit(self.output_path)
            else:
                self.capture_error.emit("No packets captured")

        except PermissionError:
            self.capture_error.emit(
                "Permission denied. Packet capture requires elevated privileges."
            )
        except Exception as e:
            logger.exception(f"Capture failed: {e}")
            self.capture_error.emit(str(e))
