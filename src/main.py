#!/usr/bin/env python3
"""Entry point for Pman v2.0 — Scapy Packet Analyzer, Crafter & Network Diagnostics."""
from __future__ import annotations

import os
import sys

from PyQt5.QtWidgets import QApplication

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from ui.main_window import PmanMainWindow  # noqa: E402


def main() -> int:
    app = QApplication(sys.argv)
    sample_pcap = os.path.join(SRC_DIR, "01-06-2025 12:17:50_pman.pcap")
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        sample_pcap = sys.argv[1]
    win = PmanMainWindow(sample_pcap=sample_pcap)
    win.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
