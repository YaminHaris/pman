"""Main PyQt5 window for Pman — Scapy GUI, Packet Analyzer & Network Diagnostics."""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt5.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from scapy.all import Packet

from core.diagnostics import (
    arp_discover,
    compute_analytics,
    parse_port_spec,
    run_traceroute,
    tcp_port_probe,
)
from core.packet_engine import (
    LiveSniffer,
    PacketStore,
    dissect_packet,
    format_hexdump,
    has_raw_socket_privilege,
    list_interfaces,
)
from core.radar import (
    LanDevice,
    get_default_gateway_and_cidr,
    passive_os_fingerprint,
    scan_lan_radar,
)
from core.scapy_builder import (
    COMMON_LAYERS,
    LayerSpec,
    build_scapy_packet,
    generate_scapy_code,
    get_all_scapy_layers,
    get_layer_fields,
    packet_to_layer_specs,
    parse_field_value,
    transmit_packet,
    transmit_via_os_socket,
)
from core.script_runner import SCRIPT_PRESETS, run_scapy_script

DARK_QSS = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'DejaVu Sans', sans-serif;
    font-size: 12px;
}
QTabWidget::pane {
    border: 1px solid #30363d;
    background: #0d1117;
}
QTabBar::tab {
    background: #161b22;
    color: #8b949e;
    padding: 8px 18px;
    border: 1px solid #30363d;
    border-bottom: none;
    margin-right: 2px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background: #0d1117;
    color: #58a6ff;
    border-top: 2px solid #58a6ff;
}
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 10px;
    font-weight: bold;
    color: #58a6ff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QListWidget, QTreeWidget, QTableWidget {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 4px;
    selection-background-color: #1f6feb;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 5px;
    border: 1px solid #30363d;
    font-weight: bold;
}
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 5px;
    padding: 6px 12px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #58a6ff;
}
QPushButton#primary {
    background-color: #238636;
    border-color: #2ea043;
}
QPushButton#primary:hover {
    background-color: #2ea043;
}
QPushButton#danger {
    background-color: #da3633;
    border-color: #f85149;
}
QPushButton#accent {
    background-color: #1f6feb;
    border-color: #58a6ff;
}
QStatusBar {
    background: #161b22;
    color: #8b949e;
    border-top: 1px solid #30363d;
}
"""

PROTO_COLORS = {
    "TCP": "#1a2f4b",
    "HTTP": "#1a3b2a",
    "TLS": "#272343",
    "UDP": "#2a2818",
    "DNS": "#1e323d",
    "ICMP": "#3b2330",
    "ARP": "#3a2e1a",
}


class WorkerThread(QThread):
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        try:
            self.finished_ok.emit(self._fn())
        except Exception as exc:
            self.failed.emit(str(exc))


class LanRadarCanvas(QWidget):
    """Dark-mode circular LAN radar plotting discovered hosts by RTT distance."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumSize(360, 320)
        self.local_ip = "127.0.0.1"
        self.devices: List[LanDevice] = []

    def set_scan_result(self, local_ip: str, devices: List[LanDevice]) -> None:
        self.local_ip = local_ip
        self.devices = devices
        self.update()

    def paintEvent(self, _event: Any) -> None:  # noqa: N802
        import math

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#0d1117"))

        cx, cy = w // 2, h // 2
        radius = min(w, h) // 2 - 28
        if radius < 30:
            return

        # Concentric radar rings
        p.setPen(QPen(QColor("#1f2d3d"), 1, Qt.DashLine))
        for frac in (0.33, 0.66, 1.0):
            r = int(radius * frac)
            p.drawEllipse(cx - r, cy - r, r * 2, r * 2)
        p.drawLine(cx - radius, cy, cx + radius, cy)
        p.drawLine(cx, cy - radius, cx, cy + radius)

        # Center node (This machine)
        p.setBrush(QBrush(QColor("#58a6ff")))
        p.setPen(QPen(QColor("#ffffff"), 1.5))
        p.drawEllipse(cx - 7, cy - 7, 14, 14)
        p.setFont(QFont("DejaVu Sans", 9, QFont.Bold))
        p.drawText(cx + 10, cy + 4, f"YOU ({self.local_ip})")

        # Plot discovered LAN devices
        n = max(1, len(self.devices))
        for i, dev in enumerate(self.devices):
            angle = (2 * math.pi * i) / n - math.pi / 4
            rtt = dev.rtt_ms if dev.rtt_ms is not None else 12.0
            dist_frac = min(0.92, max(0.32, 0.32 + (rtt / 30.0) * 0.58))
            dx = int(cx + radius * dist_frac * math.cos(angle))
            dy = int(cy + radius * dist_frac * math.sin(angle))

            col = QColor("#f0883e") if "Router" in dev.role_hint else (
                QColor("#3fb950") if "Mobile" in dev.role_hint else QColor("#a371f7")
            )
            p.setPen(QPen(QColor("#30363d"), 1))
            p.drawLine(cx, cy, dx, dy)
            p.setBrush(QBrush(col))
            p.setPen(QPen(QColor("#ffffff"), 1))
            p.drawEllipse(dx - 6, dy - 6, 12, 12)
            rtt_s = f"{dev.rtt_ms:.1f}ms" if dev.rtt_ms is not None else "?ms"
            p.setPen(col)
            p.drawText(dx + 9, dy - 2, f"{dev.ip} ({rtt_s})")
            p.setPen(QColor("#8b949e"))
            p.setFont(QFont("DejaVu Sans", 8))
            p.drawText(dx + 9, dy + 11, dev.role_hint)
            p.setFont(QFont("DejaVu Sans", 9, QFont.Bold))


class PmanMainWindow(QMainWindow):
    packet_arrived = pyqtSignal(object)

    def __init__(self, sample_pcap: Optional[str] = None) -> None:
        super().__init__()
        self.setWindowTitle("Pman v2.0 — Scapy Packet Analyzer, Crafter & Diagnostics")
        self.resize(1380, 860)
        self.setStyleSheet(DARK_QSS)

        self.store = PacketStore()
        self.sniffer = LiveSniffer()
        self.all_scapy_layers = get_all_scapy_layers()
        self.crafter_stack: List[LayerSpec] = [
            LayerSpec("IP", {"dst": "127.0.0.1"}),
            LayerSpec("TCP", {"dport": 80, "flags": "S"}),
        ]
        self._active_workers: List[WorkerThread] = []
        self._selected_packet_idx: Optional[int] = None

        self.packet_arrived.connect(self._on_live_packet)

        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(False)
        self.setCentralWidget(self.tabs)

        self._build_capture_tab()
        self._build_crafter_tab()
        self._build_diagnostics_tab()
        self._build_analytics_tab()
        self._build_console_tab()
        self._build_radar_tab()
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        priv = "RAW SOCKET READY" if has_raw_socket_privilege() else "NON-ROOT MODE (click Elevate for live sniff/raw TX)"
        self.status_bar.showMessage(f"Ready — Pman v2.0 | {priv}")

        self._refresh_crafter_stack_list()
        if sample_pcap and os.path.exists(sample_pcap):
            self._load_pcap_path(sample_pcap)

    # ── Tab 1: Capture & Dissect ──────────────────────────────────────────────
    def _build_capture_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Toolbar
        bar = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(list_interfaces())
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("BPF capture filter (e.g., tcp port 80, arp, icmp)")
        self.btn_sniff_start = QPushButton("▶ Start Capture")
        self.btn_sniff_start.setObjectName("primary")
        self.btn_sniff_stop = QPushButton("■ Stop")
        self.btn_sniff_stop.setObjectName("danger")
        self.btn_sniff_stop.setEnabled(False)
        self.btn_open_pcap = QPushButton("Open PCAP")
        self.btn_save_pcap = QPushButton("Save PCAP")
        self.btn_clear_pkts = QPushButton("Clear")
        self.btn_elevate = QPushButton("Elevate (pkexec)")
        self.btn_elevate.setObjectName("accent")
        self.btn_elevate.setVisible(not has_raw_socket_privilege())

        bar.addWidget(QLabel("Interface:"))
        bar.addWidget(self.iface_combo)
        bar.addWidget(self.bpf_edit, 2)
        bar.addWidget(self.btn_sniff_start)
        bar.addWidget(self.btn_sniff_stop)
        bar.addWidget(self.btn_open_pcap)
        bar.addWidget(self.btn_save_pcap)
        bar.addWidget(self.btn_clear_pkts)
        bar.addWidget(self.btn_elevate)
        layout.addLayout(bar)

        # Display Filter bar
        fbar = QHBoxLayout()
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("Display filter (e.g., proto=tcp, ip=192.168.1.1, port=443, dns)")
        self.btn_apply_filter = QPushButton("Apply Filter")
        self.btn_to_crafter = QPushButton("Send Selected to Crafter →")
        self.btn_to_crafter.setObjectName("accent")
        fbar.addWidget(QLabel("Filter:"))
        fbar.addWidget(self.display_filter, 3)
        fbar.addWidget(self.btn_apply_filter)
        fbar.addWidget(self.btn_to_crafter)
        layout.addLayout(fbar)

        # 3-pane Wireshark splitter
        vsplit = QSplitter(Qt.Vertical)

        self.pkt_table = QTableWidget(0, 7)
        self.pkt_table.setHorizontalHeaderLabels(["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.pkt_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.pkt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.pkt_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.pkt_table.verticalHeader().setVisible(False)
        vsplit.addWidget(self.pkt_table)

        hsplit = QSplitter(Qt.Horizontal)
        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(["Protocol Layer / Field", "Value"])
        self.layer_tree.setColumnWidth(0, 280)
        hsplit.addWidget(self.layer_tree)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("DejaVu Sans Mono", 10))
        hsplit.addWidget(self.hex_view)
        hsplit.setSizes([580, 620])

        vsplit.addWidget(hsplit)
        vsplit.setSizes([420, 320])
        layout.addWidget(vsplit)

        self.btn_sniff_start.clicked.connect(self._start_capture)
        self.btn_sniff_stop.clicked.connect(self._stop_capture)
        self.btn_open_pcap.clicked.connect(self._open_pcap_dialog)
        self.btn_save_pcap.clicked.connect(self._save_pcap_dialog)
        self.btn_clear_pkts.clicked.connect(self._clear_packets)
        self.btn_elevate.clicked.connect(self._relaunch_elevated)
        self.btn_apply_filter.clicked.connect(self._refresh_packet_table)
        self.display_filter.returnPressed.connect(self._refresh_packet_table)
        self.pkt_table.itemSelectionChanged.connect(self._on_packet_selected)
        self.btn_to_crafter.clicked.connect(self._send_selected_to_crafter)

        self.tabs.addTab(tab, "Capture && Dissect")

    # ── Tab 2: Scapy Packet Crafter ───────────────────────────────────────────
    def _build_crafter_tab(self) -> None:
        tab = QWidget()
        root = QHBoxLayout(tab)

        # Left column: Layer palette + Stack
        left = QVBoxLayout()
        pal_box = QGroupBox("Add Scapy Layer")
        pal_lay = QVBoxLayout(pal_box)

        common_row = QHBoxLayout()
        for lname in ["Ether", "ARP", "IP", "IPv6", "TCP", "UDP", "ICMP", "DNS", "Raw"]:
            btn = QPushButton(lname)
            btn.clicked.connect(lambda _=False, n=lname: self._add_crafter_layer(n))
            common_row.addWidget(btn)
        pal_lay.addLayout(common_row)

        all_row = QHBoxLayout()
        self.all_layers_combo = QComboBox()
        self.all_layers_combo.setEditable(True)
        self.all_layers_combo.addItems(sorted(self.all_scapy_layers.keys()))
        btn_add_any = QPushButton("Add Layer")
        btn_add_any.clicked.connect(lambda: self._add_crafter_layer(self.all_layers_combo.currentText().strip()))
        all_row.addWidget(QLabel("All Scapy Layers:"))
        all_row.addWidget(self.all_layers_combo, 1)
        all_row.addWidget(btn_add_any)
        pal_lay.addLayout(all_row)
        left.addWidget(pal_box)

        stack_box = QGroupBox("Packet Layer Stack")
        stack_lay = QVBoxLayout(stack_box)
        self.stack_list = QListWidget()
        stack_lay.addWidget(self.stack_list)
        sbtns = QHBoxLayout()
        for label, cb in [("Move Up", self._move_layer_up), ("Move Down", self._move_layer_down), ("Remove", self._remove_layer)]:
            b = QPushButton(label)
            b.clicked.connect(cb)
            sbtns.addWidget(b)
        stack_lay.addLayout(sbtns)
        left.addWidget(stack_box)
        root.addLayout(left, 2)

        # Right column: Dynamic Field Editor + Preview + Transmit
        right = QVBoxLayout()
        fields_box = QGroupBox("Layer Fields (Scapy fields_desc)")
        fields_lay = QVBoxLayout(fields_box)
        self.fields_table = QTableWidget(0, 3)
        self.fields_table.setHorizontalHeaderLabels(["Field", "Value", "Type"])
        self.fields_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.fields_table.verticalHeader().setVisible(False)
        fields_lay.addWidget(self.fields_table)
        right.addWidget(fields_box, 3)

        prev_box = QGroupBox("Generated Scapy Expression & Transmit")
        prev_lay = QVBoxLayout(prev_box)
        self.scapy_preview = QPlainTextEdit()
        self.scapy_preview.setReadOnly(True)
        self.scapy_preview.setMaximumHeight(65)
        self.scapy_preview.setFont(QFont("DejaVu Sans Mono", 10))
        prev_lay.addWidget(self.scapy_preview)

        tx_row = QHBoxLayout()
        self.tx_count = QSpinBox()
        self.tx_count.setRange(1, 1000)
        self.tx_count.setValue(1)
        btn_send_l3 = QPushButton("Send L3 (send)")
        btn_send_l3.setObjectName("primary")
        btn_send_l2 = QPushButton("Send L2 (sendp)")
        btn_sr1 = QPushButton("Send & Receive (sr1)")
        btn_sr1.setObjectName("accent")
        btn_os_sock = QPushButton("Send via OS Socket (Non-Root)")
        tx_row.addWidget(QLabel("Count:"))
        tx_row.addWidget(self.tx_count)
        tx_row.addWidget(btn_send_l3)
        tx_row.addWidget(btn_send_l2)
        tx_row.addWidget(btn_sr1)
        tx_row.addWidget(btn_os_sock)
        prev_lay.addLayout(tx_row)

        self.crafter_output = QPlainTextEdit()
        self.crafter_output.setReadOnly(True)
        self.crafter_output.setFont(QFont("DejaVu Sans Mono", 10))
        prev_lay.addWidget(self.crafter_output)
        right.addWidget(prev_box, 2)

        root.addLayout(right, 3)

        self.stack_list.currentRowChanged.connect(self._on_crafter_layer_selected)
        self.fields_table.itemChanged.connect(self._on_crafter_field_edited)
        btn_send_l3.clicked.connect(lambda: self._send_crafted(layer2=False, wait_reply=False))
        btn_send_l2.clicked.connect(lambda: self._send_crafted(layer2=True, wait_reply=False))
        btn_sr1.clicked.connect(lambda: self._send_crafted(layer2=False, wait_reply=True))
        btn_os_sock.clicked.connect(self._send_via_os_socket)

        self.tabs.addTab(tab, "Scapy Packet Crafter")

    # ── Tab 3: Network Diagnostics ────────────────────────────────────────────
    def _build_diagnostics_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        ctrl_box = QGroupBox("Active Network Diagnostics")
        form = QFormLayout(ctrl_box)
        self.diag_target = QLineEdit("127.0.0.1")
        self.diag_ports = QLineEdit("22,80,443,8080")
        self.diag_cidr = QLineEdit("192.168.1.0/24")
        form.addRow("Target Host / IP:", self.diag_target)
        form.addRow("TCP Ports (e.g. 22,80,443 or 1-1024):", self.diag_ports)
        form.addRow("Local Subnet CIDR (ARP):", self.diag_cidr)

        btns = QHBoxLayout()
        b_tcp = QPushButton("TCP Port Reachability Probe")
        b_tcp.setObjectName("primary")
        b_arp = QPushButton("ARP Subnet Discovery")
        b_arp.setObjectName("accent")
        b_tr = QPushButton("Scapy Traceroute")
        btns.addWidget(b_tcp)
        btns.addWidget(b_arp)
        btns.addWidget(b_tr)
        form.addRow(btns)
        layout.addWidget(ctrl_box)

        self.diag_output = QPlainTextEdit()
        self.diag_output.setReadOnly(True)
        self.diag_output.setFont(QFont("DejaVu Sans Mono", 10))
        layout.addWidget(self.diag_output, 1)

        b_tcp.clicked.connect(self._run_tcp_probe)
        b_arp.clicked.connect(self._run_arp_probe)
        b_tr.clicked.connect(self._run_traceroute_probe)

        self.tabs.addTab(tab, "Network Diagnostics")

    # ── Tab 4: Analytics & Defense ────────────────────────────────────────────
    def _build_analytics_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        top = QHBoxLayout()
        self.analytics_summary = QLabel("No packets loaded.")
        self.analytics_summary.setStyleSheet("font-size: 13px; font-weight: bold; color: #58a6ff;")
        btn_refresh = QPushButton("Refresh Analytics")
        btn_refresh.setObjectName("accent")
        top.addWidget(self.analytics_summary, 1)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        mid = QHBoxLayout()
        self.proto_table = QTableWidget(0, 3)
        self.proto_table.setHorizontalHeaderLabels(["Protocol", "Packets", "Share"])
        self.proto_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.proto_table.verticalHeader().setVisible(False)
        mid.addWidget(self.proto_table, 1)

        self.talkers_table = QTableWidget(0, 2)
        self.talkers_table.setHorizontalHeaderLabels(["Top Source / Dst IP", "Packets"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.talkers_table.verticalHeader().setVisible(False)
        mid.addWidget(self.talkers_table, 1)
        layout.addLayout(mid, 2)

        alert_box = QGroupBox("Defensive Anomaly & Hygiene Alerts")
        alert_lay = QVBoxLayout(alert_box)
        self.alerts_view = QPlainTextEdit()
        self.alerts_view.setReadOnly(True)
        self.alerts_view.setFont(QFont("DejaVu Sans Mono", 10))
        alert_lay.addWidget(self.alerts_view)
        layout.addWidget(alert_box, 1)

        btn_refresh.clicked.connect(self._refresh_analytics)
        self.tabs.addTab(tab, "Analytics && Defense")

    # ── Tab 5: Scapy Scripting Console ────────────────────────────────────────
    def _build_console_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        top = QHBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(list(SCRIPT_PRESETS.keys()))
        btn_load_preset = QPushButton("Load Preset")
        btn_run_script = QPushButton("▶ Run Scapy Script")
        btn_run_script.setObjectName("primary")
        top.addWidget(QLabel("Preset:"))
        top.addWidget(self.preset_combo, 1)
        top.addWidget(btn_load_preset)
        top.addWidget(btn_run_script)
        layout.addLayout(top)

        split = QSplitter(Qt.Vertical)
        self.script_editor = QPlainTextEdit()
        self.script_editor.setFont(QFont("DejaVu Sans Mono", 10))
        self.script_editor.setPlainText(SCRIPT_PRESETS["Top Talkers & Protocols"])
        split.addWidget(self.script_editor)

        self.script_output = QPlainTextEdit()
        self.script_output.setReadOnly(True)
        self.script_output.setFont(QFont("DejaVu Sans Mono", 10))
        split.addWidget(self.script_output)
        split.setSizes([340, 340])
        layout.addWidget(split, 1)

        btn_load_preset.clicked.connect(lambda: self.script_editor.setPlainText(SCRIPT_PRESETS[self.preset_combo.currentText()]))
        btn_run_script.clicked.connect(self._run_console_script)
        self.tabs.addTab(tab, "Scapy Scripting Console")

    # ── Tab 6: Radar & OS Fingerprint ─────────────────────────────────────────
    def _build_radar_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        top = QHBoxLayout()
        try:
            _, _, default_cidr = get_default_gateway_and_cidr()
        except Exception:
            default_cidr = "192.168.0.0/24"
        self.radar_cidr = QLineEdit(default_cidr)
        btn_scan = QPushButton("▶ Scan LAN & Fingerprint")
        btn_scan.setObjectName("primary")
        btn_fp = QPushButton("Refresh Passive OS Fingerprints (PCAP)")
        btn_fp.setObjectName("accent")
        top.addWidget(QLabel("Subnet CIDR:"))
        top.addWidget(self.radar_cidr, 1)
        top.addWidget(btn_scan)
        top.addWidget(btn_fp)
        layout.addLayout(top)

        split = QSplitter(Qt.Horizontal)
        self.radar_canvas = LanRadarCanvas()
        split.addWidget(self.radar_canvas)

        right = QSplitter(Qt.Vertical)
        self.radar_table = QTableWidget(0, 6)
        self.radar_table.setHorizontalHeaderLabels(["IP", "MAC", "MAC Type", "RTT (ms)", "Services", "Device Hint"])
        self.radar_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.radar_table.verticalHeader().setVisible(False)
        right.addWidget(self.radar_table)

        self.os_fp_table = QTableWidget(0, 6)
        self.os_fp_table.setHorizontalHeaderLabels(["IP (PCAP)", "Pkts", "Seen TTL", "Init TTL", "Est Hops", "Passive OS Guess"])
        self.os_fp_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.os_fp_table.verticalHeader().setVisible(False)
        right.addWidget(self.os_fp_table)
        split.addWidget(right)
        split.setSizes([430, 770])
        layout.addWidget(split, 1)

        btn_scan.clicked.connect(self._run_lan_radar)
        btn_fp.clicked.connect(self._refresh_passive_os_fp)
        self.tabs.addTab(tab, "Radar && OS Fingerprint")

    def _run_lan_radar(self) -> None:
        cidr = self.radar_cidr.text().strip()
        iface = self.iface_combo.currentText()
        self.status_bar.showMessage(f"Scanning {cidr} + mDNS/SSDP...")
        self._spawn_worker(
            lambda: scan_lan_radar(cidr=cidr, iface=iface),
            self._on_lan_radar_done,
        )

    def _on_lan_radar_done(self, res: Dict[str, Any]) -> None:
        devices: List[LanDevice] = res["devices"]
        self.radar_canvas.set_scan_result(str(res["local_ip"]), devices)
        self.radar_table.setRowCount(len(devices))
        for i, d in enumerate(devices):
            vals = [
                d.ip, d.mac, d.mac_type,
                f"{d.rtt_ms:.2f}" if d.rtt_ms is not None else "-",
                d.services, d.role_hint,
            ]
            for col, v in enumerate(vals):
                self.radar_table.setItem(i, col, QTableWidgetItem(v))
        self.status_bar.showMessage(f"LAN Radar complete: {len(devices)} device(s) on {res['cidr']}")

    def _refresh_passive_os_fp(self) -> None:
        fps = passive_os_fingerprint(self.store.all())
        self.os_fp_table.setRowCount(len(fps))
        for i, fp in enumerate(fps):
            ttl_str = f"{fp.ttl_min}" if fp.ttl_min == fp.ttl_max else f"{fp.ttl_min}-{fp.ttl_max}"
            vals = [fp.ip, str(fp.packets), ttl_str, str(fp.est_init_ttl), str(fp.est_hops), fp.os_guess]
            for col, v in enumerate(vals):
                self.os_fp_table.setItem(i, col, QTableWidgetItem(v))

    def _on_tab_changed(self, idx: int) -> None:
        if idx == 3:
            self._refresh_analytics()
        elif idx == 5:
            self._refresh_passive_os_fp()

    def _relaunch_elevated(self) -> None:
        import subprocess, sys as _sys
        script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
        env_args = [
            "pkexec", "env",
            f"DISPLAY={os.environ.get('DISPLAY', ':0')}",
            f"XAUTHORITY={os.environ.get('XAUTHORITY', os.path.expanduser('~/.Xauthority'))}",
            "QT_QPA_PLATFORM=xcb",
            _sys.executable, script,
        ]
        try:
            subprocess.Popen(env_args)
            self.status_bar.showMessage("Launched elevated Pman window via pkexec...")
        except Exception as exc:
            QMessageBox.warning(self, "Elevation Error", str(exc))

    def _send_via_os_socket(self) -> None:
        try:
            pkt = build_scapy_packet(self.crafter_stack)
            res = transmit_via_os_socket(pkt)
            self.crafter_output.setPlainText(f"[{res['mode']}] {res['reply_summary']}")
        except Exception as exc:
            self.crafter_output.setPlainText(f"[ERROR] {exc}")

    # ── Handlers ──────────────────────────────────────────────────────────────
    def _start_capture(self) -> None:
        iface = self.iface_combo.currentText()
        bpf = self.bpf_edit.text()
        try:
            self.sniffer.start(iface, bpf, lambda pkt: self.packet_arrived.emit(pkt))
            self.btn_sniff_start.setEnabled(False)
            self.btn_sniff_stop.setEnabled(True)
            self.status_bar.showMessage(f"Capturing on {iface} (filter: {bpf or 'none'})...")
        except Exception as exc:
            QMessageBox.warning(self, "Capture Error", f"Failed to start capture on {iface}:\n{exc}\n\nTip: Raw capture requires CAP_NET_RAW or sudo.")

    def _stop_capture(self) -> None:
        self.sniffer.stop()
        self.btn_sniff_start.setEnabled(True)
        self.btn_sniff_stop.setEnabled(False)
        self.status_bar.showMessage(f"Capture stopped — {len(self.store)} packets stored.")

    def _on_live_packet(self, pkt: Packet) -> None:
        self.store.append(pkt)
        self._refresh_packet_table()

    def _open_pcap_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if path:
            self._load_pcap_path(path)

    def _load_pcap_path(self, path: str) -> None:
        try:
            cnt = self.store.load_pcap(path)
            self._refresh_packet_table()
            self._refresh_analytics()
            self.status_bar.showMessage(f"Loaded {cnt} packets from {os.path.basename(path)}")
        except Exception as exc:
            QMessageBox.warning(self, "PCAP Load Error", str(exc))

    def _save_pcap_dialog(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "capture.pcap", "PCAP Files (*.pcap)")
        if path:
            cnt = self.store.save_pcap(path)
            self.status_bar.showMessage(f"Saved {cnt} packets to {path}")

    def _clear_packets(self) -> None:
        self.store.clear()
        self.pkt_table.setRowCount(0)
        self.layer_tree.clear()
        self.hex_view.clear()
        self._refresh_analytics()

    def _refresh_packet_table(self) -> None:
        summaries = self.store.filter_summaries(self.display_filter.text())
        self.pkt_table.setRowCount(len(summaries))
        for row, s in enumerate(summaries):
            vals = [str(s.index), s.timestamp, s.src, s.dst, s.protocol, str(s.length), s.info]
            bg = QColor(PROTO_COLORS.get(s.protocol, "#161b22"))
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setBackground(bg)
                if col == 0:
                    item.setData(Qt.UserRole, s.index - 1)
                self.pkt_table.setItem(row, col, item)

    def _on_packet_selected(self) -> None:
        rows = self.pkt_table.selectionModel().selectedRows()
        if not rows:
            return
        item = self.pkt_table.item(rows[0].row(), 0)
        if item is None:
            return
        pkt_idx = int(item.data(Qt.UserRole))
        self._selected_packet_idx = pkt_idx
        pkt = self.store.get(pkt_idx)
        if pkt is None:
            return

        self.layer_tree.clear()
        for layer_name, fields in dissect_packet(pkt):
            parent = QTreeWidgetItem([layer_name, ""])
            parent.setForeground(0, QColor("#58a6ff"))
            for fname, fval in fields:
                parent.addChild(QTreeWidgetItem([fname, fval]))
            self.layer_tree.addTopLevelItem(parent)
            parent.setExpanded(True)

        self.hex_view.setPlainText(format_hexdump(pkt))

    def _send_selected_to_crafter(self) -> None:
        if self._selected_packet_idx is None:
            return
        pkt = self.store.get(self._selected_packet_idx)
        if pkt is None:
            return
        self.crafter_stack = packet_to_layer_specs(pkt)
        self._refresh_crafter_stack_list()
        self.tabs.setCurrentIndex(1)

    # ── Crafter logic ─────────────────────────────────────────────────────────
    def _add_crafter_layer(self, name: str) -> None:
        if name not in self.all_scapy_layers:
            QMessageBox.warning(self, "Unknown Layer", f"Scapy layer '{name}' not found.")
            return
        defaults = {fn: dv for fn, dv, _ in get_layer_fields(name)}
        self.crafter_stack.append(LayerSpec(name=name, fields=defaults))
        self._refresh_crafter_stack_list(select_idx=len(self.crafter_stack) - 1)

    def _move_layer_up(self) -> None:
        row = self.stack_list.currentRow()
        if row > 0:
            self.crafter_stack[row - 1], self.crafter_stack[row] = self.crafter_stack[row], self.crafter_stack[row - 1]
            self._refresh_crafter_stack_list(select_idx=row - 1)

    def _move_layer_down(self) -> None:
        row = self.stack_list.currentRow()
        if 0 <= row < len(self.crafter_stack) - 1:
            self.crafter_stack[row + 1], self.crafter_stack[row] = self.crafter_stack[row], self.crafter_stack[row + 1]
            self._refresh_crafter_stack_list(select_idx=row + 1)

    def _remove_layer(self) -> None:
        row = self.stack_list.currentRow()
        if 0 <= row < len(self.crafter_stack):
            self.crafter_stack.pop(row)
            self._refresh_crafter_stack_list(select_idx=max(0, row - 1))

    def _refresh_crafter_stack_list(self, select_idx: int = 0) -> None:
        self.stack_list.clear()
        for spec in self.crafter_stack:
            self.stack_list.addItem(spec.name)
        if self.crafter_stack:
            self.stack_list.setCurrentRow(min(select_idx, len(self.crafter_stack) - 1))
        self.scapy_preview.setPlainText(generate_scapy_code(self.crafter_stack))

    def _on_crafter_layer_selected(self, row: int) -> None:
        self.fields_table.blockSignals(True)
        self.fields_table.setRowCount(0)
        if 0 <= row < len(self.crafter_stack):
            spec = self.crafter_stack[row]
            meta = get_layer_fields(spec.name)
            self.fields_table.setRowCount(len(meta))
            for i, (fname, default_val, ftype) in enumerate(meta):
                val = spec.fields.get(fname, default_val)
                it_name = QTableWidgetItem(fname)
                it_name.setFlags(it_name.flags() & ~Qt.ItemIsEditable)
                it_name.setData(Qt.UserRole, default_val)
                it_val = QTableWidgetItem("" if val is None else str(val))
                it_type = QTableWidgetItem(ftype)
                it_type.setFlags(it_type.flags() & ~Qt.ItemIsEditable)
                self.fields_table.setItem(i, 0, it_name)
                self.fields_table.setItem(i, 1, it_val)
                self.fields_table.setItem(i, 2, it_type)
        self.fields_table.blockSignals(False)

    def _on_crafter_field_edited(self, item: QTableWidgetItem) -> None:
        if item.column() != 1:
            return
        row = self.stack_list.currentRow()
        if not (0 <= row < len(self.crafter_stack)):
            return
        fname_item = self.fields_table.item(item.row(), 0)
        if fname_item is None:
            return
        fname = fname_item.text()
        orig_default = fname_item.data(Qt.UserRole)
        self.crafter_stack[row].fields[fname] = parse_field_value(item.text(), orig_default)
        self.scapy_preview.setPlainText(generate_scapy_code(self.crafter_stack))

    def _send_crafted(self, layer2: bool, wait_reply: bool) -> None:
        try:
            pkt = build_scapy_packet(self.crafter_stack)
            res = transmit_packet(pkt, layer2=layer2, count=self.tx_count.value(), wait_reply=wait_reply)
            txt = f"[{res['mode']}] {res['reply_summary']}\n"
            if res["reply"] is not None:
                txt += "\n--- Reply Dissection ---\n"
                for lname, fields in dissect_packet(res["reply"]):
                    txt += f"{lname}: " + ", ".join(f"{k}={v}" for k, v in fields) + "\n"
            self.crafter_output.setPlainText(txt)
        except Exception as exc:
            self.crafter_output.setPlainText(f"[ERROR] {exc}\n(Raw packet transmission requires CAP_NET_RAW or sudo.)")

    # ── Diagnostics logic ─────────────────────────────────────────────────────
    def _spawn_worker(self, fn: Callable[[], Any], on_done: Callable[[Any], None]) -> None:
        w = WorkerThread(fn)
        w.finished_ok.connect(on_done)
        w.failed.connect(lambda err: self.diag_output.appendPlainText(f"[ERROR] {err}\n"))
        self._active_workers.append(w)
        w.start()

    def _run_tcp_probe(self) -> None:
        host = self.diag_target.text().strip()
        ports = parse_port_spec(self.diag_ports.text())
        self.diag_output.appendPlainText(f"[*] Probing {host} across {len(ports)} TCP port(s)...")
        self._spawn_worker(
            lambda: tcp_port_probe(host, ports),
            lambda res: self.diag_output.appendPlainText(
                "\n".join(f"  OPEN  {r['port']}/tcp  ({r['service']})" for r in res) or "  No open ports found."
            ),
        )

    def _run_arp_probe(self) -> None:
        cidr = self.diag_cidr.text().strip()
        iface = self.iface_combo.currentText()
        self.diag_output.appendPlainText(f"[*] Running ARP discovery on {cidr} ({iface})...")
        self._spawn_worker(
            lambda: arp_discover(cidr, iface=iface),
            lambda hosts: self.diag_output.appendPlainText(
                "\n".join(f"  {h['ip']:16s}  {h['mac']}" for h in hosts) or "  No ARP replies."
            ),
        )

    def _run_traceroute_probe(self) -> None:
        if not has_raw_socket_privilege():
            self.diag_output.appendPlainText("[!] Scapy Traceroute requires raw sockets. Click 'Elevate (pkexec)' on Capture tab.")
            return
        target = self.diag_target.text().strip()
        self.diag_output.appendPlainText(f"[*] Running Scapy traceroute to {target}...")
        self._spawn_worker(
            lambda: run_traceroute(target),
            lambda hops: self.diag_output.appendPlainText(
                "\n".join(f"  Hop {h['ttl']:2d}: {h['ip']:16s} ({h['proto']})" for h in hops) or "  No hops returned."
            ),
        )

    # ── Analytics & Console ───────────────────────────────────────────────────
    def _refresh_analytics(self) -> None:
        a = compute_analytics(self.store.all())
        self.analytics_summary.setText(f"Total Packets: {a.total_packets}   |   Total Bytes: {a.total_bytes:,}")

        self.proto_table.setRowCount(len(a.protocols))
        for i, (proto, cnt) in enumerate(a.protocols):
            self.proto_table.setItem(i, 0, QTableWidgetItem(proto))
            self.proto_table.setItem(i, 1, QTableWidgetItem(str(cnt)))
            bar = QProgressBar()
            bar.setMaximum(max(1, a.total_packets))
            bar.setValue(cnt)
            bar.setFormat(f"{(100.0 * cnt / max(1, a.total_packets)):.1f}%")
            self.proto_table.setCellWidget(i, 2, bar)

        talkers = a.top_sources + a.top_destinations
        self.talkers_table.setRowCount(len(talkers))
        for i, (ip, cnt) in enumerate(talkers):
            prefix = "SRC " if i < len(a.top_sources) else "DST "
            self.talkers_table.setItem(i, 0, QTableWidgetItem(prefix + ip))
            self.talkers_table.setItem(i, 1, QTableWidgetItem(str(cnt)))

        self.alerts_view.setPlainText("\n".join(a.alerts))

    def _run_console_script(self) -> None:
        sel = self.store.get(self._selected_packet_idx) if self._selected_packet_idx is not None else None
        res = run_scapy_script(self.script_editor.toPlainText(), self.store.all(), sel)
        self.script_output.setPlainText(res["output"] or "(Script completed with no output)")
