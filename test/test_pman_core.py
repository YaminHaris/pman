"""Unit & headless GUI tests for Pman v2.0."""
import os
import sys

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.diagnostics import compute_analytics, parse_port_spec, tcp_port_probe
from core.packet_engine import PacketStore, dissect_packet, format_hexdump, summarize_packet
from core.scapy_builder import (
    LayerSpec,
    build_scapy_packet,
    generate_scapy_code,
    get_all_scapy_layers,
    get_layer_fields,
    packet_to_layer_specs,
)
from core.script_runner import SCRIPT_PRESETS, run_scapy_script


def test_packet_store_load_sample_pcap_and_filter():
    pcap = os.path.join(SRC_DIR, "01-06-2025 12:17:50_pman.pcap")
    assert os.path.exists(pcap)
    store = PacketStore()
    n = store.load_pcap(pcap)
    assert n > 0
    all_s = store.filter_summaries("")
    assert len(all_s) == n
    pkt = store.get(0)
    assert pkt is not None
    layers = dissect_packet(pkt)
    assert len(layers) >= 1
    assert len(format_hexdump(pkt)) > 0


def test_scapy_builder_and_code_gen():
    layers = get_all_scapy_layers()
    assert "IP" in layers and "TCP" in layers and "DNS" in layers
    assert len(layers) > 20
    fields = get_layer_fields("TCP")
    assert any(f[0] == "dport" for f in fields)

    stack = [
        LayerSpec("Ether", {"dst": "ff:ff:ff:ff:ff:ff"}),
        LayerSpec("IP", {"dst": "10.0.0.1"}),
        LayerSpec("TCP", {"dport": 443, "flags": "S"}),
    ]
    pkt = build_scapy_packet(stack)
    assert pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP)
    assert pkt[TCP].dport == 443
    code = generate_scapy_code(stack)
    assert "TCP(" in code and "443" in code

    roundtrip = packet_to_layer_specs(pkt)
    assert [s.name for s in roundtrip] == ["Ether", "IP", "TCP"]


def test_analytics_and_syn_burst_alert():
    pkts = [IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80 + i, flags="S") for i in range(30)]
    pkts.append(IP(src="10.0.0.9", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    a = compute_analytics(pkts)
    assert a.total_packets == 31
    assert any("SYN Burst" in alert for alert in a.alerts)
    assert any("Cleartext" in alert for alert in a.alerts)


def test_port_spec_and_script_runner():
    assert parse_port_spec("22,80,100-102") == [22, 80, 100, 101, 102]
    pkts = [IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443, flags="S")]
    res = run_scapy_script(SCRIPT_PRESETS["Top Talkers & Protocols"], pkts, pkts[0])
    assert res["ok"] is True
    assert "Total packets: 1" in res["output"]


def test_headless_qt_window():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt5.QtWidgets import QApplication
    from ui.main_window import PmanMainWindow

    app = QApplication.instance() or QApplication([])
    pcap = os.path.join(SRC_DIR, "01-06-2025 12:17:50_pman.pcap")
    win = PmanMainWindow(sample_pcap=pcap)
    assert win.pkt_table.rowCount() > 0
    assert win.tabs.count() == 5
    win.close()
