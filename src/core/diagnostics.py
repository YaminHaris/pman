"""Network diagnostics (ARP discovery, TCP port reachability, traceroute) and defensive traffic analytics."""
from __future__ import annotations

import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Packet, srp, traceroute

from .packet_engine import summarize_packet


@dataclass
class TrafficAnalytics:
    total_packets: int
    total_bytes: int
    protocols: List[Tuple[str, int]]
    top_sources: List[Tuple[str, int]]
    top_destinations: List[Tuple[str, int]]
    top_ports: List[Tuple[int, int]]
    alerts: List[str]


def parse_port_spec(spec: str) -> List[int]:
    """Parse '22,80,443' or '1-1024' into sorted unique port ints."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            for p in range(max(1, lo), min(65535, hi) + 1):
                ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def arp_discover(cidr: str, iface: Optional[str] = None, timeout: float = 2.0) -> List[Dict[str, str]]:
    """Run ARP discovery on a local subnet (requires raw socket / CAP_NET_RAW)."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    kwargs: Dict[str, Any] = {"timeout": timeout, "verbose": False}
    if iface:
        kwargs["iface"] = iface
    ans, _ = srp(pkt, **kwargs)
    hosts: List[Dict[str, str]] = []
    for _, rcv in ans:
        hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    return hosts


def tcp_port_probe(host: str, ports: List[int], timeout: float = 0.4) -> List[Dict[str, Any]]:
    """Check TCP port reachability for diagnostics without requiring root."""
    results: List[Dict[str, Any]] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((host, port))
            if rc == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "-"
                results.append({"port": port, "state": "OPEN", "service": service})
        except OSError:
            pass
        finally:
            sock.close()
    return results


def run_traceroute(target: str, max_hops: int = 20, timeout: float = 1.5) -> List[Dict[str, Any]]:
    """Run Scapy L3 traceroute toward target."""
    ans, _ = traceroute(target, maxttl=max_hops, timeout=timeout, verbose=False)
    hops: List[Dict[str, Any]] = []
    for snd, rcv in ans:
        hops.append({
            "ttl": int(snd.ttl),
            "ip": str(rcv.src),
            "proto": rcv.lastlayer().name,
        })
    hops.sort(key=lambda h: h["ttl"])
    return hops


def compute_analytics(packets: List[Packet]) -> TrafficAnalytics:
    """Compute protocol breakdown, top talkers, and defensive anomaly alerts."""
    proto_counts: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    syn_by_src: Counter[str] = Counter()
    rst_by_src: Counter[str] = Counter()
    icmp_by_src: Counter[str] = Counter()
    arp_ip_macs: Dict[str, set[str]] = defaultdict(set)
    cleartext_ports_seen: set[int] = set()
    total_bytes = 0

    for idx, pkt in enumerate(packets):
        total_bytes += len(pkt)
        s = summarize_packet(pkt, idx + 1)
        proto_counts[s.protocol] += 1
        if s.src != "-":
            src_counts[s.src] += 1
        if s.dst != "-":
            dst_counts[s.dst] += 1

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            port_counts[int(tcp.dport)] += 1
            flags = str(tcp.flags)
            if "S" in flags and "A" not in flags and pkt.haslayer(IP):
                syn_by_src[pkt[IP].src] += 1
            if "R" in flags and pkt.haslayer(IP):
                rst_by_src[pkt[IP].src] += 1
            if tcp.dport in (21, 23, 80) or tcp.sport in (21, 23, 80):
                cleartext_ports_seen.add(int(tcp.dport if tcp.dport in (21, 23, 80) else tcp.sport))
        elif pkt.haslayer(UDP):
            port_counts[int(pkt[UDP].dport)] += 1
        elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp_by_src[pkt[IP].src] += 1

        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            arp_ip_macs[pkt[ARP].psrc].add(pkt[ARP].hwsrc)

    alerts: List[str] = []
    for ip, cnt in syn_by_src.items():
        if cnt >= 25:
            alerts.append(f"[SYN Burst] {ip} sent {cnt} half-open SYN packets (possible port scan / SYN flood).")
    for ip, cnt in rst_by_src.items():
        if cnt >= 20:
            alerts.append(f"[High RST Rate] {ip} triggered {cnt} TCP RST packets.")
    for ip, cnt in icmp_by_src.items():
        if cnt >= 30:
            alerts.append(f"[ICMP Spike] {ip} generated {cnt} ICMP packets.")
    for ip, macs in arp_ip_macs.items():
        if len(macs) > 1:
            alerts.append(f"[ARP Conflict] {ip} claimed by multiple MACs: {', '.join(sorted(macs))}.")
    if cleartext_ports_seen:
        alerts.append(f"[Cleartext Traffic] Unencrypted service ports observed: {sorted(cleartext_ports_seen)}.")
    if not alerts and packets:
        alerts.append("[OK] No SYN bursts, ARP conflicts, or ICMP spikes detected in current capture.")

    return TrafficAnalytics(
        total_packets=len(packets),
        total_bytes=total_bytes,
        protocols=proto_counts.most_common(12),
        top_sources=src_counts.most_common(8),
        top_destinations=dst_counts.most_common(8),
        top_ports=port_counts.most_common(8),
        alerts=alerts,
    )
