"""Packet capture, PCAP I/O, display filtering, dissection, and hex dump helpers."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    AsyncSniffer,
    Ether,
    Packet,
    get_if_list,
    hexdump,
    rdpcap,
    wrpcap,
)


@dataclass
class PacketSummary:
    index: int
    timestamp: str
    src: str
    dst: str
    protocol: str
    length: int
    info: str


def list_interfaces() -> List[str]:
    """Return available network interfaces."""
    try:
        ifaces = list(get_if_list())
        return ifaces if ifaces else ["lo"]
    except Exception:
        return ["lo"]


def summarize_packet(pkt: Packet, index: int, base_time: Optional[float] = None) -> PacketSummary:
    """Extract Wireshark-style summary columns from a Scapy Packet."""
    pkt_time = float(getattr(pkt, "time", time.time()))
    rel = (pkt_time - base_time) if base_time is not None else 0.0
    ts_str = f"{rel:0.4f}s" if base_time is not None else time.strftime("%H:%M:%S", time.localtime(pkt_time))

    src = "-"
    dst = "-"
    proto = pkt.lastlayer().name if pkt.layers() else "RAW"
    info = pkt.summary()

    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "IPv4"
    elif pkt.haslayer(IPv6):
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
        proto = "IPv6"
    elif pkt.haslayer(ARP):
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        proto = "ARP"
        op = "Who has" if pkt[ARP].op == 1 else "is at"
        info = f"ARP {op} {pkt[ARP].pdst} ({pkt[ARP].psrc})"
    elif pkt.haslayer(Ether):
        src = pkt[Ether].src
        dst = pkt[Ether].dst
        proto = "Ethernet"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = "HTTP" if (tcp.dport in (80, 8080) or tcp.sport in (80, 8080)) else (
            "TLS" if (tcp.dport == 443 or tcp.sport == 443) else "TCP"
        )
        info = f"{tcp.sport} -> {tcp.dport} [{tcp.flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        if pkt.haslayer(DNS):
            proto = "DNS"
            dns = pkt[DNS]
            qname = dns.qd.qname.decode(errors="replace") if dns.qd else ""
            kind = "Response" if dns.qr else "Query"
            info = f"DNS {kind} {qname}".strip()
        else:
            proto = "UDP"
            info = f"{udp.sport} -> {udp.dport} Len={udp.len}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        icmp = pkt[ICMP]
        info = f"ICMP type={icmp.type} code={icmp.code}"

    return PacketSummary(
        index=index,
        timestamp=ts_str,
        src=str(src),
        dst=str(dst),
        protocol=str(proto),
        length=len(pkt),
        info=str(info),
    )


def dissect_packet(pkt: Packet) -> List[Tuple[str, List[Tuple[str, str]]]]:
    """Return structured list of (layer_name, [(field, value), ...]) for tree view."""
    layers_out: List[Tuple[str, List[Tuple[str, str]]]] = []
    cur: Optional[Packet] = pkt
    while cur is not None and not isinstance(cur, type(None)):
        fields: List[Tuple[str, str]] = []
        for fdesc in getattr(cur, "fields_desc", []):
            fname = fdesc.name
            try:
                val = cur.getfieldval(fname)
                fields.append((fname, repr(val) if isinstance(val, bytes) else str(val)))
            except Exception as exc:
                fields.append((fname, f"<err: {exc}>"))
        layers_out.append((cur.name, fields))
        payload = cur.payload
        if payload is None or payload.__class__.__name__ == "NoPayload":
            break
        cur = payload
    return layers_out


def format_hexdump(pkt: Packet) -> str:
    """Return Wireshark-style hex + ASCII dump string."""
    try:
        return hexdump(pkt, dump=True) or ""
    except Exception as exc:
        return f"<hexdump error: {exc}>"


class PacketStore:
    """Thread-safe container for captured/loaded packets with display filtering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets: List[Packet] = []
        self._base_time: Optional[float] = None

    def clear(self) -> None:
        with self._lock:
            self._packets.clear()
            self._base_time = None

    def append(self, pkt: Packet) -> int:
        with self._lock:
            if self._base_time is None:
                self._base_time = float(getattr(pkt, "time", time.time()))
            self._packets.append(pkt)
            return len(self._packets) - 1

    def extend(self, pkts: List[Packet]) -> None:
        with self._lock:
            for pkt in pkts:
                if self._base_time is None:
                    self._base_time = float(getattr(pkt, "time", time.time()))
                self._packets.append(pkt)

    def all(self) -> List[Packet]:
        with self._lock:
            return list(self._packets)

    def get(self, idx: int) -> Optional[Packet]:
        with self._lock:
            if 0 <= idx < len(self._packets):
                return self._packets[idx]
            return None

    def __len__(self) -> int:
        with self._lock:
            return len(self._packets)

    def load_pcap(self, path: str) -> int:
        pkts = list(rdpcap(path))
        self.clear()
        self.extend(pkts)
        return len(pkts)

    def save_pcap(self, path: str) -> int:
        pkts = self.all()
        wrpcap(path, pkts)
        return len(pkts)

    def filter_summaries(self, query: str = "") -> List[PacketSummary]:
        """Filter packets using a simple Wireshark-like display expression (proto, IP, port, or substring)."""
        q = query.strip().lower()
        with self._lock:
            base = self._base_time
            pkts = list(self._packets)

        out: List[PacketSummary] = []
        for idx, pkt in enumerate(pkts):
            s = summarize_packet(pkt, idx + 1, base)
            if not q:
                out.append(s)
                continue
            haystack = f"{s.protocol} {s.src} {s.dst} {s.info}".lower()
            # Support simple key=value tokens like ip=1.2.3.4, port=80, proto=tcp
            tokens = [t for t in q.split() if t]
            matched = True
            for tok in tokens:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    if k in ("ip", "host") and v not in (s.src.lower(), s.dst.lower()):
                        matched = False
                        break
                    elif k == "src" and v not in s.src.lower():
                        matched = False
                        break
                    elif k == "dst" and v not in s.dst.lower():
                        matched = False
                        break
                    elif k in ("proto", "protocol") and v not in s.protocol.lower():
                        matched = False
                        break
                    elif k == "port" and v not in s.info.lower():
                        matched = False
                        break
                elif tok not in haystack:
                    matched = False
                    break
            if matched:
                out.append(s)
        return out


def has_raw_socket_privilege() -> bool:
    """Return True if current process can open AF_PACKET raw sockets."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.close()
        return True
    except PermissionError:
        return False
    except OSError:
        return False


class LiveSniffer:
    """Non-blocking Scapy AsyncSniffer wrapper with pre-flight privilege check."""

    def __init__(self) -> None:
        self._sniffer: Optional[AsyncSniffer] = None
        self.running = False

    def start(self, iface: str, bpf_filter: str, on_packet: Any, on_error: Any = None) -> None:
        if self.running:
            return
        if not has_raw_socket_privilege():
            msg = "Raw packet capture requires root or CAP_NET_RAW. Click 'Elevate (pkexec)' in the toolbar."
            if on_error:
                on_error(msg)
                return
            raise PermissionError(msg)
        kwargs: dict[str, Any] = {
            "iface": iface if iface else None,
            "prn": on_packet,
            "store": False,
        }
        if bpf_filter.strip():
            kwargs["filter"] = bpf_filter.strip()
        try:
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self.running = True
        except Exception as exc:
            self.running = False
            self._sniffer = None
            if on_error:
                on_error(str(exc))
            else:
                raise

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self.running = False
