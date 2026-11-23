"""LAN Radar, mDNS/SSDP service discovery, MAC classification, and passive OS fingerprinting."""
from __future__ import annotations

import ipaddress
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from scapy.all import DNS, DNSQR, IP, TCP, Packet

from .diagnostics import arp_discover


@dataclass
class LanDevice:
    ip: str
    mac: str
    mac_type: str
    rtt_ms: Optional[float]
    services: str
    role_hint: str


@dataclass
class PassiveFingerprint:
    ip: str
    packets: int
    ttl_min: int
    ttl_max: int
    est_init_ttl: int
    est_hops: int
    window_sample: int
    df_bit: bool
    os_guess: str


def classify_mac(mac: str) -> str:
    """Detect locally-administered / randomized MAC (common on iOS/Android Private Wi-Fi)."""
    try:
        first_octet = int(mac.split(":")[0], 16)
        if first_octet & 0x02:
            return "Randomized / Private MAC (iOS/Android)"
        return "Hardware OUI MAC"
    except Exception:
        return "Unknown"


def get_default_gateway_and_cidr() -> Tuple[str, str, str]:
    """Return (local_ip, gateway_ip, cidr) from OS routing table."""
    out = subprocess.check_output(["ip", "route", "show", "default"], text=True).strip()
    gw = "192.168.0.1"
    local_ip = "127.0.0.1"
    parts = out.split()
    if "via" in parts:
        gw = parts[parts.index("via") + 1]
    if "src" in parts:
        local_ip = parts[parts.index("src") + 1]
    net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return local_ip, gw, str(net)


def _measure_rtt_ms(ip: str, timeout: float = 0.6) -> Optional[float]:
    """Measure quick ICMP/TCP RTT to a LAN IP."""
    try:
        t0 = time.monotonic()
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            timeout=timeout + 1.0,
        )
        if res.returncode == 0:
            for tok in res.stdout.split():
                if tok.startswith("time="):
                    return float(tok.split("=", 1)[1])
            return round((time.monotonic() - t0) * 1000.0, 2)
    except Exception:
        pass
    return None


def _discover_mdns_ssdp(timeout: float = 1.0) -> Dict[str, List[str]]:
    """Query mDNS (224.0.0.251:5353) and SSDP (239.255.255.250:1900) without root."""
    services_by_ip: Dict[str, List[str]] = {}

    # Scapy-crafted mDNS PTR query
    try:
        msock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        msock.settimeout(timeout)
        for qname in ["_services._dns-sd._udp.local", "_companion-link._tcp.local", "_airplay._tcp.local"]:
            msock.sendto(bytes(DNS(rd=0, qd=DNSQR(qname=qname, qtype="PTR"))), ("224.0.0.251", 5353))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = msock.recvfrom(4096)
                resp = DNS(data)
                services_by_ip.setdefault(addr[0], [])
                if "mDNS" not in services_by_ip[addr[0]]:
                    services_by_ip[addr[0]].append("mDNS")
                if resp.an:
                    services_by_ip[addr[0]].append(resp.an.rrname.decode(errors="replace")[:32])
            except socket.timeout:
                break
        msock.close()
    except Exception:
        pass

    # SSDP M-SEARCH
    try:
        ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ssock.settimeout(timeout)
        msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        ssock.sendto(msg, ("239.255.255.250", 1900))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = ssock.recvfrom(4096)
                services_by_ip.setdefault(addr[0], [])
                for line in data.decode(errors="replace").splitlines():
                    if line.lower().startswith("server:"):
                        srv = line.split(":", 1)[1].strip()[:36]
                        if srv not in services_by_ip[addr[0]]:
                            services_by_ip[addr[0]].append(srv)
                        break
            except socket.timeout:
                break
        ssock.close()
    except Exception:
        pass

    return services_by_ip


def scan_lan_radar(cidr: Optional[str] = None, iface: Optional[str] = None) -> Dict[str, object]:
    """Discover LAN hosts, classify MACs, probe RTT, and attach mDNS/SSDP hints."""
    local_ip, gw, default_cidr = get_default_gateway_and_cidr()
    target_cidr = cidr or default_cidr
    raw_hosts = arp_discover(target_cidr, iface=iface)
    svc_map = _discover_mdns_ssdp(timeout=0.8)

    devices: List[LanDevice] = []
    for h in raw_hosts:
        ip = h["ip"]
        mac = h["mac"]
        mtype = classify_mac(mac)
        rtt = _measure_rtt_ms(ip)
        svcs = ", ".join(svc_map.get(ip, [])) or "-"
        if ip == gw:
            hint = "Router / Gateway"
        elif "Randomized" in mtype:
            hint = "Mobile Device (iOS / Android)"
        else:
            hint = "LAN Host"
        devices.append(LanDevice(ip=ip, mac=mac, mac_type=mtype, rtt_ms=rtt, services=svcs, role_hint=hint))

    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")) if "." in d.ip else (0,))
    return {"local_ip": local_ip, "gateway": gw, "cidr": target_cidr, "devices": devices}


def passive_os_fingerprint(packets: List[Packet]) -> List[PassiveFingerprint]:
    """Infer initial TTL, hop count, and OS stack from captured IP/TCP packets (p0f-style)."""
    stats: Dict[str, Dict[str, object]] = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        src = str(ip.src)
        ttl = int(ip.ttl)
        df = "DF" in str(ip.flags)
        win = int(pkt[TCP].window) if pkt.haslayer(TCP) else 0
        rec = stats.setdefault(src, {"count": 0, "ttls": [], "wins": [], "df": df})
        rec["count"] = int(rec["count"]) + 1
        rec["ttls"].append(ttl)  # type: ignore[attr-defined]
        if win:
            rec["wins"].append(win)  # type: ignore[attr-defined]
        rec["df"] = bool(rec["df"]) or df

    out: List[PassiveFingerprint] = []
    for ip, rec in sorted(stats.items(), key=lambda kv: -int(kv[1]["count"])):
        ttls: List[int] = rec["ttls"]  # type: ignore[assignment]
        wins: List[int] = rec["wins"]  # type: ignore[assignment]
        tmax = max(ttls)
        tmin = min(ttls)
        if tmax <= 64:
            init_ttl = 64
            os_guess = "Linux / macOS / iOS (TTL 64)"
        elif tmax <= 128:
            init_ttl = 128
            os_guess = "Windows / Cloud LB (TTL 128)"
        else:
            init_ttl = 255
            os_guess = "Network Appliance / Solaris (TTL 255)"
        hops = max(0, init_ttl - tmax)
        out.append(
            PassiveFingerprint(
                ip=ip,
                packets=int(rec["count"]),
                ttl_min=tmin,
                ttl_max=tmax,
                est_init_ttl=init_ttl,
                est_hops=hops,
                window_sample=wins[0] if wins else 0,
                df_bit=bool(rec["df"]),
                os_guess=os_guess,
            )
        )
    return out
