"""Universal Scapy layered packet builder, code generator, and sender."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Type

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Dot1Q,
    Ether,
    IPv6,
    Packet,
    Raw,
    conf,
    send,
    sendp,
    sr1,
    srp1,
)

COMMON_LAYERS: Dict[str, Type[Packet]] = {
    "Ether": Ether,
    "Dot1Q": Dot1Q,
    "ARP": ARP,
    "IP": IP,
    "IPv6": IPv6,
    "ICMP": ICMP,
    "TCP": TCP,
    "UDP": UDP,
    "DNS": DNS,
    "DNSQR": DNSQR,
    "Raw": Raw,
}


@dataclass
class LayerSpec:
    name: str
    fields: Dict[str, Any]


def get_all_scapy_layers() -> Dict[str, Type[Packet]]:
    """Return mapping of all registered Scapy layer names to their Packet classes."""
    layers: Dict[str, Type[Packet]] = dict(COMMON_LAYERS)
    try:
        for cls in conf.layers:
            if isinstance(cls, type) and issubclass(cls, Packet):
                layers.setdefault(cls.__name__, cls)
    except Exception:
        pass
    return layers


def get_layer_fields(layer_name: str) -> List[Tuple[str, Any, str]]:
    """Return [(field_name, default_value, type_hint), ...] for any Scapy layer."""
    layers = get_all_scapy_layers()
    cls = layers.get(layer_name)
    if cls is None:
        return []
    inst = cls()
    out: List[Tuple[str, Any, str]] = []
    for fdesc in getattr(cls, "fields_desc", []):
        fname = fdesc.name
        try:
            default = inst.getfieldval(fname)
        except Exception:
            default = getattr(fdesc, "default", "")
        if isinstance(default, bytes):
            default_repr: Any = default.decode(errors="replace")
        else:
            default_repr = default
        out.append((fname, default_repr, fdesc.__class__.__name__))
    return out


def parse_field_value(raw_str: str, original_default: Any) -> Any:
    """Coerce GUI string input into the appropriate Python/Scapy field value."""
    s = raw_str.strip()
    if s == "" or s == "None":
        return None
    if isinstance(original_default, int) and not isinstance(original_default, bool):
        try:
            return int(s, 0)
        except ValueError:
            return s
    if isinstance(original_default, float):
        try:
            return float(s)
        except ValueError:
            return s
    if isinstance(original_default, bytes):
        return s.encode("utf-8")
    if s.startswith("[") or s.startswith("(") or s.startswith("{"):
        try:
            return ast.literal_eval(s)
        except Exception:
            return s
    return s


def build_scapy_packet(stack: List[LayerSpec]) -> Packet:
    """Compile a list of LayerSpecs into a Scapy Packet."""
    if not stack:
        raise ValueError("Layer stack is empty")
    layers = get_all_scapy_layers()
    pkt: Optional[Packet] = None
    for spec in stack:
        cls = layers.get(spec.name)
        if cls is None:
            raise ValueError(f"Unknown Scapy layer: {spec.name}")
        kwargs = {k: v for k, v in spec.fields.items() if v is not None}
        layer_obj = cls(**kwargs)
        pkt = layer_obj if pkt is None else (pkt / layer_obj)
    assert pkt is not None
    return pkt


def generate_scapy_code(stack: List[LayerSpec]) -> str:
    """Generate clean Python/Scapy expression for the current layer stack."""
    if not stack:
        return "# Add layers on the left to build a packet"
    parts: List[str] = []
    layers = get_all_scapy_layers()
    for spec in stack:
        cls = layers.get(spec.name)
        defaults = {}
        if cls is not None:
            inst = cls()
            for fdesc in getattr(cls, "fields_desc", []):
                try:
                    defaults[fdesc.name] = inst.getfieldval(fdesc.name)
                except Exception:
                    pass
        args = []
        for k, v in spec.fields.items():
            if v is not None and v != defaults.get(k):
                args.append(f"{k}={v!r}")
        parts.append(f"{spec.name}({', '.join(args)})")
    return " / ".join(parts)


def packet_to_layer_specs(pkt: Packet) -> List[LayerSpec]:
    """Convert an existing captured Scapy Packet into editable LayerSpecs."""
    specs: List[LayerSpec] = []
    cur: Optional[Packet] = pkt
    while cur is not None and cur.__class__.__name__ != "NoPayload":
        fields: Dict[str, Any] = {}
        for fdesc in getattr(cur, "fields_desc", []):
            try:
                fields[fdesc.name] = cur.getfieldval(fdesc.name)
            except Exception:
                pass
        specs.append(LayerSpec(name=cur.__class__.__name__, fields=fields))
        cur = cur.payload if cur.payload and cur.payload.__class__.__name__ != "NoPayload" else None
    return specs


def transmit_packet(
    pkt: Packet,
    layer2: bool = False,
    count: int = 1,
    inter: float = 0.05,
    wait_reply: bool = False,
    iface: Optional[str] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Send a packet (L2 or L3) and optionally wait for a reply with sr1/srp1."""
    kwargs: Dict[str, Any] = {"verbose": False}
    if iface:
        kwargs["iface"] = iface

    if wait_reply:
        reply = srp1(pkt, timeout=timeout, **kwargs) if layer2 else sr1(pkt, timeout=timeout, **kwargs)
        return {
            "sent": 1,
            "mode": "srp1 (L2)" if layer2 else "sr1 (L3)",
            "reply": reply,
            "reply_summary": reply.summary() if reply is not None else "No reply within timeout",
        }

    if layer2:
        sendp(pkt, count=count, inter=inter, **kwargs)
    else:
        send(pkt, count=count, inter=inter, **kwargs)
    return {
        "sent": count,
        "mode": "sendp (L2)" if layer2 else "send (L3)",
        "reply": None,
        "reply_summary": f"Transmitted {count} packet(s) via {'L2' if layer2 else 'L3'}",
    }
