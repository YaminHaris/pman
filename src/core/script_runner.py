"""Interactive Scapy Python scripting console runner with diagnostic presets."""
from __future__ import annotations

import contextlib
import io
import traceback
from typing import Any, Dict, List, Optional

import scapy.all as scapy_all
from scapy.all import Packet

SCRIPT_PRESETS: Dict[str, str] = {
    "Top Talkers & Protocols": """# Summarizes protocols and top source IPs from loaded/captured packets
from collections import Counter
protos = Counter(p.lastlayer().name for p in packets)
print(f"Total packets: {len(packets)}")
print("Protocols:", dict(protos.most_common(10)))
srcs = Counter(p[IP].src for p in packets if p.haslayer(IP))
print("Top IPv4 sources:", srcs.most_common(5))
""",
    "Extract DNS Queries": """# Lists all DNS query names seen in the capture
queries = []
for i, p in enumerate(packets, 1):
    if p.haslayer(DNS) and p[DNS].qr == 0 and p[DNS].qd:
        queries.append((i, p[DNS].qd.qname.decode(errors='replace')))
print(f"Found {len(queries)} DNS queries:")
for idx, q in queries[:25]:
    print(f"  #{idx}: {q}")
""",
    "TCP Flag Breakdown": """# Counts TCP flag combinations across all TCP packets
from collections import Counter
flags = Counter(str(p[TCP].flags) for p in packets if p.haslayer(TCP))
print("TCP Flag counts:", dict(flags))
""",
    "Inspect Selected Packet": """# Full Scapy .show() dissection of the currently selected packet
if selected is None:
    print("No packet selected in Capture tab.")
else:
    selected.show()
""",
    "Craft & Dissect Custom Packet": """# Build a layered Scapy packet and inspect its compiled bytes & fields
pkt = IP(dst="1.1.1.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
pkt.show()
print("Raw length:", len(pkt), "bytes")
""",
}


def run_scapy_script(
    code: str,
    packets: List[Packet],
    selected: Optional[Packet] = None,
) -> Dict[str, Any]:
    """Execute a Scapy Python snippet and capture stdout/stderr."""
    env: Dict[str, Any] = {}
    for name in dir(scapy_all):
        if not name.startswith("_"):
            env[name] = getattr(scapy_all, name)
    env["packets"] = packets
    env["selected"] = selected

    buf = io.StringIO()
    ok = True
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            exec(compile(code, "<pman_console>", "exec"), env, env)
    except Exception:
        ok = False
        buf.write(traceback.format_exc())

    return {"ok": ok, "output": buf.getvalue()}
