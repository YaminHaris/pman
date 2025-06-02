from scapy.all import *
import threading


def scan_(INTERFACE, FILTER,  EXECUTE):
    
    pkt = sniff(
    iface=INTERFACE,         # Interface to sniff on (None = default)
    count=1,            # Number of packets to capture (0 = infinite)
    timeout=None,       # Stop after N seconds
    filter=FILTER,        # BPF filter (like "tcp", "udp", "port 80")
    prn=EXECUTE,           # Callback function to apply on each packet
    store=1             # Whether to store packets in memory
    )


def start_instance(functionToThread):
    #an instance of the scan will be called in a seperate thread as to not clash with the gui
    THREAD = threading.Thread(target=functionToThread)    




