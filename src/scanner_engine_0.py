from scapy.all import sniff, wrpcap
import threading
from datetime import datetime
import os
import signal

# Ensure the output directory exists
os.makedirs("pcap", exist_ok=True)


class ScannerEngine:
    def __init__(self, iface, bpf_filter, packet_handler):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.packet_handler = packet_handler
        self.running = False
        self.thread = None

        # Generate unique pcap filename
        now = datetime.now()
        dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")
        self.pcap_file = f"pcap/{dt_string}_pman.pcap"

        # Create empty file initially
        wrpcap(self.pcap_file, [])

    def scan(self):
        while self.running:
            pkt = sniff(
                iface=self.iface,
                count=1,
                timeout=None,
                filter=self.bpf_filter,
                prn=self.packet_handler,
                store=1
            )
            wrpcap(self.pcap_file, pkt, append=True)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            print(f"[+] Started scanning on {self.iface} with filter '{self.bpf_filter}'")

    def stop(self):
        if self.running:
            self.running = False
            self.thread.join()
            print("[+] Stopped scanning.")


# Optional: Graceful interrupt handler (Ctrl+C)
def setup_interrupt_handler(scanner_instance):
    def handler(sig, frame):
        print("\n[!] Interrupt received, stopping scan...")
        scanner_instance.stop()
    signal.signal(signal.SIGINT, handler)


def packet_callback(pkt):
    print(pkt.summary())

#scanner = ScannerEngine("wlp3s0", "tcp", packet_callback)
#setup_interrupt_handler(scanner)
#scanner.start()

