import tkinter as tk
from tkinter import ttk, scrolledtext
import psutil
from scanner_engine_0 import ScannerEngine


def get_network_interfaces():
    return list(psutil.net_if_addrs().keys())

class ScannerFrame(tk.Frame):
    def __init__(self, parent, start_scan_callback, stop_scan_callback):
        super().__init__(parent)
        self.start_scan_callback = start_scan_callback
        self.stop_scan_callback = stop_scan_callback
        self.scanning = False
        self.scanner = None
        self.create_widgets()

    def packet_callback(self, pkt):
        self.append_output(pkt.summary())

    def toggle_scan(self):
        if not self.scanning:
            self.scanning = True
            self.toggle_button.config(text="Stop Scan")

            config = self.get_scan_config()
            self.start_scan_callback(config)

            # Initialize scanner with dynamic config
            self.scanner = ScannerEngine(
                config["interface"],
                config["bpf_filter"] or "ip",
                self.packet_callback
            )
            self.scanner.start()

        else:
            self.scanning = False
            self.toggle_button.config(text="Start Scan")
            self.stop_scan_callback()

            if self.scanner:
                self.scanner.stop()

    def create_widgets(self):
        self.toggle_button = ttk.Button(self, text="Start Scan", command=self.toggle_scan)
        self.toggle_button.pack(pady=10)

        form = ttk.Frame(self)
        form.pack(pady=10)

        interfaces = get_network_interfaces()
        self.interface = self._dropdown(form, "Interface", interfaces, 0)

        self.target_ip = self._entry(form, "Target IP / Subnet", 1)
        self.port_range = self._entry(form, "Port Range (e.g., 1-1000)", 2)
        self.packet_filter = self._dropdown(form, "Packet Filter", ["ALL", "TCP", "UDP", "ICMP"], 3)
        self.scan_type = self._dropdown(form, "Scan Type", ["SYN", "ACK", "FIN", "XMAS"], 4)
        self.display_mode = self._dropdown(form, "Display Mode", ["Headers Only", "Raw", "Hexdump"], 5)

        self.promisc = tk.BooleanVar()
        self.pcap_save = tk.BooleanVar()
        ttk.Checkbutton(form, text="Promiscuous Mode", variable=self.promisc).grid(row=6, column=0, sticky="w", pady=2)
        ttk.Checkbutton(form, text="Save to PCAP", variable=self.pcap_save).grid(row=6, column=1, sticky="w", pady=2)

        self.pcap_path = self._entry(form, "PCAP Path (if enabled)", 7)
        self.bpf_filter = self._entry(form, "Custom BPF Filter (Optional)", 8)
        self.packet_count = self._entry(form, "Packet Count (0 = infinite)", 9)
        self.timeout = self._entry(form, "Sniff Timeout (seconds)", 10)

        # Output Box
        self.output_box = scrolledtext.ScrolledText(self, width=100, height=20, font=("Courier", 10))
        self.output_box.pack(pady=10, padx=10)

    def _entry(self, parent, label, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=5, pady=2)
        entry = ttk.Entry(parent, width=40)
        entry.grid(row=row, column=1, sticky="w", padx=5, pady=2)
        return entry

    def _dropdown(self, parent, label, options, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=5, pady=2)
        combo = ttk.Combobox(parent, values=options, state="readonly", width=38)
        combo.current(0)
        combo.grid(row=row, column=1, sticky="w", padx=5, pady=2)
        return combo

    def get_scan_config(self):
        return {
            "interface": self.interface.get(),
            "target_ip": self.target_ip.get(),
            "port_range": self.port_range.get(),
            "packet_filter": self.packet_filter.get(),
            "scan_type": self.scan_type.get(),
            "display_mode": self.display_mode.get(),
            "promiscuous": self.promisc.get(),
            "save_pcap": self.pcap_save.get(),
            "pcap_path": self.pcap_path.get(),
            "bpf_filter": self.bpf_filter.get(),
            "packet_count": int(self.packet_count.get()) if self.packet_count.get().isdigit() else 0,
            "timeout": int(self.timeout.get()) if self.timeout.get().isdigit() else 0
        }

    def append_output(self, text):
        self.output_box.insert(tk.END, text + "\n")
        self.output_box.see(tk.END)

