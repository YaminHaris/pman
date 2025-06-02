import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random

# --- Mock Packet Generation Functions ---
def get_random_ip():
    """Generates a random IPv4 address string."""
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def get_random_port():
    """Generates a random port number."""
    return random.randint(1024, 65535)

def get_random_mac():
    """Generates a random MAC address string."""
    return ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])

def generate_mock_packet(packet_id):
    """
    Generates a mock packet with a summary string and a details dictionary.
    """
    protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'ARP']
    protocol = random.choice(protocols)
    
    src_ip = get_random_ip()
    dst_ip = get_random_ip()
    src_mac = get_random_mac()
    dst_mac = get_random_mac()
    
    src_port = get_random_port() if protocol not in ['ICMP', 'ARP'] else None
    dst_port = get_random_port() if protocol not in ['ICMP', 'ARP'] else None
    length = random.randint(60, 1500)
    
    timestamp_str = time.strftime('%H:%M:%S')
    
    summary = f"ID: {packet_id:04d} | {timestamp_str} | {protocol.ljust(4)} | "
    
    if protocol == 'ARP':
        summary += f"{src_mac} -> {dst_mac} | Who has {dst_ip}? Tell {src_ip}"
    else:
        summary += f"{src_ip}"
        if src_port:
            summary += f":{src_port}"
        summary += f" -> {dst_ip}"
        if dst_port:
            summary += f":{dst_port}"
    summary += f" | Len: {length}"
    
    details = {
        "packet_id": packet_id,
        "timestamp": time.time(),
        "capture_time": timestamp_str,
        "protocol": protocol,
        "source_mac": src_mac,
        "destination_mac": dst_mac,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": src_port,
        "destination_port": dst_port,
        "length": length,
        "raw_data_hex": "0x" + "".join([random.choice("0123456789abcdef") for _ in range(random.randint(20,100))])
    }

    # Protocol-specific details
    if protocol == "TCP":
        details["flags"] = {
            "SYN": random.choice([True, False]), 
            "ACK": random.choice([True, False]), 
            "FIN": random.choice([True, False]),
            "RST": random.choice([False, False, False, True]) # Less frequent
        }
        details["sequence_number"] = random.randint(0, 2**32 - 1)
        details["acknowledgment_number"] = random.randint(0, 2**32 - 1)
        details["window_size"] = random.randint(0, 2**16 - 1)
    elif protocol == "UDP":
        details["checksum"] = f"0x{random.randint(0, 2**16 - 1):04x}"
    elif protocol == "ICMP":
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable"}
        icmp_type_code = random.choice(list(icmp_types.keys()))
        details["icmp_type"] = f"{icmp_type_code} ({icmp_types[icmp_type_code]})"
        details["icmp_code"] = random.randint(0,15)
    elif protocol == "HTTP":
        details["http_method"] = random.choice(["GET", "POST", "PUT", "HEAD"])
        details["http_path"] = "/" + "".join([random.choice("abcdefghijklmnopqrstuvwxyz/-_") for _ in range(random.randint(5,20))])
        details["http_host"] = f"www.example{random.randint(1,100)}.com"
    elif protocol == "DNS":
        details["dns_query_type"] = random.choice(["A", "AAAA", "MX", "CNAME", "TXT"])
        details["dns_query_name"] = f"service{random.randint(1,50)}.example.org"


    return summary, details

class ScapySnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Scapy Sniffing Utility (Simulated)")
        master.geometry("1000x750") # Adjusted size

        self.is_sniffing = False
        self.sniffing_thread = None
        self.packet_id_counter = 1
        self.all_packets_details = {} # Stores packet details, keyed by summary string
        self.displayed_packet_summaries = [] # Stores summaries currently in listbox

        # --- Styling ---
        self.style = ttk.Style()
        # Available themes: 'clam', 'alt', 'default', 'classic', 'vista', 'xpnative'
        # 'clam' or 'alt' are usually good cross-platform choices.
        try:
            self.style.theme_use('clam') 
        except tk.TclError:
            print("Clam theme not available, using default.")
            self.style.theme_use(self.style.theme_names()[0]) # Fallback to the first available theme
        
        self.style.configure("TButton", padding=6, relief="flat", font=('Helvetica', 10))
        self.style.map("Start.TButton", foreground=[('!disabled', 'white')], background=[('!disabled', 'green'), ('disabled', 'lightgrey')])
        self.style.map("Stop.TButton", foreground=[('!disabled', 'white')], background=[('!disabled', 'red'), ('disabled', 'lightgrey')])
        self.style.configure("TLabel", font=('Helvetica', 10), padding=2)
        self.style.configure("TEntry", padding=5, font=('Helvetica', 10))
        self.style.configure("Main.TFrame", background="#e0e0e0") # Light grey background for main frames
        self.style.configure("Header.TLabel", font=('Helvetica', 14, 'bold'), foreground="#333")
        self.style.configure("TLabelframe.Label", font=('Helvetica', 11, 'bold'), foreground="#333")
        self.style.configure("Status.TLabel", font=('Helvetica', 9), padding=3)


        # --- Main Layout Frames ---
        # Top control frame
        control_frame = ttk.Frame(master, padding="10 10 10 5", style="Main.TFrame")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        # Main display area (Packet List and Details)
        display_frame = ttk.Frame(master, padding="10 5 10 10", style="Main.TFrame")
        display_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Configure display_frame columns to resize proportionally
        display_frame.columnconfigure(0, weight=2) # Packet list takes 2/3
        display_frame.columnconfigure(1, weight=1) # Packet details take 1/3

        packet_list_frame = ttk.LabelFrame(display_frame, text="Captured Packets", padding="10")
        packet_list_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        packet_list_frame.rowconfigure(0, weight=1)
        packet_list_frame.columnconfigure(0, weight=1)


        packet_detail_frame = ttk.LabelFrame(display_frame, text="Packet Details", padding="10")
        packet_detail_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        packet_detail_frame.rowconfigure(0, weight=1)
        packet_detail_frame.columnconfigure(0, weight=1)

        # --- Control Frame Widgets ---
        ttk.Label(control_frame, text="Interface (Sim):").pack(side=tk.LEFT, padx=(0,5), pady=5)
        self.iface_var = tk.StringVar(value="eth0 (sim)")
        iface_options = ["eth0 (sim)", "wlan0 (sim)", "any (sim)", "lo (sim)"]
        iface_menu = ttk.OptionMenu(control_frame, self.iface_var, self.iface_var.get(), *iface_options)
        iface_menu.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing, style="Start.TButton")
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, style="Stop.TButton")
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Label(control_frame, text="Filter (in summary):").pack(side=tk.LEFT, padx=(15,0), pady=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.filter_entry.bind("<Return>", lambda event: self.apply_filter()) # Apply filter on Enter key

        self.filter_button = ttk.Button(control_frame, text="Apply", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=(0,5), pady=5)
        self.clear_filter_button = ttk.Button(control_frame, text="Clear", command=self.clear_filter)
        self.clear_filter_button.pack(side=tk.LEFT, padx=5, pady=5)


        # --- Packet List Frame Widgets ---
        self.packet_listbox = tk.Listbox(packet_list_frame, height=25, selectmode=tk.SINGLE, font=('Courier New', 9), activestyle='dotbox')
        self.packet_listbox.grid(row=0, column=0, sticky="nsew")
        
        list_scrollbar_y = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, command=self.packet_listbox.yview)
        list_scrollbar_y.grid(row=0, column=1, sticky="ns")
        self.packet_listbox.config(yscrollcommand=list_scrollbar_y.set)

        list_scrollbar_x = ttk.Scrollbar(packet_list_frame, orient=tk.HORIZONTAL, command=self.packet_listbox.xview)
        list_scrollbar_x.grid(row=1, column=0, sticky="ew")
        self.packet_listbox.config(xscrollcommand=list_scrollbar_x.set)
        
        self.packet_listbox.bind('<<ListboxSelect>>', self.show_packet_details)

        # --- Packet Detail Frame Widgets ---
        self.packet_detail_text = scrolledtext.ScrolledText(packet_detail_frame, height=25, state=tk.DISABLED, wrap=tk.WORD, font=('Consolas', 9), relief=tk.SOLID, borderwidth=1)
        self.packet_detail_text.grid(row=0, column=0, sticky="nsew")
        
        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Select an interface and start sniffing.")
        status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, style="Status.TLabel")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_sniffing(self):
        if self.is_sniffing:
            messagebox.showwarning("Sniffing Active", "Sniffing is already in progress.", parent=self.master)
            return

        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set(f"Sniffing on {self.iface_var.get()}... (Simulated)")
        
        # Optional: Clear previous session's packets from display and memory
        # self.packet_listbox.delete(0, tk.END)
        # self.all_packets_details.clear()
        # self.displayed_packet_summaries.clear()
        # self.packet_id_counter = 1 
        # self.clear_details_pane()

        self.sniffing_thread = threading.Thread(target=self.simulate_sniffing_loop, daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        # The thread is a daemon, so it will exit when the main program exits.
        # It also checks `self.is_sniffing` in its loop.
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Sniffing stopped.")

    def simulate_sniffing_loop(self):
        """Simulates packet capture in a loop. Runs in a separate thread."""
        while self.is_sniffing:
            summary, details = generate_mock_packet(self.packet_id_counter)
            
            # Schedule GUI update on the main thread
            self.master.after(0, self.add_packet_to_gui, summary, details)
            
            self.packet_id_counter += 1
            time.sleep(random.uniform(0.2, 1.0)) # Simulate packet arrival interval

    def add_packet_to_gui(self, summary, details):
        """Adds a packet to internal storage and updates the listbox if it matches the current filter."""
        if not self.master.winfo_exists(): # Check if window still exists
            self.is_sniffing = False # Stop sniffing if window closed
            return

        self.all_packets_details[summary] = details 
        
        filter_text = self.filter_var.get().lower()
        if not filter_text or filter_text in summary.lower():
            self.packet_listbox.insert(tk.END, summary)
            self.displayed_packet_summaries.append(summary)
            if self.packet_listbox.size() > 300: # Limit listbox visual size
                old_summary = self.displayed_packet_summaries.pop(0)
                # Find and delete the actual item from listbox (might not be at index 0 if filtered)
                try:
                    idx_to_delete = self.packet_listbox.get(0, tk.END).index(old_summary)
                    self.packet_listbox.delete(idx_to_delete)
                except ValueError:
                    pass # Item already removed by filter or not found
            self.packet_listbox.see(tk.END) # Scroll to the latest packet

    def clear_details_pane(self):
        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        self.packet_detail_text.config(state=tk.DISABLED)

    def show_packet_details(self, event=None): # event=None for programmatic call
        """Displays details of the selected packet in the details pane."""
        if not self.packet_listbox.curselection():
            self.clear_details_pane()
            return
        
        selected_index = self.packet_listbox.curselection()[0]
        selected_summary = self.packet_listbox.get(selected_index)
        
        details = self.all_packets_details.get(selected_summary)

        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        if details:
            for key, value in details.items():
                display_key = key.replace('_',' ').title()
                if isinstance(value, dict): # For nested structures like TCP flags
                    self.packet_detail_text.insert(tk.END, f"{display_key}:\n")
                    for sub_key, sub_value in value.items():
                        self.packet_detail_text.insert(tk.END, f"  {sub_key.title()}: {sub_value}\n")
                elif isinstance(value, list): # For potential list data
                     self.packet_detail_text.insert(tk.END, f"{display_key}:\n")
                     for item in value:
                         self.packet_detail_text.insert(tk.END, f"  - {item}\n")
                else:
                    self.packet_detail_text.insert(tk.END, f"{display_key}: {value}\n")
            self.packet_detail_text.insert(tk.END, f"\n--- Full Summary ---\n{selected_summary}\n")
        else:
            self.packet_detail_text.insert(tk.END, "Details not found for this packet.")
        self.packet_detail_text.config(state=tk.DISABLED)
        self.packet_detail_text.yview_moveto(0.0) # Scroll detail view to top

    def apply_filter(self):
        """Filters the displayed packets based on the text in the filter entry."""
        self.packet_listbox.delete(0, tk.END)
        self.displayed_packet_summaries.clear()
        filter_text = self.filter_var.get().lower()
        
        # Iterate over all captured packet summaries (keys of all_packets_details)
        # Sort them by packet_id to maintain order if needed, though dicts are ordered in modern Python
        # For simplicity, iterating directly. If order is critical and many packets, consider sorting keys.
        
        count = 0
        for summary in self.all_packets_details.keys(): # Iterate in captured order
            if not filter_text or filter_text in summary.lower():
                self.packet_listbox.insert(tk.END, summary)
                self.displayed_packet_summaries.append(summary)
                count +=1
        
        self.status_var.set(f"Filter applied: '{filter_text if filter_text else 'None'}'. Displaying {count} packets.")
        if self.packet_listbox.size() == 0 and filter_text:
            self.status_var.set(f"No packets match filter: '{filter_text}'")
        self.clear_details_pane() # Clear details as selection is lost

    def clear_filter(self):
        """Clears the filter entry and re-applies to show all packets."""
        self.filter_var.set("")
        self.apply_filter()
        self.status_var.set(f"Filter cleared. Displaying {self.packet_listbox.size()} packets.")

    def on_closing(self):
        """Handles the window close event."""
        if self.is_sniffing:
            if messagebox.askokcancel("Quit", "Sniffing is active. Do you want to stop and quit?", parent=self.master):
                self.stop_sniffing()
                self.master.destroy()
            # else: user cancelled, do nothing
        else:
            self.master.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = ScapySnifferGUI(root)
    # Handle window close button click
    root.protocol("WM_DELETE_WINDOW", app.on_closing) 
    root.mainloop()
