import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random # Keep for potential future use, though not for core sniffing now

try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    from scapy.arch import get_if_list, get_working_ifaces # To get interface list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Mock Scapy layers for the GUI to still load if Scapy is not installed,
    # though sniffing won't work.
    class MockLayer:
        def __init__(self, name="MockLayer"):
            self.name = name
        def __getattr__(self, item):
            return f"mock_{item}"
        def haslayer(self, _): return False
        def show(self, dump=False): return "Scapy not installed. Mock packet data."

    Ether = IP = TCP = UDP = ICMP = ARP = DNS = Raw = MockLayer

class ScapySnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Scapy Sniffing Utility")
        master.geometry("1100x800") # Slightly wider for more details

        self.is_sniffing = False
        self.sniffing_thread = None
        self.packet_id_counter = 1
        self.all_packets_details = {} 
        self.displayed_packet_summaries = []

        if not SCAPY_AVAILABLE:
            messagebox.showerror("Scapy Not Found", 
                                 "The Scapy library is not installed or could not be imported. "
                                 "Live sniffing functionality will be disabled. "
                                 "Please install Scapy (e.g., 'pip install scapy') and ensure it's in your Python path.",
                                 parent=self.master)

        # --- Styling ---
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam') 
        except tk.TclError:
            print("Clam theme not available, using default.")
            try:
                self.style.theme_use(self.style.theme_names()[0])
            except tk.TclError:
                print("No ttk themes available.")

        self.style.configure("TButton", padding=6, relief="flat", font=('Helvetica', 10))
        self.style.map("Start.TButton", foreground=[('!disabled', 'white')], background=[('!disabled', 'green'), ('disabled', 'lightgrey')])
        self.style.map("Stop.TButton", foreground=[('!disabled', 'white')], background=[('!disabled', 'red'), ('disabled', 'lightgrey')])
        self.style.configure("TLabel", font=('Helvetica', 10), padding=2)
        self.style.configure("TEntry", padding=5, font=('Helvetica', 10))
        self.style.configure("Main.TFrame", background="#e0e0e0")
        self.style.configure("Header.TLabel", font=('Helvetica', 14, 'bold'), foreground="#333")
        self.style.configure("TLabelframe.Label", font=('Helvetica', 11, 'bold'), foreground="#333")
        self.style.configure("Status.TLabel", font=('Helvetica', 9), padding=3)

        # --- Main Layout Frames ---
        control_frame = ttk.Frame(master, padding="10 10 10 5", style="Main.TFrame")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        display_frame = ttk.Frame(master, padding="10 5 10 10", style="Main.TFrame")
        display_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        display_frame.columnconfigure(0, weight=3) # Packet list wider
        display_frame.columnconfigure(1, weight=2) # Packet details

        packet_list_frame = ttk.LabelFrame(display_frame, text="Captured Packets", padding="10")
        packet_list_frame.grid(row=0, column=0, sticky="nsew", padx=(0,5))
        packet_list_frame.rowconfigure(0, weight=1)
        packet_list_frame.columnconfigure(0, weight=1)

        packet_detail_frame = ttk.LabelFrame(display_frame, text="Packet Details", padding="10")
        packet_detail_frame.grid(row=0, column=1, sticky="nsew", padx=(5,0))
        packet_detail_frame.rowconfigure(0, weight=1)
        packet_detail_frame.columnconfigure(0, weight=1)

        # --- Control Frame Widgets ---
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0,5), pady=5)
        
        iface_options = ["any"] # Default option
        if SCAPY_AVAILABLE:
            try:
                # Get a list of working interfaces. This might require privileges on some systems.
                # Using get_working_ifaces() is generally more reliable.
                real_ifaces = [iface.name for iface in get_working_ifaces() if iface.name]
                if real_ifaces:
                    iface_options = real_ifaces
                else: # Fallback if get_working_ifaces returns empty or only unnamed
                    iface_options = get_if_list() 
                    if not iface_options: iface_options = ["any"] # Final fallback
            except Exception as e:
                print(f"Could not get interface list: {e}. Using default 'any'.")
                iface_options = ["any", "eth0", "wlan0", "lo"] # Common fallbacks

        self.iface_var = tk.StringVar(value=iface_options[0])
        iface_menu = ttk.OptionMenu(control_frame, self.iface_var, self.iface_var.get(), *iface_options)
        iface_menu.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing, style="Start.TButton", state=tk.NORMAL if SCAPY_AVAILABLE else tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, style="Stop.TButton")
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Label(control_frame, text="Filter (Summary):").pack(side=tk.LEFT, padx=(15,0), pady=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=25)
        self.filter_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.filter_entry.bind("<Return>", lambda event: self.apply_filter())

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
        initial_status = "Ready." if SCAPY_AVAILABLE else "Ready (Scapy not found - sniffing disabled)."
        self.status_var.set(initial_status + " Select an interface and start sniffing. Run with admin privileges for live capture.")
        status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, style="Status.TLabel")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def start_sniffing(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Scapy Not Available", "Cannot start sniffing because Scapy is not installed or failed to import.", parent=self.master)
            return
        if self.is_sniffing:
            messagebox.showwarning("Sniffing Active", "Sniffing is already in progress.", parent=self.master)
            return

        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        selected_iface = self.iface_var.get()
        if selected_iface.lower() == "any": selected_iface = None # Scapy uses None for all interfaces

        self.status_var.set(f"Sniffing on {selected_iface or 'all interfaces'}... (Requires Admin Privileges)")
        
        self.sniffing_thread = threading.Thread(target=self.actual_sniffing_loop, args=(selected_iface,), daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing_condition(self):
        """Called by Scapy's sniff function to check if it should stop."""
        return not self.is_sniffing

    def actual_sniffing_loop(self, interface_name):
        """Runs Scapy's sniff function."""
        try:
            sniff(iface=interface_name, prn=self.process_scapy_packet, stop_filter=self.stop_sniffing_condition, store=False)
        except PermissionError:
            self.master.after(0, lambda: messagebox.showerror("Permission Error", "Permission denied. Please run the script with administrative (root/sudo) privileges.", parent=self.master))
            self.master.after(0, self.stop_sniffing) # Ensure GUI state is reset
        except Exception as e:
            # Catch other Scapy or network related errors
            error_message = f"An error occurred during sniffing: {e}\n"
            error_message += "Ensure the selected interface is correct and active. "
            error_message += "You might need to run as administrator/root."
            self.master.after(0, lambda: messagebox.showerror("Sniffing Error", error_message, parent=self.master))
            self.master.after(0, self.stop_sniffing)
        finally:
            if self.is_sniffing: # If loop exited for reasons other than stop button
                 self.master.after(0, self.stop_sniffing)


    def process_scapy_packet(self, pkt):
        """Callback for Scapy's sniff. Processes each captured packet."""
        if not self.is_sniffing: # Check if sniffing was stopped while packet was in flight
            return

        current_id = self.packet_id_counter
        self.packet_id_counter += 1
        
        timestamp_str = time.strftime('%H:%M:%S')
        summary = f"ID: {current_id:04d} | {timestamp_str} | "
        details = {
            "packet_id": current_id,
            "timestamp": time.time(),
            "capture_time": timestamp_str,
            "length": len(pkt),
            "raw_scapy_output": pkt.show(dump=True) # Full Scapy packet structure
        }

        # Layer 2: Ethernet
        if pkt.haslayer(Ether):
            details["source_mac"] = pkt[Ether].src
            details["destination_mac"] = pkt[Ether].dst
            details["ether_type"] = hex(pkt[Ether].type)
            summary += f"{pkt[Ether].src} -> {pkt[Ether].dst} | "
        else: # Default for non-Ethernet like loopback
            details["source_mac"] = "N/A"
            details["destination_mac"] = "N/A"

        # Layer 3: IP
        if pkt.haslayer(IP):
            details["source_ip"] = pkt[IP].src
            details["destination_ip"] = pkt[IP].dst
            details["ip_protocol"] = pkt[IP].proto 
            summary += f"{pkt[IP].src} -> {pkt[IP].dst} | "
        elif pkt.haslayer(ARP):
            details["source_ip"] = pkt[ARP].psrc
            details["destination_ip"] = pkt[ARP].pdst
            summary += f"ARP: {pkt[ARP].psrc} asks for {pkt[ARP].pdst} | "
        else:
            details["source_ip"] = "N/A"
            details["destination_ip"] = "N/A"

        # Layer 4: TCP/UDP/ICMP
        proto_name = "Unknown"
        if pkt.haslayer(TCP):
            proto_name = "TCP"
            details["protocol"] = "TCP"
            details["source_port"] = pkt[TCP].sport
            details["destination_port"] = pkt[TCP].dport
            details["tcp_flags"] = str(pkt[TCP].flags)
            details["sequence_number"] = pkt[TCP].seq
            details["acknowledgment_number"] = pkt[TCP].ack
            summary += f"TCP {pkt[TCP].sport}->{pkt[TCP].dport} Flags:[{pkt[TCP].flags}] | "
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            details["protocol"] = "UDP"
            details["source_port"] = pkt[UDP].sport
            details["destination_port"] = pkt[UDP].dport
            summary += f"UDP {pkt[UDP].sport}->{pkt[UDP].dport} | "
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
            details["protocol"] = "ICMP"
            details["icmp_type"] = pkt[ICMP].type
            details["icmp_code"] = pkt[ICMP].code
            summary += f"ICMP Type:{pkt[ICMP].type} Code:{pkt[ICMP].code} | "
        elif pkt.haslayer(DNS) and pkt.haslayer(UDP): # DNS often over UDP
            proto_name = "DNS"
            details["protocol"] = "DNS"
            # Basic DNS info, Scapy's DNS layer can be complex
            if pkt[DNS].qr == 0: # Query
                summary += f"DNS Query ID:{pkt[DNS].id} Name:{pkt[DNS].qd.qname.decode() if pkt[DNS].qd else 'N/A'} | "
            else: # Response
                summary += f"DNS Resp. ID:{pkt[DNS].id} | "
            details["dns_id"] = pkt[DNS].id
            details["dns_qr"] = "Query" if pkt[DNS].qr == 0 else "Response"
            if pkt[DNS].qd: details["dns_query_name"] = pkt[DNS].qd.qname.decode()
            # Add more DNS fields if needed, e.g., answers (pkt[DNS].an)
        elif pkt.haslayer(ARP):
            proto_name = "ARP"
            details["protocol"] = "ARP"
            # ARP summary already handled above
        else:
            # Try to get the highest layer name if common ones aren't found
            if pkt.layers():
                proto_name = pkt.layers()[-1].name # Name of the highest layer
            details["protocol"] = proto_name

        summary += f"{proto_name.ljust(4)} | Len: {len(pkt)}"
        details["summary_generated"] = summary # Store the generated summary for consistency

        # Add raw payload if present
        if pkt.haslayer(Raw):
            try:
                details["payload_utf8"] = pkt[Raw].load.decode('utf-8', errors='replace')[:200] + "..." # Preview
                details["payload_hex"] = pkt[Raw].load.hex()[:200] + "..." # Preview
            except Exception:
                details["payload_hex"] = pkt[Raw].load.hex()[:200] + "..." # Preview

        # Schedule GUI update on the main thread
        self.master.after(0, self.add_packet_to_gui, summary, details)


    def stop_sniffing(self):
        if self.is_sniffing:
            self.is_sniffing = False # This will be checked by stop_sniffing_condition
            # The sniffing thread will terminate once sniff() returns.
        self.start_button.config(state=tk.NORMAL if SCAPY_AVAILABLE else tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("Sniffing stopped.")


    def add_packet_to_gui(self, summary, details):
        if not self.master.winfo_exists(): 
            self.is_sniffing = False 
            return

        self.all_packets_details[summary] = details 
        
        filter_text = self.filter_var.get().lower()
        if not filter_text or filter_text in summary.lower():
            self.packet_listbox.insert(tk.END, summary)
            self.displayed_packet_summaries.append(summary)
            if self.packet_listbox.size() > 500: # Limit visual listbox size
                old_summary = self.displayed_packet_summaries.pop(0)
                try:
                    # Find the actual index in the listbox as it might be filtered
                    all_lb_items = self.packet_listbox.get(0, tk.END)
                    if old_summary in all_lb_items:
                        idx_to_delete = all_lb_items.index(old_summary)
                        self.packet_listbox.delete(idx_to_delete)
                except ValueError:
                     pass # Item might have been removed by a filter action
            self.packet_listbox.see(tk.END) 

    def clear_details_pane(self):
        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        self.packet_detail_text.config(state=tk.DISABLED)

    def show_packet_details(self, event=None):
        if not self.packet_listbox.curselection():
            self.clear_details_pane()
            return
        
        selected_index = self.packet_listbox.curselection()[0]
        selected_summary = self.packet_listbox.get(selected_index)
        
        details = self.all_packets_details.get(selected_summary)

        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        if details:
            self.packet_detail_text.insert(tk.END, "--- Parsed Details ---\n")
            for key, value in details.items():
                if key == "raw_scapy_output": continue # Display this separately
                display_key = key.replace('_',' ').title()
                if isinstance(value, dict):
                    self.packet_detail_text.insert(tk.END, f"{display_key}:\n")
                    for sub_key, sub_value in value.items():
                        self.packet_detail_text.insert(tk.END, f"  {str(sub_key).title()}: {sub_value}\n")
                elif isinstance(value, list):
                     self.packet_detail_text.insert(tk.END, f"{display_key}:\n")
                     for item in value:
                         self.packet_detail_text.insert(tk.END, f"  - {item}\n")
                else:
                    self.packet_detail_text.insert(tk.END, f"{display_key}: {value}\n")
            
            self.packet_detail_text.insert(tk.END, f"\n--- Full Original Summary Line ---\n{selected_summary}\n")

            if "raw_scapy_output" in details:
                self.packet_detail_text.insert(tk.END, "\n--- Raw Scapy Packet Structure (pkt.show()) ---\n")
                self.packet_detail_text.insert(tk.END, details["raw_scapy_output"])
        else:
            self.packet_detail_text.insert(tk.END, "Details not found for this packet.")
        self.packet_detail_text.config(state=tk.DISABLED)
        self.packet_detail_text.yview_moveto(0.0)

    def apply_filter(self):
        self.packet_listbox.delete(0, tk.END)
        self.displayed_packet_summaries.clear()
        filter_text = self.filter_var.get().lower()
        
        count = 0
        # Iterate through all_packets_details keys (which are the original summaries)
        # This ensures we filter from the complete set of captured packets.
        for summary_key in self.all_packets_details.keys():
            if not filter_text or filter_text in summary_key.lower():
                self.packet_listbox.insert(tk.END, summary_key)
                self.displayed_packet_summaries.append(summary_key) # Keep track of what's in listbox
                count +=1
        
        self.status_var.set(f"Filter applied: '{filter_text if filter_text else 'None'}'. Displaying {count} packets.")
        if self.packet_listbox.size() == 0 and filter_text:
            self.status_var.set(f"No packets match filter: '{filter_text}'")
        self.clear_details_pane()

    def clear_filter(self):
        self.filter_var.set("")
        self.apply_filter()
        self.status_var.set(f"Filter cleared. Displaying {self.packet_listbox.size()} packets from {len(self.all_packets_details)} total captured.")

    def on_closing(self):
        if self.is_sniffing:
            if messagebox.askokcancel("Quit", "Sniffing is active. Do you want to stop and quit?", parent=self.master):
                self.stop_sniffing() # This sets self.is_sniffing to False
                # Wait a moment for the sniffing thread to potentially finish its current packet and exit sniff()
                if self.sniffing_thread and self.sniffing_thread.is_alive():
                    self.sniffing_thread.join(timeout=0.5) 
                self.master.destroy()
            # else: user cancelled, do nothing
        else:
            self.master.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = ScapySnifferGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing) 
    root.mainloop()
