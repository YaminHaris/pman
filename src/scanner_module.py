import tkinter as tk
from tkinter import ttk
import psutil

def get_network_interfaces():
    return list(psutil.net_if_addrs().keys())

def show_scanner_ui(parent):
    for widget in parent.winfo_children():
        widget.destroy()

    parent.configure(bg="#1e1e1e")
    parent.grid_rowconfigure(2, weight=1)
    parent.grid_columnconfigure(0, weight=1)

    # ================= TOP BUTTONS ====================
    top_button_frame = tk.Frame(parent, bg="#1e1e1e")
    top_button_frame.grid(row=0, column=0, pady=(10, 0), sticky="ew")
    top_button_frame.columnconfigure((0, 1), weight=1)

    style_btn = {"font": ("Consolas", 11), "width": 14, "height": 1, "bd": 0, "relief": "flat"}

    btn_start = tk.Button(top_button_frame, text="▶ Start Scan", bg="#2e8b57", fg="white", activebackground="#3cb371", **style_btn)
    btn_stop = tk.Button(top_button_frame, text="■ Stop Scan", bg="#a52a2a", fg="white", activebackground="#cd5c5c", **style_btn)

    btn_start.grid(row=0, column=0, padx=10)
    btn_stop.grid(row=0, column=1, padx=10)

    # =============== CENTER INPUT CONTROLS ====================
    form_frame = tk.Frame(parent, bg="#1e1e1e")
    form_frame.grid(row=1, column=0, pady=15)

    def add_field(row, label_text, widget):
        tk.Label(form_frame, text=label_text, font=("Consolas", 11), fg="#d0d0d0", bg="#1e1e1e").grid(row=row, column=0, sticky="e", padx=10, pady=4)
        widget.grid(row=row, column=1, padx=10, pady=4)

    interfaces = get_network_interfaces()
    selected_interface = tk.StringVar(value=interfaces[0] if interfaces else "lo")
    interface_dropdown = ttk.Combobox(form_frame, textvariable=selected_interface, values=interfaces, state="readonly", width=24)

    ip_entry = tk.Entry(form_frame, width=26, font=("Consolas", 10))
    ip_entry.insert(0, "192.168.1.1")

    port_entry = tk.Entry(form_frame, width=26, font=("Consolas", 10))
    port_entry.insert(0, "1-1000")

    selected_filter = tk.StringVar(value="ALL")
    filter_dropdown = ttk.Combobox(form_frame, textvariable=selected_filter, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly", width=24)

    scan_type = tk.StringVar(value="SYN")
    scan_dropdown = ttk.Combobox(form_frame, textvariable=scan_type, values=["SYN", "ACK", "FIN", "NULL", "XMAS"], state="readonly", width=24)

    add_field(0, "Interface:", interface_dropdown)
    add_field(1, "Target IP/Subnet:", ip_entry)
    add_field(2, "Port Range:", port_entry)
    add_field(3, "Packet Filter:", filter_dropdown)
    add_field(4, "Scan Type:", scan_dropdown)

    # ============== PACKET DISPLAY BOX =================
    text_frame = tk.Frame(parent, bg="#1e1e1e")
    text_frame.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 10))

    packet_display = tk.Text(
        text_frame, height=18, font=("Consolas", 10), bg="#101010", fg="#00ff66",
        insertbackground="white", borderwidth=0, highlightthickness=1, highlightbackground="#3a3a3a"
    )
    packet_display.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(text_frame, command=packet_display.yview, bg="#1e1e1e")
    scrollbar.pack(side="right", fill="y")
    packet_display.config(yscrollcommand=scrollbar.set)

    # ========== Hookup with scan logic ==========
    def start_scan():
        iface = selected_interface.get()
        target = ip_entry.get()
        ports = port_entry.get()
        proto = selected_filter.get()
        mode = scan_type.get()

        packet_display.insert("end", f"[+] Starting scan on {iface}\nTarget: {target} | Ports: {ports} | Filter: {proto} | Type: {mode}\n\n")
        packet_display.see("end")

        # >>> CALL scan_engine.start_scan() here <<<

    def stop_scan():
        packet_display.insert("end", "[!] Scan stopped.\n\n")
        packet_display.see("end")

        # >>> CALL scan_engine.stop_scan() here <<<

    btn_start.config(command=start_scan)
    btn_stop.config(command=stop_scan)

