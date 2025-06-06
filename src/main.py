import tkinter as tk
from tkinter import ttk
from scanner_frame import ScannerFrame  # Import the scanner
from scanner_engine_0 import ScannerEngine

# Placeholder frames
class BuilderFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        ttk.Label(self, text="Builder section coming soon!").pack()

class AnalyserFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        ttk.Label(self, text="Analyser section coming soon!").pack()

class ScapyGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scapy GUI Tool")
        self.state('normal')  # Use 'normal' for Linux compatibility
        self.attributes('-fullscreen', True)  # Fullscreen
        self.resizable(True, True)

        self.navbar = ttk.Frame(self)
        self.navbar.pack(side=tk.TOP, fill=tk.X)

        # Navigation Buttons
        ttk.Button(self.navbar, text="Scanner", command=self.show_scanner).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.navbar, text="Builder", command=self.show_builder).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.navbar, text="Analyser", command=self.show_analyser).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(self.navbar, text="Exit", command=self.quit).pack(side=tk.RIGHT, padx=5, pady=5)

        self.content_frame = tk.Frame(self)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        # Frames for each section
        self.scanner_frame = ScannerFrame(self.content_frame, self.start_scan, self.stop_scan)
        self.builder_frame = BuilderFrame(self.content_frame)
        self.analyser_frame = AnalyserFrame(self.content_frame)

        self.current_frame = None
        self.show_scanner()  # Show Scanner by default

    def switch_frame(self, frame):
        if self.current_frame:
            self.current_frame.pack_forget()
        frame.pack(fill=tk.BOTH, expand=True)
        self.current_frame = frame

    def show_scanner(self):
        self.switch_frame(self.scanner_frame)

    def show_builder(self):
        self.switch_frame(self.builder_frame)

    def show_analyser(self):
        self.switch_frame(self.analyser_frame)

    def start_scan(self, config):
        print("[START SCAN]")
        print(config)
        self.scanner_frame.append_output("Starting scan with configuration:\n" + str(config))
        # TODO: start scapy sniffing here
 
    def stop_scan(self):
        print("[STOP SCAN]")
        self.scanner_frame.append_output("Scan stopped.")
        # TODO: stop scapy sniffing here
            
if __name__ == "__main__":
    app = ScapyGUI()
    app.mainloop()

