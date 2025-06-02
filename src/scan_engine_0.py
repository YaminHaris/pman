from scapy.all import sniff, wrcap
from threading.all import Thread
from datetime import datetime
from os import makedirs




class scanThread:
    def __init__(self, iface, bps_filter, execute):
        self.running = True
        self.iface = iface
        self.bps_filter = bps_filter
