from scapy.all import sniff, wrpcap
import threading
from datetime import datetime

now = datetime.now()
dt_string = now.strftime("%d-%m-%Y_%H:%M:%S")
print("date and time =", dt_string)
 

RUNNING  = True


def scan_(INTERFACE, FILTER, EXECUTE):
    
    name = f"{dt_string}_pman.pcap"
    wrpcap(name, "")
    while RUNNING:
        
        PKT = sniff(
            iface=INTERFACE,
            count=1,
            timeout=None,
            filter=FILTER,
            prn=EXECUTE,
            store=1
            )
        wrpcap(name, PKT, append=True)

def start_instance(functionToThread, args):
    THREAD = threading.Thread(target=functionToThread, args=args)
    THREAD.start()

# Example usage
#start_instance(scan_, ("wlp3s0", "tcp", lambda pkt: print(pkt.summary())))

