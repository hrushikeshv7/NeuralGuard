from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def packet_handler(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        src  = pkt[IP].src
        dst  = pkt[IP].dst
        size = len(pkt)
        time = datetime.now().strftime("%H:%M:%S")
        print(f"[{time}] {proto}  {src} → {dst}  ({size} bytes)")

print("🔍 Sniffing packets... Press Ctrl+C to stop\n")
sniff(iface="wlan0", prn=packet_handler, store=False)
