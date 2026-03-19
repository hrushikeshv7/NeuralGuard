from scapy.all import *
import time

TARGET = "10.145.74.155"
IFACE  = "wlan0"

print("🔴 Simulating PORT SCAN...")
for port in range(1, 200):
    pkt = IP(dst=TARGET, ttl=30) / TCP(dport=port, flags="S", sport=RandShort())
    send(pkt, iface=IFACE, verbose=False)
    if port % 50 == 0:
        print(f"   Scanned {port} ports...")
time.sleep(2)

print("🔴 Simulating DDoS FLOOD...")
pkts = [IP(dst=TARGET, ttl=10) / TCP(dport=80, flags="S", sport=RandShort())
        for _ in range(300)]
for p in pkts:
    send(p, iface=IFACE, verbose=False)
time.sleep(2)

print("🔴 Simulating BRUTE FORCE SSH...")
for i in range(100):
    pkt = IP(dst=TARGET, ttl=60) / TCP(dport=22, flags="S", sport=RandShort())
    send(pkt, iface=IFACE, verbose=False)
time.sleep(1)

print("✅ Attack simulation done! Check dashboard now.")
