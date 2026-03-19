from scapy.all import *
import time

TARGET = "10.145.74.155"   # your machine (destination)
IFACE  = "wlan0"

# Fake external attacker IPs — NOT private ranges
ATTACKER1 = "45.33.32.156"    # fake external IP 1
ATTACKER2 = "198.20.69.74"    # fake external IP 2
ATTACKER3 = "23.92.127.201"   # fake external IP 3

def test_port_scan():
    print("\n🔍 [1/6] PORT SCAN — scanning 200 ports from fake external IP...")
    for port in range(1, 201):
        pkt = IP(src=ATTACKER1, dst=TARGET, ttl=64) / TCP(dport=port, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Port scan done — rule: port-scan")

def test_syn_flood():
    print("\n💥 [2/6] SYN FLOOD — 600 SYN packets...")
    for _ in range(600):
        pkt = IP(src=ATTACKER2, dst=TARGET, ttl=64) / TCP(dport=8888, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ SYN flood done — rule: syn-flood")

def test_ddos():
    print("\n🌊 [3/6] DDoS — large volume packets...")
    for _ in range(400):
        pkt = IP(src=ATTACKER3, dst=TARGET, ttl=64) / TCP(dport=80) / Raw(load="X"*1400)
        send(pkt, iface=IFACE, verbose=0)
    print("✅ DDoS done — rule: ddos")

def test_brute_force():
    print("\n🔑 [4/6] BRUTE FORCE SSH — 80 packets to port 22...")
    for _ in range(80):
        pkt = IP(src=ATTACKER1, dst=TARGET, ttl=64) / TCP(dport=22, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Brute force done — rule: brute-force:port22")

def test_null_scan():
    print("\n👻 [5/6] NULL SCAN — null flags across 20 ports...")
    for port in range(1, 21):
        pkt = IP(src=ATTACKER2, dst=TARGET, ttl=64) / TCP(dport=port, flags=0)
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Null scan done — rule: null-scan")

def test_xmas_scan():
    print("\n🎄 [6/6] XMAS SCAN — FIN+PSH+URG flags...")
    for port in range(1, 21):
        pkt = IP(src=ATTACKER3, dst=TARGET, ttl=64) / TCP(dport=port, flags="FPU")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ XMAS scan done — rule: xmas-scan")

def test_ghost_ttl():
    print("\n☠️  [BONUS] GHOST TTL — spoofed low TTL packets...")
    for _ in range(20):
        pkt = IP(src=ATTACKER1, dst=TARGET, ttl=3) / TCP(dport=8080, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Ghost TTL done — rule: ghost-ttl")

if __name__ == "__main__":
    print("=" * 55)
    print("  NeuralGuard Attack Simulator — Full Suite v2")
    print("=" * 55)
    print(f"  Target    : {TARGET}")
    print(f"  Interface : {IFACE}")
    print(f"  Attackers : {ATTACKER1}, {ATTACKER2}, {ATTACKER3}")
    print("=" * 55)

    test_port_scan();   time.sleep(3)
    test_syn_flood();   time.sleep(3)
    test_ddos();        time.sleep(3)
    test_brute_force(); time.sleep(3)
    test_null_scan();   time.sleep(3)
    test_xmas_scan();   time.sleep(3)
    test_ghost_ttl();   time.sleep(2)

    print("\n" + "=" * 55)
    print("  ✅ ALL SIMULATIONS COMPLETE")
    print("  → Dashboard : http://localhost:5000")
    print("  → Verify    : sudo iptables -L INPUT -n")
    print("=" * 55)
