from scapy.all import *
import time

TARGET = "10.145.74.155"  # your wlan0 IP
IFACE  = "wlan0"

def test_port_scan():
    print("\n🔍 [1/4] PORT SCAN — scanning 200 ports...")
    for port in range(1, 201):
        pkt = IP(dst=TARGET, ttl=64) / TCP(dport=port, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Port scan done — should trigger: port-scan rule")

def test_syn_flood():
    print("\n💥 [2/4] SYN FLOOD — sending 500 SYN packets...")
    pkts = [IP(dst=TARGET, ttl=64) / TCP(dport=80, flags="S") for _ in range(500)]
    for p in pkts:
        send(p, iface=IFACE, verbose=0)
    print("✅ SYN flood done — should trigger: syn-flood rule")

def test_ddos():
    print("\n🌊 [3/4] DDoS — sending 300 large packets...")
    for _ in range(300):
        pkt = IP(dst=TARGET, ttl=64) / TCP(dport=80) / Raw(load="X" * 1400)
        send(pkt, iface=IFACE, verbose=0)
    print("✅ DDoS done — should trigger: ddos rule")

def test_brute_force():
    print("\n🔑 [4/4] BRUTE FORCE SSH — hammering port 22...")
    for _ in range(100):
        pkt = IP(dst=TARGET, ttl=64) / TCP(dport=22, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Brute force done — should trigger: brute-force rule")

def test_null_scan():
    print("\n👻 [BONUS] NULL SCAN — sending null flag packets...")
    for port in range(1, 20):
        pkt = IP(dst=TARGET, ttl=64) / TCP(dport=port, flags=0)
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Null scan done — should trigger: null-scan rule")

def test_xmas_scan():
    print("\n🎄 [BONUS] XMAS SCAN — sending XMAS flag packets...")
    for port in range(1, 20):
        pkt = IP(dst=TARGET, ttl=64) / TCP(dport=port, flags="FPU")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ XMAS scan done — should trigger: xmas-scan rule")

def test_ghost_ttl():
    print("\n☠️  [BONUS] GHOST TTL — sending spoofed low-TTL packets...")
    for _ in range(20):
        pkt = IP(dst=TARGET, ttl=3) / TCP(dport=8080, flags="S")
        send(pkt, iface=IFACE, verbose=0)
    print("✅ Ghost TTL done — should trigger: ghost-ttl rule")

if __name__ == "__main__":
    print("=" * 50)
    print("  NeuralGuard Attack Simulator — Full Suite")
    print("=" * 50)
    print(f"  Target: {TARGET}")
    print(f"  Interface: {IFACE}")
    print("=" * 50)

    test_port_scan();   time.sleep(2)
    test_syn_flood();   time.sleep(2)
    test_ddos();        time.sleep(2)
    test_brute_force(); time.sleep(2)
    test_null_scan();   time.sleep(2)
    test_xmas_scan();   time.sleep(2)
    test_ghost_ttl();   time.sleep(2)

    print("\n" + "=" * 50)
    print("  ✅ ALL SIMULATIONS COMPLETE")
    print("  Check dashboard → http://localhost:5000")
    print("  Check iptables  → sudo iptables -L INPUT -n")
    print("=" * 50)
