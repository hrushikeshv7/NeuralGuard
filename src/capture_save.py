from scapy.all import sniff, wrpcap

print("📦 Capturing 100 packets and saving to file...")
packets = sniff(iface="wlan0", count=100)
wrpcap("data/raw/capture.pcap", packets)
print("✅ Saved to data/raw/capture.pcap")
