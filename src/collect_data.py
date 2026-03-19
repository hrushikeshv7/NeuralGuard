from scapy.all import sniff, IP
from features import extract_features
import pandas as pd
import os

captured = []

def packet_handler(pkt):
    if IP in pkt:
        f = extract_features(pkt)
        captured.append(f)
        print(f"[{f['timestamp']}] {f['src_ip']} → {f['dst_ip']} | size={f['pkt_size']} ttl={f['ttl']}")

print("📡 Collecting 200 packets for dataset...\n")
sniff(iface="wlan0", prn=packet_handler, store=False, count=200)

# Save to CSV
os.makedirs("data/processed", exist_ok=True)
df = pd.DataFrame(captured)
df.to_csv("data/processed/traffic.csv", index=False)
print(f"\n✅ Saved {len(df)} rows to data/processed/traffic.csv")
print(df.head())
