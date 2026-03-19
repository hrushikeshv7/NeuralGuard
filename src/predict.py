import warnings
warnings.filterwarnings("ignore")
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import subprocess
import os
import sys
sys.path.append(os.path.dirname(__file__))
from features import extract_features

# ── Load AI model ──
print("🤖 Loading AI model...")
clf = joblib.load("models/classifier.pkl")
le  = joblib.load("models/label_encoder.pkl")
clf.verbose = 0
print("✅ Model loaded!\n")

# ── Track stats ──
stats = {"total": 0, "benign": 0, "malicious": 0, "blocked": []}

def block_ip(ip):
    if ip not in stats["blocked"]:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                      capture_output=True)
        stats["blocked"].append(ip)
        print(f"🚫 BLOCKED: {ip}")

def predict_packet(pkt):
    if not IP in pkt:
        return

    # Extract features
    f = extract_features(pkt)
    feature_cols = ['protocol','src_port','dst_port','pkt_size',
                    'ttl','tcp_flags','is_tcp','is_udp','is_icmp',
                    'flow_count','byte_rate']

    # Build feature row (fill missing with 0)
    row = [f.get(col, 0) for col in feature_cols]
X = pd.DataFrame([row], columns=feature_cols)
    for col in feature_cols:
        if col == 'duration':
            row.append(0)
        elif col == 'byte_rate':
            row.append(f.get('pkt_size', 0) / 0.001)
        else:
            row.append(f.get(col, 0))

    # AI prediction

    feature_cols = ['protocol','src_port','dst_port','pkt_size',
                'ttl','tcp_flags','is_tcp','is_udp','is_icmp',
                'duration','byte_rate']
    X = pd.DataFrame([row], columns=feature_cols)
    pred = clf.predict(X)[0]
    label = le.inverse_transform([pred])[0]
    proba = clf.predict_proba(X)[0].max()

    stats["total"] += 1
    time = datetime.now().strftime("%H:%M:%S")

    if label == "MALICIOUS" and proba > 0.80:
        stats["malicious"] += 1
        src = pkt[IP].src
        print(f"[{time}] 👳‍✈🏢🏢 TOXIC  {src} → {pkt[IP].dst}  "
              f"confidence={proba:.2f}  size={len(pkt)}")
        block_ip(src)
    else:
        stats["benign"] += 1
        if stats["total"] % 20 == 0:  # print every 20 benign packets
            print(f"[{time}] ⁶🤷‍⁷ NICE  {pkt[IP].src} → {pkt[IP].dst}  "
                  f"confidence={proba:.2f}")

    # Print summary every 100 packets
    if stats["total"] % 100 == 0:
        print(f"\n📊 Stats — Total:{stats['total']}  "
              f"Benign:{stats['benign']}  "
              f"Malicious:{stats['malicious']}  "
              f"Blocked IPs:{len(stats['blocked'])}\n")

print("🔍 Watching live traffic... Press Ctrl+C to stop\n")
print(f"{'─'*65}")
try:
    sniff(iface="wlan0", prn=predict_packet, store=False)
except KeyboardInterrupt:
    print(f"\n{'─'*65}")
    print("🛑 Detection stopped.")
    print(f"📊 Final Stats:")
    print(f"   Total packets : {stats['total']}")
    print(f"   Benign        : {stats['benign']}")
    print(f"   Malicious     : {stats['malicious']}")
    print(f"   Blocked IPs   : {stats['blocked']}")
