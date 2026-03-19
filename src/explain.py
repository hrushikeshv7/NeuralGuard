import joblib
import pandas as pd
import warnings
warnings.filterwarnings("ignore")

clf = joblib.load("models/classifier.pkl")
le  = joblib.load("models/label_encoder.pkl")
clf.verbose = 0

feature_cols = ['protocol','src_port','dst_port','pkt_size',
                'ttl','tcp_flags','is_tcp','is_udp','is_icmp',
                'duration','byte_rate']

test_packets = {
    "Normal Browsing": [6, 52341, 443, 66, 64, 18, 1, 0, 0, 0.5, 5000],
    "Port Scan":       [6, 44231, 445, 44, 30,  2, 1, 0, 0, 0.001, 300000],
    "DDoS Attack":     [6, 80,     80, 1400, 15, 2, 1, 0, 0, 0.00001, 3000000],
    "Brute Force SSH": [6, 54321,  22, 100, 60,  2, 1, 0, 0, 0.1, 15000],
}

print("\n" + "="*50)
print("   🔍 AI FIREWALL — PACKET ANALYSIS REPORT")
print("="*50)

for name, values in test_packets.items():
    pkt   = pd.DataFrame([values], columns=feature_cols)
    pred  = clf.predict(pkt)[0]
    proba = clf.predict_proba(pkt)[0]
    label = le.inverse_transform([pred])[0]
    conf  = proba.max() * 100

    icon = "🔴 MALICIOUS" if label == "MALICIOUS" else "🟢 BENIGN"

    print(f"\nPacket  : {name}")
    print(f"Result  : {icon}")
    print(f"Confidence : {conf:.1f}%")
    print(f"Reason  : port={values[2]} | ttl={values[4]} | flags={values[5]} | rate={values[10]}")
    print("-"*50)
