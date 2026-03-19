import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

np.random.seed(42)
n = 15000

# ── Generate REALISTIC traffic patterns ──

# Normal traffic
normal = pd.DataFrame({
    'protocol':  np.random.choice([6, 17], n//2),       # TCP or UDP
    'src_port':  np.random.randint(1024, 65535, n//2),  # random high ports
    'dst_port':  np.random.choice([80,443,53,22], n//2),# common ports
    'pkt_size':  np.random.randint(40, 1500, n//2),     # normal size
    'ttl':       np.random.randint(55, 128, n//2),      # normal TTL
    'tcp_flags': np.random.choice([2, 18, 16], n//2),  # SYN, SYN-ACK, ACK
    'is_tcp':    1, 'is_udp': 0, 'is_icmp': 0,
    'duration':  np.random.uniform(0.001, 2.0, n//2),
    'byte_rate': np.random.uniform(100, 50000, n//2),
    'label': 'BENIGN'
})

# Port scan attack
portscan = pd.DataFrame({
    'protocol':  6,
    'src_port':  np.random.randint(1024, 65535, 2000),
    'dst_port':  np.random.randint(1, 9999, 2000),    # scanning ALL ports
    'pkt_size':  np.random.randint(40, 60, 2000),     # tiny packets
    'ttl':       np.random.randint(20, 50, 2000),     # low TTL
    'tcp_flags': 2,                                    # only SYN
    'is_tcp': 1, 'is_udp': 0, 'is_icmp': 0,
    'duration':  np.random.uniform(0.0001, 0.01, 2000),# very fast
    'byte_rate': np.random.uniform(50000, 500000, 2000),# high rate
    'label': 'MALICIOUS'
})

# DDoS attack
ddos = pd.DataFrame({
    'protocol':  np.random.choice([6, 17], 2000),
    'src_port':  np.random.randint(1, 1024, 2000),    # low ports
    'dst_port':  np.random.choice([80, 443], 2000),   # targeting web
    'pkt_size':  np.random.randint(1000, 1500, 2000), # large packets
    'ttl':       np.random.randint(10, 40, 2000),     # very low TTL
    'tcp_flags': np.random.choice([2, 4], 2000),      # SYN or RST flood
    'is_tcp': 1, 'is_udp': 0, 'is_icmp': 0,
    'duration':  np.random.uniform(0.00001, 0.001, 2000),
    'byte_rate': np.random.uniform(500000, 5000000, 2000),# massive
    'label': 'MALICIOUS'
})

# Brute force attack
bruteforce = pd.DataFrame({
    'protocol':  6,
    'src_port':  np.random.randint(1024, 65535, 1500),
    'dst_port':  np.random.choice([22, 3389, 21], 1500), # SSH/RDP/FTP
    'pkt_size':  np.random.randint(60, 200, 1500),
    'ttl':       np.random.randint(50, 80, 1500),
    'tcp_flags': np.random.choice([2, 18], 1500),
    'is_tcp': 1, 'is_udp': 0, 'is_icmp': 0,
    'duration':  np.random.uniform(0.01, 0.5, 1500),
    'byte_rate': np.random.uniform(1000, 20000, 1500),
    'label': 'MALICIOUS'
})

# ── Combine all ──
df = pd.concat([normal, portscan, ddos, bruteforce], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Dataset: {df.shape}")
print(df['label'].value_counts())

# ── Train ──
X = df.drop('label', axis=1)
y = df['label']
le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

clf = RandomForestClassifier(n_estimators=200, max_depth=15,
                              n_jobs=-1, random_state=42, verbose=0)
clf.fit(X_train, y_train)

print("\n--- Classification Report ---")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_enc[:len(y_test)],
      target_names=le.classes_))
acc = clf.score(X_test, y_test)
print(f"✅ Accuracy: {acc*100:.2f}%")

joblib.dump(clf, "models/classifier.pkl")
joblib.dump(le,  "models/label_encoder.pkl")
print("💾 Better model saved!")
