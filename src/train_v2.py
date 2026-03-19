import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import warnings
warnings.filterwarnings("ignore")

np.random.seed(42)
n = 5000

# BENIGN — normal browsing traffic
benign = pd.DataFrame({
    "protocol":   np.random.choice([6, 17], n),
    "src_port":   np.random.randint(1024, 65535, n),
    "dst_port":   np.random.choice([80, 443, 53, 123], n),
    "pkt_size":   np.random.randint(60, 1500, n),
    "ttl":        np.random.randint(55, 128, n),
    "tcp_flags":  np.random.choice([16, 18, 24], n),  # ACK, SYN-ACK, PSH-ACK
    "is_tcp":     1, "is_udp": 0, "is_icmp": 0,
    "flow_count": np.random.randint(1, 20, n),         # few packets per flow
    "byte_rate":  np.random.uniform(100, 80000, n),    # normal rate
    "label": "BENIGN"
})

# PORT SCAN — many ports, tiny packets, only SYN
portscan = pd.DataFrame({
    "protocol":   6,
    "src_port":   np.random.randint(1024, 65535, 1500),
    "dst_port":   np.random.randint(1, 9000, 1500),    # scanning all ports
    "pkt_size":   np.random.randint(40, 60, 1500),     # tiny
    "ttl":        np.random.randint(20, 50, 1500),     # low TTL
    "tcp_flags":  2,                                    # only SYN
    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
    "flow_count": np.random.randint(100, 1000, 1500),  # many packets
    "byte_rate":  np.random.uniform(50000, 500000, 1500),
    "label": "MALICIOUS"
})

# DDOS — huge byte rate, low TTL
ddos = pd.DataFrame({
    "protocol":   np.random.choice([6, 17], 1500),
    "src_port":   np.random.randint(1, 1024, 1500),
    "dst_port":   np.random.choice([80, 443], 1500),
    "pkt_size":   np.random.randint(900, 1500, 1500),
    "ttl":        np.random.randint(5, 35, 1500),
    "tcp_flags":  np.random.choice([2, 4], 1500),
    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
    "flow_count": np.random.randint(500, 5000, 1500),  # massive count
    "byte_rate":  np.random.uniform(500000, 5000000, 1500), # massive rate
    "label": "MALICIOUS"
})

# BRUTE FORCE — port 22/3389, medium rate, repeated
bruteforce = pd.DataFrame({
    "protocol":   6,
    "src_port":   np.random.randint(1024, 65535, 1000),
    "dst_port":   np.random.choice([22, 3389, 21, 23], 1000),
    "pkt_size":   np.random.randint(60, 200, 1000),
    "ttl":        np.random.randint(45, 80, 1000),
    "tcp_flags":  np.random.choice([2, 18], 1000),
    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
    "flow_count": np.random.randint(50, 300, 1000),
    "byte_rate":  np.random.uniform(5000, 50000, 1000),
    "label": "MALICIOUS"
})

df = pd.concat([benign, portscan, ddos, bruteforce], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Dataset: {df.shape}")
print(df["label"].value_counts())

X = df.drop("label", axis=1)
y = df["label"]
le = LabelEncoder()
y_enc = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

clf = RandomForestClassifier(
    n_estimators=200, max_depth=15,
    n_jobs=-1, random_state=42, verbose=0)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=le.classes_))
print(f"✅ Accuracy: {clf.score(X_test, y_test)*100:.2f}%")

joblib.dump(clf, "models/classifier.pkl")
joblib.dump(le,  "models/label_encoder.pkl")
print("💾 Model v2 saved!")
