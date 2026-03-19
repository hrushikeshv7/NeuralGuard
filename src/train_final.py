import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib, warnings
warnings.filterwarnings("ignore")

COLS = ["protocol","src_port","dst_port","pkt_size",
        "ttl","tcp_flags","is_tcp","is_udp","is_icmp",
        "flow_count","byte_rate"]

np.random.seed(42)
n = 5000

benign = {
    "protocol":   np.random.choice([6,17], n),
    "src_port":   np.random.randint(1024,65535,n),
    "dst_port":   np.random.choice([80,443,53,123],n),
    "pkt_size":   np.random.randint(60,1500,n),
    "ttl":        np.random.randint(55,128,n),
    "tcp_flags":  np.random.choice([16,18,24],n),
    "is_tcp":     np.ones(n), "is_udp": np.zeros(n), "is_icmp": np.zeros(n),
    "flow_count": np.random.randint(1,20,n),
    "byte_rate":  np.random.uniform(100,80000,n),
    "label": ["BENIGN"]*n
}

portscan = {
    "protocol":   np.full(1500,6),
    "src_port":   np.random.randint(1024,65535,1500),
    "dst_port":   np.random.randint(1,9000,1500),
    "pkt_size":   np.random.randint(40,60,1500),
    "ttl":        np.random.randint(20,50,1500),
    "tcp_flags":  np.full(1500,2),
    "is_tcp":     np.ones(1500), "is_udp": np.zeros(1500), "is_icmp": np.zeros(1500),
    "flow_count": np.random.randint(100,1000,1500),
    "byte_rate":  np.random.uniform(50000,500000,1500),
    "label": ["MALICIOUS"]*1500
}

ddos = {
    "protocol":   np.random.choice([6,17],1500),
    "src_port":   np.random.randint(1,1024,1500),
    "dst_port":   np.random.choice([80,443],1500),
    "pkt_size":   np.random.randint(900,1500,1500),
    "ttl":        np.random.randint(5,35,1500),
    "tcp_flags":  np.random.choice([2,4],1500),
    "is_tcp":     np.ones(1500), "is_udp": np.zeros(1500), "is_icmp": np.zeros(1500),
    "flow_count": np.random.randint(500,5000,1500),
    "byte_rate":  np.random.uniform(500000,5000000,1500),
    "label": ["MALICIOUS"]*1500
}

bruteforce = {
    "protocol":   np.full(1000,6),
    "src_port":   np.random.randint(1024,65535,1000),
    "dst_port":   np.random.choice([22,3389,21],1000),
    "pkt_size":   np.random.randint(60,200,1000),
    "ttl":        np.random.randint(45,80,1000),
    "tcp_flags":  np.random.choice([2,18],1000),
    "is_tcp":     np.ones(1000), "is_udp": np.zeros(1000), "is_icmp": np.zeros(1000),
    "flow_count": np.random.randint(50,300,1000),
    "byte_rate":  np.random.uniform(5000,50000,1000),
    "label": ["MALICIOUS"]*1000
}

df = pd.concat([pd.DataFrame(d) for d in [benign,portscan,ddos,bruteforce]])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
print(f"Dataset: {df.shape}\n{df['label'].value_counts()}")

X = df[COLS]
le = LabelEncoder()
y = le.fit_transform(df["label"])

X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
clf = RandomForestClassifier(n_estimators=200, max_depth=15, n_jobs=-1, random_state=42, verbose=0)
clf.fit(X_tr, y_tr)

print(classification_report(y_te, clf.predict(X_te), target_names=le.classes_))
print(f"✅ Accuracy: {clf.score(X_te,y_te)*100:.2f}%")

joblib.dump(clf, "models/classifier.pkl")
joblib.dump(le,  "models/label_encoder.pkl")
joblib.dump(COLS,"models/feature_cols.pkl")
print("💾 Model + feature list saved!")

