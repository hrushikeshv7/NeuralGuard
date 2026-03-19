import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import os

print("📂 Loading dataset...")
df = pd.read_csv("data/processed/training_data.csv")
print(f"Dataset shape: {df.shape}")
print(df['label'].value_counts())

# ── Prepare features ──
X = df.drop('label', axis=1)
y = df['label']

le = LabelEncoder()
y_encoded = le.fit_transform(y)

# ── Split data ──
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"\n🔀 Train: {X_train.shape} | Test: {X_test.shape}")

# ── Train Random Forest ──
print("\n🌲 Training Random Forest Classifier...")
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    n_jobs=-1,
    random_state=42,
    verbose=1
)
clf.fit(X_train, y_train)

# ── Evaluate ──
print("\n📊 Evaluating model...")
y_pred = clf.predict(X_test)
print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))

accuracy = clf.score(X_test, y_test)
print(f"\n✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")

# ── Save model ──
os.makedirs("models", exist_ok=True)
joblib.dump(clf, "models/classifier.pkl")
joblib.dump(le,  "models/label_encoder.pkl")
print("💾 Model saved to models/classifier.pkl")

# ── Feature importance ──
print("\n🔍 Top 5 Most Important Features:")
importances = pd.Series(clf.feature_importances_, index=X.columns)
print(importances.sort_values(ascending=False).head(5))
