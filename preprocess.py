import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

# ── 1. Load ────────────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv('../data/cicids2017.csv')
print(f"Original shape: {df.shape}")

# ── 2. Drop infinite values ─────────────────────────────────────────────────
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"After cleaning infinites: {df.shape}")

# ── 3. Balance the dataset ──────────────────────────────────────────────────
# Cap each class at 10,000 samples so no single class dominates
print("\nBalancing classes...")
MIN_SAMPLES = 1000
MAX_SAMPLES = 10000

balanced_dfs = []
for attack_type, group in df.groupby('Attack Type'):
    if len(group) >= MIN_SAMPLES:
        sampled = group.sample(n=min(len(group), MAX_SAMPLES), random_state=42)
        balanced_dfs.append(sampled)
        print(f"  {attack_type}: {len(sampled)} samples")

df_balanced = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"\nBalanced dataset shape: {df_balanced.shape}")

# ── 4. Separate features and labels ─────────────────────────────────────────
X = df_balanced.drop(columns=['Attack Type'])
y = df_balanced['Attack Type']

# ── 5. Encode labels ─────────────────────────────────────────────────────────
print("\nEncoding labels...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"Classes: {list(le.classes_)}")

# ── 6. Scale features ────────────────────────────────────────────────────────
print("\nScaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── 7. Train/test split ──────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"\nTraining samples: {X_train.shape[0]}")
print(f"Testing samples:  {X_test.shape[0]}")

# ── 8. Save everything ───────────────────────────────────────────────────────
os.makedirs('../models', exist_ok=True)

joblib.dump(X_train, '../models/X_train.pkl')
joblib.dump(X_test,  '../models/X_test.pkl')
joblib.dump(y_train, '../models/y_train.pkl')
joblib.dump(y_test,  '../models/y_test.pkl')
joblib.dump(scaler,  '../models/scaler.pkl')
joblib.dump(le,      '../models/label_encoder.pkl')
joblib.dump(list(X.columns), '../models/feature_names.pkl')

print("\nAll files saved to /models folder.")
print("Preprocessing complete!")