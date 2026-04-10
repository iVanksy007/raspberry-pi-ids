import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import os

# ── 1. Load preprocessed data ────────────────────────────────────────────────
print("Loading preprocessed data...")
X_train = joblib.load('../models/X_train.pkl')
X_test  = joblib.load('../models/X_test.pkl')
y_train = joblib.load('../models/y_train.pkl')
y_test  = joblib.load('../models/y_test.pkl')
le      = joblib.load('../models/label_encoder.pkl')
classes = le.classes_

os.makedirs('../models', exist_ok=True)

# ── 2. Train Decision Tree ───────────────────────────────────────────────────
print("\nTraining Decision Tree...")
dt = DecisionTreeClassifier(max_depth=20, random_state=42)
dt.fit(X_train, y_train)
dt_preds = dt.predict(X_test)
dt_acc = accuracy_score(y_test, dt_preds)
print(f"Decision Tree Accuracy: {dt_acc:.4f}")
joblib.dump(dt, '../models/decision_tree.pkl')

# ── 3. Train Random Forest ───────────────────────────────────────────────────
print("\nTraining Random Forest (this takes a few minutes)...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
rf_preds = rf.predict(X_test)
rf_acc = accuracy_score(y_test, rf_preds)
print(f"Random Forest Accuracy: {rf_acc:.4f}")
joblib.dump(rf, '../models/random_forest.pkl')

# ── 4. Print classification reports ─────────────────────────────────────────
print("\n── Decision Tree Report ──────────────────────────────")
print(classification_report(y_test, dt_preds, target_names=classes))

print("\n── Random Forest Report ──────────────────────────────")
print(classification_report(y_test, rf_preds, target_names=classes))

# ── 5. Plot confusion matrices ───────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

for ax, preds, title in zip(axes,
                             [dt_preds, rf_preds],
                             ['Decision Tree', 'Random Forest']):
    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_title(f'{title} — Confusion Matrix')
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('../models/confusion_matrices.png', dpi=150)
plt.show()
print("\nConfusion matrix saved to /models folder.")
print("\nTraining complete!")