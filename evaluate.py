import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, precision_score,
                             recall_score, f1_score)
import os

# ── 1. Load ──────────────────────────────────────────────────────────────────
print("Loading model and test data...")
X_test  = joblib.load('../models/X_test.pkl')
y_test  = joblib.load('../models/y_test.pkl')
le      = joblib.load('../models/label_encoder.pkl')
rf      = joblib.load('../models/random_forest.pkl')
dt      = joblib.load('../models/decision_tree.pkl')
classes = le.classes_

os.makedirs('../models/plots', exist_ok=True)

# ── 2. Predictions ───────────────────────────────────────────────────────────
rf_preds = rf.predict(X_test)
dt_preds = dt.predict(X_test)

# ── 3. Print full metrics ────────────────────────────────────────────────────
for name, preds in [('Random Forest', rf_preds), ('Decision Tree', dt_preds)]:
    print(f"\n{'='*50}")
    print(f" {name}")
    print(f"{'='*50}")
    print(f"  Accuracy : {accuracy_score(y_test, preds):.4f}")
    print(f"  Precision: {precision_score(y_test, preds, average='weighted'):.4f}")
    print(f"  Recall   : {recall_score(y_test, preds, average='weighted'):.4f}")
    print(f"  F1-Score : {f1_score(y_test, preds, average='weighted'):.4f}")
    print(f"\n{classification_report(y_test, preds, target_names=classes)}")

# ── 4. Confusion matrices ────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(18, 7))
for ax, preds, title in zip(axes,
                             [rf_preds, dt_preds],
                             ['Random Forest', 'Decision Tree']):
    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_title(f'{title} — Confusion Matrix', fontsize=13)
    ax.set_xlabel('Predicted Label')
    ax.set_ylabel('True Label')
    ax.tick_params(axis='x', rotation=45)
plt.tight_layout()
plt.savefig('../models/plots/confusion_matrices.png', dpi=150)
plt.show()

# ── 5. Model comparison bar chart ────────────────────────────────────────────
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
rf_scores = [
    accuracy_score(y_test, rf_preds),
    precision_score(y_test, rf_preds, average='weighted'),
    recall_score(y_test, rf_preds, average='weighted'),
    f1_score(y_test, rf_preds, average='weighted')
]
dt_scores = [
    accuracy_score(y_test, dt_preds),
    precision_score(y_test, dt_preds, average='weighted'),
    recall_score(y_test, dt_preds, average='weighted'),
    f1_score(y_test, dt_preds, average='weighted')
]

x = np.arange(len(metrics))
width = 0.35
fig, ax = plt.subplots(figsize=(10, 6))
bars1 = ax.bar(x - width/2, rf_scores, width, label='Random Forest', color='steelblue')
bars2 = ax.bar(x + width/2, dt_scores, width, label='Decision Tree', color='lightcoral')
ax.set_ylim(0.99, 1.001)
ax.set_ylabel('Score')
ax.set_title('Model Performance Comparison')
ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.legend()
ax.bar_label(bars1, fmt='%.4f', padding=2, fontsize=9)
ax.bar_label(bars2, fmt='%.4f', padding=2, fontsize=9)
plt.tight_layout()
plt.savefig('../models/plots/model_comparison.png', dpi=150)
plt.show()

# ── 6. Feature importance (Random Forest) ────────────────────────────────────
feature_names = joblib.load('../models/feature_names.pkl')
importances   = rf.feature_importances_
top_n = 15
indices = np.argsort(importances)[::-1][:top_n]

fig, ax = plt.subplots(figsize=(10, 6))
ax.barh(range(top_n), importances[indices][::-1], color='steelblue')
ax.set_yticks(range(top_n))
ax.set_yticklabels([feature_names[i] for i in indices][::-1])
ax.set_xlabel('Feature Importance Score')
ax.set_title('Top 15 Most Important Features (Random Forest)')
plt.tight_layout()
plt.savefig('../models/plots/feature_importance.png', dpi=150)
plt.show()

print("\nAll plots saved to /models/plots/")
print("Evaluation complete!")