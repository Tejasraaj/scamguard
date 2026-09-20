import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the labeled dataset
df = pd.read_csv("data/url_training_data.csv")

X = df.drop(columns=["label"])
y = df["label"]

# Split into train/test (80/20), stratified so class balance is preserved
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train a Random Forest
model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)

print("=== Classification Report ===")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Malicious"]))

print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

print("=== Feature Importances ===")
for name, importance in zip(X.columns, model.feature_importances_):
    print(f"{name}: {importance:.3f}")

# Save the trained model for later use in the API
joblib.dump(model, "app/url_model.pkl")
print("\nModel saved to app/url_model.pkl")