import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)

# Load the SMS Spam Collection (tab separated: label, message)
df = pd.read_csv("data/raw/SMSSpamCollection", sep="\t",
                 header=None, names=["label", "message"])
df["target"] = (df["label"] == "spam").astype(int)
print("Rows:", len(df))
print(df["label"].value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    df["message"], df["target"], test_size=0.2, random_state=42,
    stratify=df["target"]
)

# TF-IDF turns text into numbers, Logistic Regression classifies them
model = Pipeline([
    ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2)),
    ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
])
model.fit(X_train, y_train)

pred = model.predict(X_test)
print("\n=== Message model: test set results ===")
print("Accuracy :", round(accuracy_score(y_test, pred) * 100, 2))
print("Precision:", round(precision_score(y_test, pred) * 100, 2))
print("Recall   :", round(recall_score(y_test, pred) * 100, 2))
print("F1       :", round(f1_score(y_test, pred) * 100, 2))
print("Confusion matrix [[TN FP] [FN TP]]:")
print(confusion_matrix(y_test, pred))

joblib.dump(model, "app/message_model.pkl")
print("\nSaved to app/message_model.pkl")

# Try it on the six test messages from earlier
samples = [
    "URGENT! Your account will be suspended. Verify your OTP immediately to claim your prize!",
    "Dear customer, your SBI account is blocked. Update your card number now at http://sbi-kyc-update.xyz/login or your account will expire.",
    "Congratulations! You are the lucky winner of the lottery. Claim your free gift now: www.lucky-gift.top",
    "Your package could not be delivered. Pay a small fee at http://track-parcel-india.com/pay",
    "Hi, are we still meeting for lunch at 1 pm tomorrow?",
    "Hope you enjoy shopping this weekend",
]
print("\n=== Spam probability on sample messages ===")
for text, p in zip(samples, model.predict_proba(samples)[:, 1]):
    print(f"{p * 100:5.1f}%  {text[:70]}")
