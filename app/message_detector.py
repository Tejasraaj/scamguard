import re
import joblib

try:
    message_model = joblib.load("app/message_model.pkl")
except Exception as e:
    print("Message model not loaded, using rules only:", e)
    message_model = None

URGENCY_WORDS = ["urgent", "immediately", "act now", "suspended", "verify now",
                 "expire", "expires", "expired", "limited time"]
CREDENTIAL_WORDS = ["password", "otp", "pin", "cvv", "verify your account",
                    "bank details", "card number"]
PRIZE_WORDS = ["congratulations", "winner", "lottery", "prize", "claim your", "free gift"]


def count_hits(text, words):
    return sum(1 for w in words if re.search(r"\b" + re.escape(w) + r"\b", text))


def extract_message_features(message):
    text = message.lower()
    return {
        "length": len(message),
        "has_url": bool(re.search(r"https?://|www\.", text)),
        "urgency_hits": count_hits(text, URGENCY_WORDS),
        "credential_hits": count_hits(text, CREDENTIAL_WORDS),
        "prize_hits": count_hits(text, PRIZE_WORDS),
        "exclaim_count": message.count("!"),
        "caps_ratio": sum(1 for c in message if c.isupper()) / max(len(message), 1),
    }


def rule_analysis(features):
    risk = 0
    reasons = []
    if features["urgency_hits"] > 0:
        risk += 25
        reasons.append("Contains urgency or threatening language")
    if features["credential_hits"] > 0:
        risk += 35
        reasons.append("Requests sensitive credentials or financial info")
    if features["prize_hits"] > 0:
        risk += 25
        reasons.append("Contains prize or reward scam language")
    if features["has_url"]:
        risk += 10
        reasons.append("Contains a link")
    if features["exclaim_count"] >= 2:
        risk += 5
        reasons.append("Excessive exclamation marks")
    return min(risk, 100), reasons


def analyze_message(message):
    features = extract_message_features(message)
    rule_score, reasons = rule_analysis(features)

    score = rule_score
    source = "rules"
    if message_model is not None:
        try:
            prob = float(message_model.predict_proba([message])[0][1])
            score = round(prob * 100)
            source = "ml"
        except Exception as e:
            print("Message model failed, using rules:", e)

    verdict = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW RISK"

    if not reasons:
        if score >= 30:
            reasons = ["No specific keyword flags, but the language pattern resembles known scam messages"]
        else:
            reasons = ["No significant risk indicators found"]

    return {
        "features": features,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "scored_by": source,
    }
