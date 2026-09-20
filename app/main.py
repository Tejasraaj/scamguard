from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
from app.database import SessionLocal, URLAnalysis, MessageAnalysis
import joblib
import pandas as pd
import re

app = FastAPI(title="Scam Detection API")
url_model = joblib.load("app/url_model_v2.pkl")

class URLRequest(BaseModel):
    url: str

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return {
        "url_length": len(url),
        "https": parsed.scheme == "https",
        "subdomain_count": hostname.count("."),
        "has_ip": bool(ipv4_pattern.match(hostname.split(":")[0])),
        "hyphen_count": hostname.count("-"),
    }

def score_url(features: dict) -> dict:
    risk = 0
    reasons = []
    if not features["https"]:
        risk += 20
        reasons.append("Connection is not encrypted (no HTTPS)")
    if features["url_length"] > 75:
        risk += 15
        reasons.append("Unusually long URL")
    if features["subdomain_count"] > 3:
        risk += 20
        reasons.append("Excessive subdomains")
    if features["has_ip"]:
        risk += 30
        reasons.append("Domain is a raw IP address, not a name")
    if features["hyphen_count"] >= 3:
        risk += 15
        reasons.append("Domain contains many hyphens")

    verdict = "HIGH RISK" if risk >= 60 else "SUSPICIOUS" if risk >= 30 else "LOW RISK"
    return {"risk_score": min(risk, 100), "verdict": verdict, "reasons": reasons}

@app.post("/detect")
def detect(request: URLRequest):
    features = extract_url_features(request.url)

    feature_order = ["url_length", "https", "subdomain_count", "has_ip", "hyphen_count",
                      "digit_ratio", "path_length", "has_at_symbol", "brand_keyword_count"]

    if "://" in request.url:
        full_url = request.url
    else:
        full_url = "http://" + request.url

    parsed_full = urlparse(full_url)
    hostname = parsed_full.netloc.split(":")[0]
    path = parsed_full.path
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    brand_keywords = ["paypal", "amazon", "bank", "login", "secure", "verify", "account", "update", "confirm", "signin"]

    full_features = {
        **features,
        "digit_ratio": round(digit_ratio, 3),
        "path_length": len(path),
        "has_at_symbol": int("@" in request.url),
        "brand_keyword_count": sum(1 for kw in brand_keywords if kw in hostname.lower()),
    }

    X = pd.DataFrame([full_features])[feature_order]
    ml_probability = url_model.predict_proba(X)[0][1]
    ml_score = round(ml_probability * 100)

    rule_result = score_url(features)

    verdict = "HIGH RISK" if ml_score >= 60 else "SUSPICIOUS" if ml_score >= 30 else "LOW RISK"
    reasons = rule_result["reasons"] if rule_result["reasons"] else (
        ["No specific red flags, but model detected a pattern consistent with malicious URLs"]
        if ml_score >= 30 else ["No significant risk indicators found"]
    )

    db = SessionLocal()
    record = URLAnalysis(
        url=request.url,
        risk_score=ml_score,
        verdict=verdict,
        reasons=", ".join(reasons)
    )
    db.add(record)
    db.commit()
    db.close()

    return {
        "url": request.url,
        "features": full_features,
        "risk_score": ml_score,
        "verdict": verdict,
        "reasons": reasons
    }


class MessageRequest(BaseModel):
    message: str

URGENCY_WORDS = ["urgent", "immediately", "act now", "suspended", "verify now", "expire", "limited time"]
CREDENTIAL_WORDS = ["password", "otp", "pin", "cvv", "verify your account", "bank details", "card number"]
PRIZE_WORDS = ["congratulations", "winner", "lottery", "prize", "claim your", "free gift"]

def extract_message_features(message: str) -> dict:
    text = message.lower()
    return {
        "length": len(message),
        "has_url": bool(re.search(r"https?://|www\.", text)),
        "urgency_hits": sum(1 for w in URGENCY_WORDS if w in text),
        "credential_hits": sum(1 for w in CREDENTIAL_WORDS if w in text),
        "prize_hits": sum(1 for w in PRIZE_WORDS if w in text),
        "exclaim_count": message.count("!"),
        "caps_ratio": sum(1 for c in message if c.isupper()) / max(len(message), 1),
    }

def score_message(features: dict) -> dict:
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

    verdict = "HIGH RISK" if risk >= 60 else "SUSPICIOUS" if risk >= 30 else "LOW RISK"
    return {"risk_score": min(risk, 100), "verdict": verdict, "reasons": reasons}

@app.post("/detect-message")
def detect_message(request: MessageRequest):
    features = extract_message_features(request.message)
    result = score_message(features)

    db = SessionLocal()
    record = MessageAnalysis(
        message=request.message,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        reasons=", ".join(result["reasons"])
    )
    db.add(record)
    db.commit()
    db.close()

    return {"message": request.message, "features": features, **result}
