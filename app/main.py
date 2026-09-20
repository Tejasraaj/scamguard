from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import re

app = FastAPI(title="Scam Detection API")

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
    result = score_url(features)
    return {"url": request.url, "features": features, **result}
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
    return {"message": request.message, "features": features, **result}