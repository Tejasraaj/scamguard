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