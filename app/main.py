from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from urllib.parse import urlparse
from app.database import SessionLocal, URLAnalysis, MessageAnalysis, Blocklist
import datetime
import joblib
import pandas as pd
import re

app = FastAPI(title="Scam Detection API")
url_model = joblib.load("app/url_model_v2.pkl")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Only very confident detections go on the blocklist (reduces false positives)
BLOCKLIST_THRESHOLD = 90

# Big trusted domains are never auto-blocked
PROTECTED_DOMAINS = ("google.com", "wikipedia.org", "github.com",
                     "microsoft.com", "amazon.com", "apple.com")


@app.get("/")
def serve_frontend():
    return FileResponse("app/static/index.html")


# ---------- Level 1: recommended actions ----------

HEADLINES = {
    "HIGH RISK": "Do not proceed. Do not open, reply to or act on this.",
    "SUSPICIOUS": "Be careful. Verify this through an official source before acting.",
    "LOW RISK": "No strong warning signs found, but stay alert.",
}

ADVICE = {
    "not encrypted": "Never enter passwords or card details on a site without HTTPS.",
    "raw ip": "Real services almost never use a bare IP address for login pages.",
    "hyphens": "Check the real domain carefully. Scammers imitate brands with extra words and hyphens.",
    "subdomains": "The real owner of a site is the last part of the domain before the first slash.",
    "credentials": "Never share OTP, PIN, CVV or passwords. Banks and companies never ask for them by message.",
    "urgency": "Scammers create panic. Pause and contact the organisation through its official app or number.",
    "prize": "You cannot win a contest you never entered. Never pay a fee to claim a prize.",
    "link": "Do not tap links in unexpected messages. Open the official app or website yourself.",
}


def build_recommendations(verdict, reasons):
    recs = [HEADLINES[verdict]]
    joined = " | ".join(reasons).lower()
    for keyword, advice in ADVICE.items():
        if keyword in joined:
            recs.append(advice)
    if verdict == "HIGH RISK":
        recs.append("If you already clicked or replied, change your passwords and contact your bank.")
    return recs


# ---------- Level 2: blocklist helpers (all fault tolerant) ----------

def get_domain(url):
    full = url if "://" in url else "http://" + url
    return urlparse(full).netloc.split("@")[-1].split(":")[0].lower()


def is_protected(domain):
    for p in PROTECTED_DOMAINS:
        if domain == p or domain.endswith("." + p):
            return True
    return False


def check_blocklist(domain):
    try:
        db = SessionLocal()
        try:
            entry = db.query(Blocklist).filter(Blocklist.domain == domain).first()
            if entry:
                entry.times_seen += 1
                entry.last_seen = datetime.datetime.utcnow()
                db.commit()
                return entry.times_seen
        finally:
            db.close()
    except Exception as e:
        print("Blocklist check failed:", e)
    return 0


def add_to_blocklist(domain):
    try:
        db = SessionLocal()
        try:
            entry = db.query(Blocklist).filter(Blocklist.domain == domain).first()
            if entry:
                entry.times_seen += 1
                entry.last_seen = datetime.datetime.utcnow()
            else:
                db.add(Blocklist(domain=domain))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        print("Blocklist update failed:", e)


def save_url_record(url, score, verdict, reasons):
    try:
        db = SessionLocal()
        try:
            db.add(URLAnalysis(url=url, risk_score=score, verdict=verdict,
                               reasons=", ".join(reasons)))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        print("Could not save URL record:", e)


def save_message_record(message, score, verdict, reasons):
    try:
        db = SessionLocal()
        try:
            db.add(MessageAnalysis(message=message, risk_score=score,
                                   verdict=verdict, reasons=", ".join(reasons)))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        print("Could not save message record:", e)


# ---------- URL detection ----------

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
    domain = get_domain(request.url)

    # Known bad domain: block instantly, skip the model
    seen = check_blocklist(domain) if domain else 0
    if seen:
        reasons = [f"This domain is on the blocklist (flagged before, seen {seen} times)"]
        save_url_record(request.url, 100, "HIGH RISK", reasons)
        return {
            "url": request.url,
            "risk_score": 100,
            "verdict": "HIGH RISK",
            "blocked": True,
            "reasons": reasons,
            "recommendations": build_recommendations("HIGH RISK", reasons),
        }

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
    brand_keywords = ["paypal", "amazon", "bank", "login", "secure",
                      "verify", "account", "update", "confirm", "signin"]

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
    if rule_result["reasons"]:
        reasons = rule_result["reasons"]
    elif ml_score >= 30:
        reasons = ["No specific red flags, but the model detected a pattern consistent with malicious URLs"]
    else:
        reasons = ["No significant risk indicators found"]

    # Remember very confident detections
    blocked = False
    if ml_score >= BLOCKLIST_THRESHOLD and domain and not is_protected(domain):
        add_to_blocklist(domain)
        blocked = True

    save_url_record(request.url, ml_score, verdict, reasons)

    return {
        "url": request.url,
        "features": full_features,
        "risk_score": ml_score,
        "verdict": verdict,
        "blocked": blocked,
        "reasons": reasons,
        "recommendations": build_recommendations(verdict, reasons),
    }


# ---------- Message detection ----------

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

    save_message_record(request.message, result["risk_score"],
                        result["verdict"], result["reasons"])

    return {
        "message": request.message,
        "features": features,
        **result,
        "recommendations": build_recommendations(result["verdict"], result["reasons"]),
    }


# ---------- History and blocklist views ----------

@app.get("/history")
def get_history():
    try:
        db = SessionLocal()
        try:
            urls = db.query(URLAnalysis).order_by(URLAnalysis.id.desc()).limit(20).all()
            messages = db.query(MessageAnalysis).order_by(MessageAnalysis.id.desc()).limit(20).all()
            return {
                "urls": [{"id": u.id, "url": u.url, "risk_score": u.risk_score,
                          "verdict": u.verdict, "reasons": u.reasons} for u in urls],
                "messages": [{"id": m.id, "message": m.message, "risk_score": m.risk_score,
                              "verdict": m.verdict, "reasons": m.reasons} for m in messages],
            }
        finally:
            db.close()
    except Exception as e:
        print("History failed:", e)
        return {"urls": [], "messages": [], "error": "Database unavailable"}


@app.get("/blocklist")
def get_blocklist():
    try:
        db = SessionLocal()
        try:
            rows = db.query(Blocklist).order_by(Blocklist.last_seen.desc()).limit(50).all()
            return {"domains": [{"domain": r.domain, "times_seen": r.times_seen} for r in rows]}
        finally:
            db.close()
    except Exception as e:
        print("Blocklist view failed:", e)
        return {"domains": [], "error": "Database unavailable"}
