import pandas as pd
import re
from urllib.parse import urlparse

def extract_url_features(url: str) -> dict:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.netloc.split(":")[0]
        ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return {
            "url_length": len(url),
            "https": int(parsed.scheme == "https"),
            "subdomain_count": hostname.count("."),
            "has_ip": int(bool(ipv4_pattern.match(hostname))),
            "hyphen_count": hostname.count("-"),
        }
    except Exception:
        return None

# --- Legitimate URLs from Tranco (sample 15,000 to balance dataset size) ---
tranco = pd.read_csv("data/raw/tranco_PY96J.csv", header=None, names=["rank", "domain"])
legit_sample = ("https://" + tranco["domain"].sample(n=15000, random_state=42)).tolist()

# --- Malicious URLs (OpenPhish + URLhaus) ---
with open("data/raw/openphish.txt", "r", encoding="utf-8", errors="ignore") as f:
    openphish_urls = [line.strip() for line in f if line.strip()]

urlhaus = pd.read_csv(
    "data/raw/urlhaus.csv", comment="#", header=None,
    names=["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
)
malicious_urls = list(set(openphish_urls + urlhaus["url"].dropna().tolist()))

# --- Build feature rows ---
rows = []
for url in legit_sample:
    feats = extract_url_features(url)
    if feats:
        feats["label"] = 0
        rows.append(feats)

for url in malicious_urls:
    feats = extract_url_features(url)
    if feats:
        feats["label"] = 1
        rows.append(feats)

df = pd.DataFrame(rows)
df.to_csv("data/url_training_data.csv", index=False)

print(f"Total rows: {len(df)}")
print(df["label"].value_counts())
print(df.head())

