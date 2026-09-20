import pandas as pd
import re
from urllib.parse import urlparse

BRAND_KEYWORDS = ["paypal", "amazon", "bank", "login", "secure", "verify", "account", "update", "confirm", "signin"]

def extract_url_features(url: str) -> dict:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.netloc.split(":")[0]
        path = parsed.path
        ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        digit_count = sum(c.isdigit() for c in hostname)
        digit_ratio = digit_count / max(len(hostname), 1)

        return {
            "url_length": len(url),
            "https": int(parsed.scheme == "https"),
            "subdomain_count": hostname.count("."),
            "has_ip": int(bool(ipv4_pattern.match(hostname))),
            "hyphen_count": hostname.count("-"),
            "digit_ratio": round(digit_ratio, 3),
            "path_length": len(path),
            "has_at_symbol": int("@" in url),
            "brand_keyword_count": sum(1 for kw in BRAND_KEYWORDS if kw in hostname.lower()),
        }
    except Exception:
        return None

# Load, keeping only well-formed rows with valid labels
df_raw = pd.read_csv("data/raw/url_dataset.csv", on_bad_lines="skip", engine="python")
df_raw = df_raw[df_raw["type"].isin(["legitimate", "phishing"])].dropna(subset=["url"])

print(f"Loaded {len(df_raw)} valid labeled rows")
print(df_raw["type"].value_counts())

# Balance classes: sample equal numbers from each (avoids class-imbalance bias)
n_per_class = min(df_raw["type"].value_counts())
legit_sample = df_raw[df_raw["type"] == "legitimate"].sample(n=n_per_class, random_state=42)
phish_sample = df_raw[df_raw["type"] == "phishing"].sample(n=n_per_class, random_state=42)
df_balanced = pd.concat([legit_sample, phish_sample], ignore_index=True)

# Extract features
rows = []
for _, row in df_balanced.iterrows():
    feats = extract_url_features(row["url"])
    if feats:
        feats["label"] = 1 if row["type"] == "phishing" else 0
        rows.append(feats)

df_final = pd.DataFrame(rows)
df_final.to_csv("data/url_training_data_v2.csv", index=False)

print(f"\nFinal training set: {len(df_final)} rows")
print(df_final["label"].value_counts())
print(df_final.head())