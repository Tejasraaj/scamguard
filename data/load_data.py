import pandas as pd

# --- Load SMS spam dataset ---
sms = pd.read_csv(
    "data/raw/SMSSpamCollection",
    sep="\t",
    header=None,
    names=["label", "message"]
)
print("=== SMS Spam Dataset ===")
print(sms.shape)
print(sms["label"].value_counts())
print(sms.head(3))
print()

# --- Load Tranco (legitimate domains) ---
tranco = pd.read_csv(
    "data/raw/tranco_PY96J.csv",
    header=None,
    names=["rank", "domain"]
)
print("=== Tranco Legitimate Domains ===")
print(tranco.shape)
print(tranco.head(3))
print()

# --- Load OpenPhish (phishing URLs) ---
with open("data/raw/openphish.txt", "r", encoding="utf-8", errors="ignore") as f:
    phishing_urls = [line.strip() for line in f if line.strip()]
print("=== OpenPhish Phishing URLs ===")
print(f"Total phishing URLs: {len(phishing_urls)}")
print(phishing_urls[:3])

# --- Load OpenPhish (phishing URLs) ---
with open("data/raw/openphish.txt", "r", encoding="utf-8", errors="ignore") as f:
    openphish_urls = [line.strip() for line in f if line.strip()]
print("=== OpenPhish Phishing URLs ===")
print(f"Total: {len(openphish_urls)}")

# --- Load URLhaus (malicious URLs), skipping comment lines ---
urlhaus = pd.read_csv(
    "data/raw/urlhaus.csv",
    comment="#",
    header=None,
    names=["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
)
urlhaus_urls = urlhaus["url"].dropna().tolist()
print("=== URLhaus Malicious URLs ===")
print(f"Total: {len(urlhaus_urls)}")

# --- Combine both into one malicious/phishing URL list ---
malicious_urls = list(set(openphish_urls + urlhaus_urls))
print("=== Combined Malicious URL Set ===")
print(f"Total unique malicious URLs: {len(malicious_urls)}")

# --- Load OpenPhish (phishing URLs) ---
with open("data/raw/openphish.txt", "r", encoding="utf-8", errors="ignore") as f:
    phishing_urls = [line.strip() for line in f if line.strip()]
print("=== OpenPhish Phishing URLs ===")
print(f"Total phishing URLs: {len(phishing_urls)}")
print(phishing_urls[:3])