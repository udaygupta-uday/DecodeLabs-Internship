import re
import ipaddress
from urllib.parse import urlparse

# ----------------------------
# Configuration
# ----------------------------

FEATURE_WEIGHTS = {
    "HTTP instead of HTTPS": 5,
    "Raw IP Address": 15,
    "URL Shortener": 12,
    "@ Symbol": 10,
    "Excessive Subdomains": 8,
    "Typosquatting": 15,
    "Suspicious Keywords": 8,
    "Long URL": 5,
    "Hyphen in Domain": 5
}

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "cutt.ly",
    "is.gd",
    "ow.ly"
]

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "password",
    "bank",
    "payment",
    "invoice",
    "otp",
    "update"
]


LEGITIMATE_BRANDS = [
    "google",
    "amazon",
    "paypal",
    "microsoft",
    "facebook",
    "instagram",
    "apple",
    "netflix"
]

TYPO_PATTERNS = {
    "amaz0n": "amazon",
    "paypa1": "paypal",
    "g00gle": "google",
    "faceb00k": "facebook",
    "micr0soft": "microsoft"
}


# ----------------------------
# Helper Function
# ----------------------------

def is_ip(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


# ----------------------------
# URL Analyzer
# ----------------------------

def analyze_url(url):

    score = 0
    findings = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()

    # 1. HTTP
    if parsed.scheme == "http":
        score += FEATURE_WEIGHTS["HTTP instead of HTTPS"]
        findings.append("Uses HTTP instead of HTTPS")

    # 2. IP Address
    if is_ip(domain):
        score += FEATURE_WEIGHTS["Raw IP Address"]
        findings.append("Uses an IP address instead of a domain")

    # 3. URL Shortener
    if any(domain.endswith(short) for short in SHORTENERS):
        score += FEATURE_WEIGHTS["URL Shortener"]
        findings.append("Uses a URL shortening service")

    # 4. @ Symbol
    if "@" in url:
        score += FEATURE_WEIGHTS["@ Symbol"]
        findings.append("Contains '@' symbol")

    # 5. Excessive Subdomains
    if domain.count(".") >- 2:
        score += FEATURE_WEIGHTS["Excessive Subdomains"]
        findings.append("Too many subdomains")

    # 6. Typosquatting
    for fake, original in TYPO_PATTERNS.items():
        if fake in domain:
            score += FEATURE_WEIGHTS["Typosquatting"]
            findings.append(f"Typosquatting detected ({fake} → {original})")

    # 7. Suspicious Keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += FEATURE_WEIGHTS["Suspicious Keywords"]
            findings.append(f"Suspicious keyword: {word}")

    # 8. Long URL
    if len(url) > 40:
        score += FEATURE_WEIGHTS["Long URL"]
        findings.append("URL is unusually long")

    # 9. Hyphen
    if "-" in domain:
        score += FEATURE_WEIGHTS["Hyphen in Domain"]
        findings.append("Hyphen found in domain")

    # Final Result
    if score >= 40:
        verdict = "HIGH RISK PHISHING"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    return score, verdict, findings


# ----------------------------
# Main Program
# ----------------------------

print("=" * 60)
print("        PHISHING URL ANALYZER")
print("=" * 60)

url = input("\nEnter URL: ")

score, verdict, findings = analyze_url(url)

print("\n" + "=" * 60)
print("ANALYSIS REPORT")
print("=" * 60)

print(f"URL      : {url}")
print(f"Score    : {score}/100")
print(f"Verdict  : {verdict}")

print("\nDetected Red Flags:")

if findings:
    for i, item in enumerate(findings, 1):
        print(f"{i}. {item}")
else:
    print("No suspicious indicators found.")

print("\nRecommendation:")

if verdict == "HIGH RISK PHISHING":
    print("❌ Do NOT open this URL.")
    print("❌ Do NOT enter passwords or personal information.")
elif verdict == "SUSPICIOUS":
    print("⚠ Verify the website before visiting.")
else:
    print("✅ No major phishing indicators detected.")
