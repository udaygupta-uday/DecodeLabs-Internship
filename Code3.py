import re
import ipaddress
from urllib.parse import urlparse

# -----------------------------
# Legitimate Brand Names
# -----------------------------
BRANDS = [
    "paypal", "google", "amazon", "netflix",
    "microsoft", "apple", "facebook",
    "instagram", "chase"
]

# -----------------------------
# Phishing Keywords
# -----------------------------
KEYWORDS = [
    "urgent", "verify", "login", "password",
    "account", "bank", "otp", "winner",
    "claim", "gift", "free", "click here",
    "security alert", "update",
    "payment", "invoice"
]

# -----------------------------
# URL Shorteners
# -----------------------------
SHORTENERS = [
    "bit.ly", "tinyurl.com",
    "goo.gl", "t.co",
    "cutt.ly", "is.gd"
]

# -----------------------------
# Suspicious TLDs
# -----------------------------
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk",
    ".cf", ".gq", ".ml"
]

# -----------------------------
# Typosquatting Patterns
# -----------------------------
TYPO_PATTERNS = [
    r"paypa1",
    r"amaz0n",
    r"g00gle",
    r"micr0soft",
    r"faceb00k"
]

# -----------------------------
# Extract URLs
# -----------------------------
def extract_urls(text):
    pattern = r'(https?://\S+|www\.\S+)'
    return re.findall(pattern, text)


# -----------------------------
# Check if Domain is IP
# -----------------------------
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


# -----------------------------
# Analyze One URL
# -----------------------------
def analyze_url(url):

    score = 0
    reasons = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Remove port if exists
    domain = domain.split(":")[0]

    # HTTP Check
    if parsed.scheme == "http":
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    # URL Shortener
    if any(short in domain for short in SHORTENERS):
        score += 3
        reasons.append("Uses URL Shortener")

    # Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 2
        reasons.append("Suspicious Top-Level Domain")

    # IP Address
    if is_ip(domain):
        score += 3
        reasons.append("Uses IP Address instead of Domain")

    # Typosquatting
    for typo in TYPO_PATTERNS:
        if re.search(typo, domain):
            score += 3
            reasons.append("Possible Typosquatting")
            break

    # Subdomain Tricking
    parts = domain.split(".")

    if len(parts) > 3:
        for brand in BRANDS:
            if brand in parts[:-2]:
                score += 3
                reasons.append("Possible Subdomain Tricking")
                break

    # Combosquatting
    combo_words = [
        "login",
        "verify",
        "security",
        "reward",
        "coupon",
        "activation",
        "update"
    ]

    for brand in BRANDS:
        if brand in domain:
            for word in combo_words:
                if f"{brand}-{word}" in domain or f"{word}-{brand}" in domain:
                    score += 2
                    reasons.append("Possible Combosquatting")
                    break

    # Homograph Attack
    if not domain.isascii():
        score += 3
        reasons.append("Possible Homograph Attack")

    # @ Symbol
    if "@" in url:
        score += 2
        reasons.append("Contains '@' Symbol")

    # Too Long URL
    if len(url) > 100:
        score += 1
        reasons.append("Very Long URL")

    # Too Many Hyphens
    if domain.count("-") >= 2:
        score += 1
        reasons.append("Too Many Hyphens")

    return score, list(set(reasons))


# -----------------------------
# Analyze Message
# -----------------------------
def analyze_message(message):

    score = 0

    red_flags = []

    explanation = []

    lower_msg = message.lower()

    # Keyword Detection
    found = []

    for word in KEYWORDS:
        if word in lower_msg:
            found.append(word)

    if found:
        score += len(found)
        red_flags.append(
            "Phishing Keywords: " + ", ".join(found)
        )

        explanation.append(
            "Message contains phishing-related keywords."
        )

    # URL Detection
    urls = extract_urls(message)

    if urls:
        red_flags.append("URLs Found")

    for url in urls:

        url_score, reasons = analyze_url(url)

        score += url_score

        red_flags.extend(reasons)

        explanation.extend(reasons)

    # Remove Duplicates
    red_flags = list(set(red_flags))
    explanation = list(set(explanation))

    # Final Decision
    if score >= 10:
        level = "PHISHING"
        action = "BLOCK"

    elif score >= 5:
        level = "SUSPICIOUS"
        action = "WARNING"

    else:
        level = "SAFE"
        action = "ALLOW"

    return score, level, action, urls, red_flags, explanation


# -----------------------------
# Main Program
# -----------------------------
print("=" * 70)
print("      PHISHING AWARENESS ANALYSIS SYSTEM")
print("=" * 70)

message = input("\nPaste Email or Message:\n\n")

score, level, action, urls, flags, reasons = analyze_message(message)

print("\n" + "=" * 70)
print("ANALYSIS REPORT")
print("=" * 70)

print(f"Risk Score      : {score}")
print(f"Risk Level      : {level}")
print(f"Firewall Action : {action}")

print("\nDetected URLs")
if urls:
    for url in urls:
        print("•", url)
else:
    print("No URLs Found")

print("\nRed Flags")
if flags:
    for flag in flags:
        print("•", flag)
else:
    print("No Red Flags Found")

print("\nWhy is this message unsafe?")
if reasons:
    for reason in reasons:
        print("•", reason)
else:
    print("No suspicious behaviour detected.")

print("\nAnalysis Completed Successfully.")
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

