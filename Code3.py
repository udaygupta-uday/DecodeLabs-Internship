import re
from urllib.parse import urlparse

# -------------------------------
# Legitimate Brands
# -------------------------------
BRANDS = [
    "paypal",
    "google",
    "amazon",
    "netflix",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "chase"
]

# -------------------------------
# Common Phishing Keywords
# -------------------------------
KEYWORDS = [
    "urgent",
    "verify",
    "login",
    "password",
    "account",
    "bank",
    "otp",
    "winner",
    "claim",
    "gift",
    "free",
    "click here",
    "security alert",
    "update",
    "payment",
    "invoice"
]

# -------------------------------
# URL Shorteners
# -------------------------------
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "cutt.ly",
    "is.gd"
]

# -------------------------------
# Suspicious TLDs
# -------------------------------
SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".cf",
    ".gq",
    ".ml",
    ".top"
]


def extract_urls(text):
    pattern = r'https?://[^\s]+|www\.[^\s]+'
    return re.findall(pattern, text)


def analyze_url(url):

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # -----------------------------
    # HTTP Check
    # -----------------------------
    if parsed.scheme == "http":
        score += 1
        reasons.append("Uses HTTP instead of HTTPS.")

    # -----------------------------
    # URL Shortener
    # -----------------------------
    if any(short in domain for short in SHORTENERS):
        score += 3
        reasons.append("Uses a URL shortening service.")

    # -----------------------------
    # Typosquatting
    # -----------------------------
    typo_patterns = [
        "paypa1",
        "amaz0n",
        "g00gle",
        "micr0soft",
        "faceb00k"
    ]

    for typo in typo_patterns:
        if typo in domain:
            score += 3
            reasons.append("Possible Typosquatting attack.")

    # -----------------------------
    # Subdomain Tricking
    # -----------------------------
    for brand in BRANDS:
        if brand in domain and not domain.endswith(brand + ".com"):
            if domain.count(".") >= 2:
                score += 3
                reasons.append("Possible Subdomain Tricking.")

    # -----------------------------
    # Combosquatting
    # -----------------------------
    combo_words = [
        "login",
        "verify",
        "coupon",
        "reward",
        "activation",
        "security",
        "alert",
        "update"
    ]

    for brand in BRANDS:
        if brand in domain:
            for word in combo_words:
                if word in domain:
                    score += 2
                    reasons.append("Possible Combosquatting.")

    # -----------------------------
    # TLD Swapping
    # -----------------------------
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 2
            reasons.append("Uses suspicious Top-Level Domain.")

    # -----------------------------
    # Long URL
    # -----------------------------
    if len(url) > 80:
        score += 1
        reasons.append("URL is unusually long.")

    # -----------------------------
    # '@' Symbol
    # -----------------------------
    if '@' in url:
        score += 2
        reasons.append("Contains '@' symbol.")

    # -----------------------------
    # Hyphens
    # -----------------------------
    if domain.count("-") >= 2:
        score += 1
        reasons.append("Too many hyphens in domain.")

    return score, reasons


def analyze_message(message):

    score = 0

    red_flags = []

    explanations = []

    message = message.lower()

    # -----------------------------
    # Keyword Detection
    # -----------------------------
    found = []

    for word in KEYWORDS:
        if word in message:
            found.append(word)

    if found:
        score += len(found)

        red_flags.append(
            "Phishing Keywords: " + ", ".join(found)
        )

        explanations.append(
            "The message creates urgency or requests sensitive information."
        )

    # -----------------------------
    # URL Analysis
    # -----------------------------
    urls = extract_urls(message)

    if urls:
        red_flags.append("URL(s) Found")

    for url in urls:

        url_score, reasons = analyze_url(url)

        score += url_score

        for reason in reasons:
            red_flags.append(reason)

        explanations.extend(reasons)

    # -----------------------------
    # Final Decision
    # -----------------------------
    if score >= 8:
        level = "PHISHING"
        action = "BLOCK"

    elif score >= 4:
        level = "SUSPICIOUS"
        action = "WARNING"

    else:
        level = "SAFE"
        action = "ALLOW"

    return level, action, urls, red_flags, explanations


# ====================================================
# Main Program
# ====================================================

print("=" * 70)
print("        PHISHING AWARENESS ANALYSIS SYSTEM")
print("=" * 70)

message = input("\nPaste Email or Message:\n\n")

level, action, urls, flags, reasons = analyze_message(message)

print("\n" + "=" * 70)
print("ANALYSIS REPORT")
print("=" * 70)

print("Risk Level :", level)
print("Firewall Action :", action)

print("\nDetected URLs")

if urls:
    for u in urls:
        print("•", u)
else:
    print("No URLs Found")

print("\nRed Flags")

if flags:
    for f in flags:
        print("•", f)
else:
    print("No Red Flags Found")

print("\nWhy is this message unsafe?")

if reasons:
    for r in set(reasons):
        print("•", r)
else:
    print("No suspicious behaviour detected.")

print("\nAnalysis Completed Successfully.")
