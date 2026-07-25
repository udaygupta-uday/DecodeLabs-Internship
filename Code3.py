import re

PHISHING_KEYWORDS = [
    "urgent", "verify", "password", "bank", "login",
    "click here", "winner", "claim", "gift", "free",
    "limited time", "otp", "account suspended"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co"
]

def analyze_message(message):
    score = 0
    red_flags = []

    # Find URLs
    urls = re.findall(r'https?://\S+|www\.\S+', message)

    if urls:
        red_flags.append("Contains URL(s)")
        score += 2

    # Check suspicious domains
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                red_flags.append(f"Shortened URL detected: {url}")
                score += 3

    # Check phishing keywords
    lower_msg = message.lower()

    for word in PHISHING_KEYWORDS:
        if word in lower_msg:
            red_flags.append(f"Keyword found: {word}")
            score += 1

    # Determine risk
    if score >= 6:
        risk = "PHISHING"
    elif score >= 3:
        risk = "SUSPICIOUS"
    else:
        risk = "SAFE"

    return risk, red_flags


print("=" * 50)
print("Simple Firewall - Phishing Message Detector")
print("=" * 50)

message = input("\nPaste Email/SMS:\n")

risk, flags = analyze_message(message)

print("\nResult")
print("-" * 30)
print("Risk Level:", risk)

if flags:
    print("\nRed Flags:")
    for flag in flags:
        print("-", flag)
else:
    print("No red flags found.")

if risk == "PHISHING":
    print("\nFirewall Action: BLOCKED")
elif risk == "SUSPICIOUS":
    print("\nFirewall Action: WARNING")
else:
    print("\nFirewall Action: ALLOWED")
