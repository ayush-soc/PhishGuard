import email
import re
import sys
from email import policy
from colorama import Fore, init
from vt_checker import check_url, check_ip
from reporter import print_report

init(autoreset=True)

def load_email(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return email.message_from_file(f, policy=policy.default)

def extract_headers(msg):
    return {
        "from":       msg.get("From", "N/A"),
        "reply_to":   msg.get("Reply-To", "N/A"),
        "subject":    msg.get("Subject", "N/A"),
        "date":       msg.get("Date", "N/A"),
        "received":   msg.get_all("Received", []),
        "x_mailer":   msg.get("X-Mailer", "N/A"),
    }

def extract_urls(msg):
    urls = set()
    pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    urls.update(pattern.findall(part.get_content()))
                except:
                    pass
    else:
        try:
            urls.update(pattern.findall(msg.get_content()))
        except:
            pass
    return list(urls)

def extract_sender_ip(received_headers):
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    if received_headers:
        last = received_headers[-1]
        for ip in pattern.findall(last):
            parts = ip.split(".")
            if not (
                parts[0] == "10" or
                (parts[0] == "172" and 16 <= int(parts[1]) <= 31) or
                (parts[0] == "192" and parts[1] == "168") or
                ip.startswith("127.")
            ):
                return ip
    return None

def check_spoofing(headers):
    flags = []
    from_addr  = headers["from"]
    reply_to   = headers["reply_to"]

    if reply_to != "N/A" and reply_to not in from_addr:
        flags.append("Reply-To differs from From address")

    suspicious_words = [
        "urgent", "verify", "account", "suspended", "click here",
        "confirm", "password", "login", "winner", "prize",
        "free", "limited time", "act now"
    ]
    found = [w for w in suspicious_words if w in headers["subject"].lower()]
    if found:
        flags.append(f"Suspicious keywords in subject: {', '.join(found)}")

    from_match = re.search(r'<(.+?)>', from_addr)
    if from_match:
        domain = from_match.group(1).split("@")[-1]
        display = from_addr.split("<")[0].strip().lower()
        brands = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "bank"]
        if any(b in display for b in brands):
            if not any(b in domain for b in brands):
                flags.append(f"Brand impersonation — display name vs domain mismatch: '{domain}'")

    return flags

def calculate_verdict(spoof_flags, url_results, ip_result):
    score = 0
    score += len(spoof_flags) * 20

    for r in url_results:
        if r.get("malicious", 0) > 0:
            score += 40
        elif r.get("suspicious", 0) > 0:
            score += 20

    if ip_result and ip_result.get("malicious", 0) > 0:
        score += 30

    if score >= 60:
        return "MALICIOUS", score
    elif score >= 20:
        return "SUSPICIOUS", score
    else:
        return "SAFE", score

def analyze(filepath):
    print(Fore.WHITE + f"\n[*] Loading: {filepath}")

    try:
        msg = load_email(filepath)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {filepath}")
        sys.exit(1)

    print(Fore.WHITE + "[*] Extracting headers...")
    headers = extract_headers(msg)

    print(Fore.WHITE + "[*] Running spoofing checks...")
    spoof_flags = check_spoofing(headers)

    print(Fore.WHITE + "[*] Extracting sender IP...")
    sender_ip = extract_sender_ip(headers["received"])

    print(Fore.WHITE + "[*] Checking IP on VirusTotal...")
    ip_result = check_ip(sender_ip) if sender_ip else None

    print(Fore.WHITE + "[*] Extracting URLs...")
    urls = extract_urls(msg)

    print(Fore.WHITE + f"[*] Checking {len(urls)} URL(s) on VirusTotal...")
    url_results = [check_url(u) for u in urls[:5]]

    verdict, score = calculate_verdict(spoof_flags, url_results, ip_result)

    data = {
        "headers":    headers,
        "spoof_flags": spoof_flags,
        "sender_ip":  sender_ip,
        "ip_result":  ip_result,
        "url_results": url_results,
        "verdict":    verdict,
        "score":      score,
    }

    print_report(data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage  : python phishguard.py <email.eml>")
        print("Example: python phishguard.py samples/test.eml")
        sys.exit(1)

    analyze(sys.argv[1])