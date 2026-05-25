from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

MITRE_MAP = {
    "spoofing":     "T1566.001 - Spearphishing Attachment",
    "url":          "T1566.002 - Spearphishing Link",
    "impersonation":"T1656 - Impersonation",
    "credentials":  "T1598 - Phishing for Information",
}

def print_banner():
    print(Fore.CYAN + """
╔═══════════════════════════════════════════════╗
║            PhishGuard v1.0                    ║
║    Phishing Email Analyzer | Ayush Mishra     ║
║    SOC Blue Team Tool                         ║
╚═══════════════════════════════════════════════╝""")

def print_section(title):
    print(Fore.CYAN + f"\n--- {title} " + "-" * (45 - len(title)))

def print_report(data):
    print_banner()

    # Headers
    print_section("EMAIL HEADERS")
    print(f"  From       : {data['headers']['from']}")
    print(f"  Reply-To   : {data['headers']['reply_to']}")
    print(f"  Subject    : {data['headers']['subject']}")
    print(f"  Date       : {data['headers']['date']}")
    print(f"  X-Mailer   : {data['headers']['x_mailer']}")

    # Spoofing
    print_section("SPOOFING & MANIPULATION CHECKS")
    if data['spoof_flags']:
        for flag in data['spoof_flags']:
            print(Fore.YELLOW + f"  [!] {flag}")
    else:
        print(Fore.GREEN + "  [OK] No spoofing indicators detected")

    # Sender IP
    print_section("SENDER IP ANALYSIS")
    if data['sender_ip']:
        print(f"  Originating IP : {data['sender_ip']}")
        ip_result = data['ip_result']
        if ip_result:
            if "error" in ip_result:
                print(Fore.YELLOW + f"  VT Result      : {ip_result['error']}")
            elif ip_result['malicious'] > 0:
                print(Fore.RED + f"  VT Result      : MALICIOUS ({ip_result['malicious']} engines)")
            else:
                print(Fore.GREEN + f"  VT Result      : Clean")
    else:
        print("  Could not extract originating IP")

    # URLs
    print_section("URL ANALYSIS")
    if data['url_results']:
        for r in data['url_results']:
            url_short = r['url'][:55] + "..." if len(r['url']) > 55 else r['url']
            if "error" in r:
                print(Fore.YELLOW + f"  [?] {url_short}")
                print(Fore.YELLOW + f"      {r['error']}")
            elif r['malicious'] > 0:
                print(Fore.RED + f"  [X] {url_short}")
                print(Fore.RED + f"      MALICIOUS - {r['malicious']} engines flagged")
            elif r['suspicious'] > 0:
                print(Fore.YELLOW + f"  [?] {url_short}")
                print(Fore.YELLOW + f"      SUSPICIOUS - {r['suspicious']} engines flagged")
            else:
                print(Fore.GREEN + f"  [OK] {url_short}")
                print(Fore.GREEN + f"       Clean")
    else:
        print("  No URLs found in email body")

    # MITRE ATT&CK
    print_section("MITRE ATT&CK MAPPING")
    techniques = set()
    if data['spoof_flags']:
        techniques.add(MITRE_MAP['spoofing'])
        techniques.add(MITRE_MAP['impersonation'])
    if data['url_results']:
        techniques.add(MITRE_MAP['url'])
    if any(w in data['headers']['subject'].lower() for w in
           ['password', 'verify', 'confirm', 'login', 'credential']):
        techniques.add(MITRE_MAP['credentials'])

    if techniques:
        for t in techniques:
            print(Fore.YELLOW + f"  [*] {t}")
    else:
        print("  No techniques mapped")

    # Risk Score
    print_section("RISK ASSESSMENT")
    verdict = data['verdict']
    if verdict == "MALICIOUS":
        color = Fore.RED
    elif verdict == "SUSPICIOUS":
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    print(color + f"""
  +---------------------------------------+
  |   VERDICT:  {verdict:<26}|
  |   Score  :  {str(data['score']):<26}|
  +---------------------------------------+""")

    # Save report
    save_report(data)

def save_report(data):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("PHISHGUARD ANALYSIS REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"From       : {data['headers']['from']}\n")
        f.write(f"Reply-To   : {data['headers']['reply_to']}\n")
        f.write(f"Subject    : {data['headers']['subject']}\n")
        f.write(f"Date       : {data['headers']['date']}\n\n")
        f.write("SPOOFING FLAGS:\n")
        for flag in data['spoof_flags']:
            f.write(f"  - {flag}\n")
        f.write(f"\nSENDER IP: {data['sender_ip']}\n")
        f.write("\nURLs FOUND:\n")
        for r in data['url_results']:
            f.write(f"  - {r['url']} - malicious: {r.get('malicious','N/A')}\n")
        f.write(f"\nVERDICT: {data['verdict']}\n")
        f.write(f"SCORE: {data['score']}\n")

    print(Fore.CYAN + f"\n  [*] Report saved: {filename}")