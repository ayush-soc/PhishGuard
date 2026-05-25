# PhishGuard 🛡️

A Python-based phishing email analyzer for SOC analysts.
Analyzes suspicious emails, checks URLs and IPs against 
VirusTotal, and generates a detailed incident report.

## Features
- Email header analysis and spoofing detection
- Brand impersonation detection
- URL extraction and VirusTotal reputation check
- Sender IP reputation check
- MITRE ATT&CK technique mapping
- Auto-generated incident report (.txt)
- Final verdict: SAFE / SUSPICIOUS / MALICIOUS

## How to run

### Install dependencies
pip install -r requirements.txt

### Add your VirusTotal API key
Open vt_checker.py and replace:
API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

### Run
python phishguard.py <email.eml>

## Example
python phishguard.py samples/test.eml

## Sample output
VERDICT: MALICIOUS
Score  : 60

Spoofing flags detected:
- Reply-To differs from From address
- Suspicious keywords in subject
- Brand impersonation detected

MITRE ATT&CK:
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link
- T1656 - Impersonation

## Tools used
- Python 3
- VirusTotal API (free tier)
- Colorama

## What I learned
- How phishing emails are structured
- Email header analysis and spoofing techniques
- IOC extraction and reputation checking
- MITRE ATT&CK technique mapping
- Incident report writing

## Legal note
This tool is for educational and defensive security 
purposes only. Only analyze emails you own or have 
permission to analyze.