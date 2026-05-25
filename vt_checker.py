import requests
import base64

API_KEY = "0e170ca9798493a924dae1d325b1e9c639d6c1ae5cd3c4516a6a7da0ec671df5"
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}

def check_url(url):
    try:
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")
        response = requests.get(
            f"{BASE_URL}/urls/{url_id}",
            headers=HEADERS
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "safe": stats.get("malicious", 0) == 0
            }
        return {"url": url, "error": "Not found in VT"}
    except Exception as e:
        return {"url": url, "error": str(e)}

def check_ip(ip):
    try:
        response = requests.get(
            f"{BASE_URL}/ip_addresses/{ip}",
            headers=HEADERS
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "safe": stats.get("malicious", 0) == 0
            }
        return {"ip": ip, "error": "Not found in VT"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}