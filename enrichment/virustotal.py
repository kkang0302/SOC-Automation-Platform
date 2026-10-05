import requests
from config.settings import Config

def check_hash_virustotal(file_hash):
    """
    Queries VirusTotal API v3 for file hash analysis.
    """
    if not Config.VIRUSTOTAL_KEY or Config.VIRUSTOTAL_KEY == "your_virustotal_api_key_here":
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "error": "VirusTotal API key not configured"
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": Config.VIRUSTOTAL_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
        else:
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "error": f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "error": str(e)
        }
