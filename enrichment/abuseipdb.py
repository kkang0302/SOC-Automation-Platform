import requests
from config.settings import Config

def check_ip_abuseipdb(ip_address):
    """
    Queries AbuseIPDB API v2 for IP reputation data.
    """
    if not Config.ABUSEIPDB_KEY or Config.ABUSEIPDB_KEY == "your_abuseipdb_api_key_here":
        return {
            "abuse_score": 0,
            "country": "N/A",
            "usage_type": "N/A",
            "isp": "N/A",
            "total_reports": 0,
            "error": "AbuseIPDB API key not configured"
        }

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': Config.ABUSEIPDB_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
                "isp": data.get("isp", "N/A"),
                "total_reports": data.get("totalReports", 0)
            }
        else:
            return {
                "abuse_score": 0,
                "country": "N/A",
                "usage_type": "N/A",
                "isp": "N/A",
                "total_reports": 0,
                "error": f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            "abuse_score": 0,
            "country": "N/A",
            "usage_type": "N/A",
            "isp": "N/A",
            "total_reports": 0,
            "error": str(e)
        }
