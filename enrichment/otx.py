import requests
from config.settings import Config

def check_ip_otx(ip_address):
    """
    Queries AlienVault OTX API for IPv4 indicators and pulse count.
    """
    if not Config.OTX_KEY or Config.OTX_KEY == "your_alienvault_otx_api_key_here":
        return {
            "otx_pulses": 0,
            "tags": [],
            "error": "AlienVault OTX API key not configured"
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": Config.OTX_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            tags = []
            for pulse in pulse_info.get("pulses", [])[:5]:
                tags.extend(pulse.get("tags", []))
            return {
                "otx_pulses": pulse_count,
                "tags": list(set(tags))
            }
        else:
            return {
                "otx_pulses": 0,
                "tags": [],
                "error": f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            "otx_pulses": 0,
            "tags": [],
            "error": str(e)
        }
