import requests
from config.settings import Config

def send_discord_alert(parsed_alert, risk_result, abuse_data=None):
    """
    Sends a rich formatted embed card to Discord Webhook.
    """
    if not Config.DISCORD_WEBHOOK or "your_discord_webhook" in Config.DISCORD_WEBHOOK:
        return False, "Discord Webhook URL not configured"

    color_map = {
        "CRITICAL": 15158332, # Red
        "HIGH": 15105570,     # Orange
        "MEDIUM": 1752220,    # Teal
        "LOW": 3066993        # Green
    }

    verdict = risk_result.get("verdict", "UNKNOWN")
    score = risk_result.get("risk_score", 0)

    embed = {
        "title": f"🚨 SOC ALERT: {parsed_alert.get('search_name', 'Security Event')}",
        "color": color_map.get(verdict, 3447003),
        "fields": [
            {
                "name": "Mức Rủi Ro (Verdict)", 
                "value": f"**{verdict}** (Score: {score}/100)", 
                "inline": True
            },
            {
                "name": "Source IP", 
                "value": f"`{parsed_alert.get('src_ip') or 'N/A'}`", 
                "inline": True
            },
            {
                "name": "Target / User", 
                "value": f"`{parsed_alert.get('user') or 'N/A'}`", 
                "inline": True
            },
            {
                "name": "Lý Do Cảnh Báo", 
                "value": "\n".join([f"• {r}" for r in risk_result.get('reasons', [])]), 
                "inline": False
            }
        ],
        "footer": {
            "text": "SOC Automation Engine v1.0 • Auto Incident Response Active"
        }
    }

    if abuse_data and isinstance(abuse_data, dict) and abuse_data.get("isp") != "N/A":
        embed["fields"].append({
            "name": "AbuseIPDB Threat Context",
            "value": f"Country: **{abuse_data.get('country')}** | ISP: **{abuse_data.get('isp')}** | Abuse Score: **{abuse_data.get('abuse_score')}%**",
            "inline": False
        })

    payload = {"embeds": [embed]}
    try:
        res = requests.post(Config.DISCORD_WEBHOOK, json=payload, timeout=10)
        return res.status_code in [200, 204], f"HTTP {res.status_code}"
    except Exception as e:
        return False, str(e)

