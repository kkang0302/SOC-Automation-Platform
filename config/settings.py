import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # API Keys
    ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    OTX_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")

    # Webhooks
    DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
    SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")

    # Thresholds
    RISK_HIGH = int(os.getenv("RISK_THRESHOLD_HIGH", 50))
    RISK_CRITICAL = int(os.getenv("RISK_THRESHOLD_CRITICAL", 80))

    # Server settings
    PORT = int(os.getenv("FLASK_PORT", 5000))
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
