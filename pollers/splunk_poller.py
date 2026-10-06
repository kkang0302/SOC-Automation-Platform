import sys
import os

# Automatically append project root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import logging
import requests
from config.settings import Config
from engine.orchestrator import process_alert

# Disable SSL Warnings for local self-signed Splunk certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("SplunkPoller")

SPLUNK_HOST = "https://127.0.0.1:8089"  # Splunk Management Port
SPLUNK_USER = "admin"
SPLUNK_PASS = "Kkanger2.0"

# SPL Search Query để quét log tấn công (Failed SSH logins, Suricata Alerts, Port Scans, Nmap)
SEARCH_QUERY = 'search index=* ("Failed password" OR "Suricata" OR "DROP" OR "SCAN" OR "invalid user" OR "Nmap" OR "nmap") | head 10'

def poll_splunk_alerts():
    """
    Periodic poller for Splunk Free Edition (which lacks Webhook Alert Actions).
    Queries Splunk REST API export endpoint every N seconds.
    """
    logger.info("[POLLER] Starting Splunk Free REST API Poller Daemon...")
    
    url = f"{SPLUNK_HOST}/servicesNS/admin/search/search/jobs/export"
    
    payload = {
        "search": SEARCH_QUERY,
        "output_mode": "json",
        "earliest_time": "-2m@m",
        "latest_time": "now"
    }

    seen_event_ids = set()

    while True:
        try:
            response = requests.post(
                url, 
                data=payload, 
                auth=(SPLUNK_USER, SPLUNK_PASS), 
                verify=False, 
                timeout=15
            )

            if response.status_code == 200:
                lines = response.text.strip().split("\n")
                for line in lines:
                    if not line:
                        continue
                    try:
                        import json
                        data = json.loads(line)
                        result = data.get("result", {})
                        
                        event_id = result.get("_cd") or result.get("_raw")
                        if event_id and event_id not in seen_event_ids:
                            seen_event_ids.add(event_id)
                            raw_str = result.get("_raw", "")
                            sourcetype = result.get("sourcetype") or "Splunk Log"
                            logger.info(f"[POLLER] New event detected from Splunk Free ({sourcetype}): {raw_str[:80]}...")
                            
                            mock_payload = {
                                "search_name": f"Splunk Free: {sourcetype}",
                                "severity": "high",
                                "result": result
                            }
                            process_alert(mock_payload)
                    except Exception as parse_err:
                        continue

            if len(seen_event_ids) > 1000:
                seen_event_ids.clear()

        except Exception as e:
            logger.error(f"[POLLER ERROR] Failed to connect to Splunk REST API: {e}")

        # Poll every 10 seconds
        time.sleep(10)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")
    poll_splunk_alerts()
