import logging
from parsers.splunk_parser import parse_splunk_alert
from enrichment.abuseipdb import check_ip_abuseipdb
from enrichment.virustotal import check_hash_virustotal
from enrichment.otx import check_ip_otx
from engine.risk_score import calculate_risk_score
from actions.notifier import send_discord_alert
from actions.firewall_block import block_ip_firewall

logger = logging.getLogger(__name__)

def process_alert(raw_payload):
    """
    Main Orchestrator Pipeline:
    1. Parse raw SIEM alert
    2. Enrich IOCs (IP/Hash) with Threat Intelligence
    3. Compute Risk Score & Verdict
    4. Dispatch notifications (Discord)
    5. Trigger active firewall response for High/Critical threats
    """
    logger.info("================== [PROCESSING NEW ALERT] ==================")
    
    # 1. Parse Alert
    parsed = parse_splunk_alert(raw_payload)
    logger.info(f"Parsed Alert: {parsed['search_name']} | Src: {parsed['src_ip']} | Severity: {parsed['severity']}")

    src_ip = parsed.get("src_ip")
    file_hash = parsed.get("file_hash")

    # 2. Threat Intelligence Enrichment
    abuse_info = check_ip_abuseipdb(src_ip) if src_ip else None
    vt_info = check_hash_virustotal(file_hash) if file_hash else None
    otx_info = check_ip_otx(src_ip) if src_ip else None

    # 3. Calculate Risk Score
    risk = calculate_risk_score(parsed, abuse_info, vt_info, otx_info)
    logger.info(f"Risk Evaluation Result: Verdict={risk['verdict']} | Score={risk['risk_score']}/100")

    # 4. Dispatch Notifications
    discord_ok, discord_msg = send_discord_alert(parsed, risk, abuse_info)
    logger.info(f"Notification Status: Discord={discord_msg}")

    # 5. Active Mitigation Response (Automated Containment)
    mitigation_status = "Skipped (Risk below containment threshold)"
    if risk["verdict"] in ["HIGH", "CRITICAL"] and src_ip:
        logger.warning(f"HIGH/CRITICAL Threat Verdict detected! Triggering firewall block for IP: {src_ip}")
        success, msg = block_ip_firewall(src_ip)
        mitigation_status = msg
        logger.info(f"Mitigation Result: {msg}")

    logger.info("================== [ALERT PROCESSING FINISHED] ==================")

    return {
        "parsed_alert": parsed,
        "enrichment": {
            "abuseipdb": abuse_info,
            "virustotal": vt_info,
            "alienvault_otx": otx_info
        },
        "risk_evaluation": risk,
        "notifications": {
            "discord": discord_msg
        },
        "mitigation": mitigation_status
    }
