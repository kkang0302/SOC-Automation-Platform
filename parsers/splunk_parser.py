import re

def parse_splunk_alert(payload):
    """
    Parses and normalizes raw Splunk Webhook Alert / Polled Log payload into a standard SOC schema.
    Uses regex fallback to extract source IPs and raw log context from unparsed logs.
    """
    if not isinstance(payload, dict):
        return {
            "search_name": "Unknown Alert Payload",
            "src_ip": None,
            "dest_ip": None,
            "user": "Unknown",
            "file_hash": None,
            "severity": "medium",
            "raw_log": "N/A"
        }

    # Splunk alerts store search results inside 'result' or top-level payload
    result = payload.get("result", payload)
    raw_log = result.get("_raw") or result.get("raw") or "N/A"

    # Extract signature or search name
    search_name = (
        payload.get("search_name") or 
        result.get("signature") or 
        result.get("sourcetype") or 
        result.get("rule_name") or 
        "Splunk Security Event"
    )

    if search_name == "Splunk Free Auto-Polled Event" and raw_log != "N/A":
        # Make title more descriptive using raw log snippet
        search_name = f"Log Event: {raw_log[:70]}..."

    severity = str(payload.get("severity") or result.get("severity") or "medium").lower()

    # Extract source IP from explicit fields
    src_ip = (
        result.get("src_ip") or 
        result.get("src") or 
        result.get("clientip") or 
        result.get("source_ip") or
        result.get("ip")
    )

    # Extract destination IP
    dest_ip = (
        result.get("dest_ip") or 
        result.get("dest") or 
        result.get("destination_ip") or
        result.get("target_ip")
    )

    # Fallback: Regex IPv4 extraction from raw log if src_ip is missing
    if not src_ip and raw_log != "N/A":
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_log)
        filtered_ips = [
            ip for ip in ip_matches 
            if not ip.startswith("127.") and ip not in ["0.0.0.0", "255.255.255.255"]
        ]
        if filtered_ips:
            src_ip = filtered_ips[0]
            if len(filtered_ips) > 1 and not dest_ip:
                dest_ip = filtered_ips[1]

    # Extract user/username
    user = (
        result.get("user") or 
        result.get("username") or 
        result.get("src_user") or 
        result.get("account") or
        "Unknown"
    )

    # Extract MD5 / SHA256 / File Hash
    file_hash = (
        result.get("file_hash") or 
        result.get("hash") or 
        result.get("md5") or 
        result.get("sha256")
    )

    return {
        "search_name": search_name,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "user": user,
        "file_hash": file_hash,
        "severity": severity,
        "raw_log": raw_log[:250] if raw_log != "N/A" else "N/A"
    }
