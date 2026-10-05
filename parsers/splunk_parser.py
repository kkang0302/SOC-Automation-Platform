def parse_splunk_alert(payload):
    """
    Parses and normalizes raw Splunk Webhook Alert payload into a standard SOC schema.
    """
    if not isinstance(payload, dict):
        return {
            "search_name": "Unknown Alert Payload",
            "src_ip": None,
            "dest_ip": None,
            "user": "Unknown",
            "file_hash": None,
            "severity": "medium"
        }

    # Splunk alerts store search results inside 'result' or top-level payload
    result = payload.get("result", payload)

    search_name = payload.get("search_name") or payload.get("rule_name") or "Splunk Security Alert"
    severity = str(payload.get("severity") or result.get("severity") or "medium").lower()

    # Extract source IP
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
        "severity": severity
    }
