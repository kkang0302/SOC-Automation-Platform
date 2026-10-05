from config.settings import Config

def calculate_risk_score(parsed_alert, abuse_data=None, vt_data=None, otx_data=None):
    """
    Computes a overall Risk Score (0-100) and Verdict (LOW, MEDIUM, HIGH, CRITICAL)
    based on threat intelligence enrichment data and SIEM severity.
    """
    score = 0
    reasons = []

    # 1. AbuseIPDB Scoring
    if abuse_data and isinstance(abuse_data, dict):
        abuse_score = abuse_data.get("abuse_score", 0)
        if abuse_score >= 80:
            score += 45
            reasons.append(f"AbuseIPDB high confidence abuse score ({abuse_score}%)")
        elif abuse_score >= 30:
            score += 25
            reasons.append(f"AbuseIPDB moderate abuse score ({abuse_score}%)")
        elif abuse_score > 0:
            score += 10
            reasons.append(f"AbuseIPDB low confidence abuse score ({abuse_score}%)")

    # 2. VirusTotal Scoring
    if vt_data and isinstance(vt_data, dict):
        malicious_count = vt_data.get("malicious", 0)
        if malicious_count >= 5:
            score += 50
            reasons.append(f"VirusTotal detected malicious by {malicious_count} engines")
        elif malicious_count > 0:
            score += 30
            reasons.append(f"VirusTotal detected malicious by {malicious_count} engine(s)")

    # 3. AlienVault OTX Scoring
    if otx_data and isinstance(otx_data, dict):
        pulse_count = otx_data.get("otx_pulses", 0)
        if pulse_count > 0:
            score += min(pulse_count * 10, 25)
            reasons.append(f"AlienVault OTX associated with {pulse_count} threat pulse(s)")

    # 4. SIEM Baseline Severity Weight
    siem_severity = parsed_alert.get("severity", "medium").lower()
    if siem_severity == "critical":
        score += 25
        reasons.append("SIEM Alert Severity: CRITICAL")
    elif siem_severity == "high":
        score += 15
        reasons.append("SIEM Alert Severity: HIGH")
    elif siem_severity == "medium":
        score += 5

    # Cap score at 100 max
    final_score = min(score, 100)

    # Determine Verdict using configured thresholds
    if final_score >= Config.RISK_CRITICAL:
        verdict = "CRITICAL"
    elif final_score >= Config.RISK_HIGH:
        verdict = "HIGH"
    elif final_score >= 25:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    if not reasons:
        reasons.append("Baseline alert evaluation completed with clean threat intelligence.")

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "reasons": reasons
    }
