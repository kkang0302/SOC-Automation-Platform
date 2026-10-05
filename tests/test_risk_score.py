import pytest
from parsers.splunk_parser import parse_splunk_alert
from engine.risk_score import calculate_risk_score

def test_splunk_parser():
    mock_payload = {
        "search_name": "Test Alert",
        "severity": "high",
        "result": {
            "src_ip": "1.2.3.4",
            "user": "alice"
        }
    }
    parsed = parse_splunk_alert(mock_payload)
    assert parsed["search_name"] == "Test Alert"
    assert parsed["src_ip"] == "1.2.3.4"
    assert parsed["user"] == "alice"
    assert parsed["severity"] == "high"

def test_risk_score_calculation():
    parsed = {"severity": "high"}
    abuse_data = {"abuse_score": 90}
    vt_data = {"malicious": 10}
    otx_data = {"otx_pulses": 3}

    res = calculate_risk_score(parsed, abuse_data, vt_data, otx_data)
    assert res["risk_score"] >= 80
    assert res["verdict"] == "CRITICAL"
