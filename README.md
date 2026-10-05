# 🛡️ SOC Automation Platform (SOAR Engine)

> **A Lightweight, Event-Driven Security Orchestration, Automation, and Response (SOAR) Engine built for modern Security Operations Centers (SOC).**

---

## 📌 Architecture & Workflow

```text
[ Attacker / Log Generator ] ──> [ SIEM (Splunk/Suricata) ] ──> [ Webhook Alert ]
                                                                       │
                                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    SOC Automation Platform (Python SOAR)                     │
│                                                                              │
│  1. Ingest Webhook Alert ──> 2. Parse & Normalize Schema                     │
│  3. Threat Intelligence Enrichment (AbuseIPDB, VirusTotal, AlienVault OTX)    │
│  4. Compute Risk Verdict Engine (LOW, MEDIUM, HIGH, CRITICAL)               │
│  5. Dispatch Rich Discord Notification Cards                                 │
│  6. Active Firewall Response (Automated IP Containment via iptables)        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

* **SIEM Webhook Integration**: Native webhook listener endpoint (`/api/v1/alert`) parsing Splunk alerts.
* **Multi-Source Threat Intelligence**:
  * **AbuseIPDB API v2**: IP confidence score, country code, ISP, total reports.
  * **VirusTotal API v3**: File hash analysis and engine detection counts.
  * **AlienVault OTX API**: Indicator pulse associations and threat tags.
* **Risk Scoring & Decision Engine**: Evaluates Threat Intel metadata + SIEM baseline severity to produce an actionable verdict (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* **Rich Notification Dispatch**: Beautiful embedded alert cards to Discord webhooks.
* **Automated Containment Playbook**: Native active firewall response (`iptables` / `netsh`) for high-risk threats.

---

## 🛠️ Quick Start Guide

### 1. Clone Repository & Setup Virtual Environment
```bash
git clone https://github.com/kkang0302/SOC-Automation-Platform.git
cd SOC-Automation-Platform

python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your API keys:
```bash
cp .env.example .env
nano .env
```

### 3. Run Webhook Server
```bash
python3 server.py
```
Server starts on `http://0.0.0.0:5000`. Test health status:
```bash
curl http://127.0.0.1:5000/health
```

---

## 🧪 Testing & Verification

Run automated test suite:
```bash
pytest
```

Simulate a Splunk Alert payload via cURL:
```bash
curl -X POST http://127.0.0.1:5000/api/v1/alert \
     -H "Content-Type: application/json" \
     -d @tests/mock_payloads/brute_force_alert.json
```

---

## 📜 License
Developed as part of the Enterprise SOC & Automation Portfolio Project.
