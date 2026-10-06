# 🛡️ SOC Automation Platform (SOAR Engine)

> **A Lightweight, Event-Driven Security Orchestration, Automation, and Response (SOAR) Engine built for modern Security Operations Centers (SOC). Supports both Splunk Enterprise (Webhook Mode) and Splunk Free License (REST API Poller Mode).**

---

## 📌 Architecture & Workflow

```text
[ Attacker / Kali Linux ] ──> [ SIEM (Splunk Free / Enterprise) ]
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               │                                                         │
    (Option A: Webhook Alert)                                (Option B: REST API Poller 10s)
               │                                                         │
               ▼                                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          SOC Automation Platform (Python SOAR)                          │
│                                                                                         │
│  1. Ingest Alert / Poll Log ──> 2. Parse & Normalize Schema                             │
│  3. Threat Intelligence Enrichment (AbuseIPDB, VirusTotal, AlienVault OTX)               │
│  4. Compute Risk Verdict Engine (LOW, MEDIUM, HIGH, CRITICAL)                          │
│  5. Dispatch Rich Discord Notification Embed Cards                                      │
│  6. Active Firewall Response (Automated IP Containment via iptables / netsh)            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

* **Dual Operation Modes**:
  * **Webhook Listener Server** (`server.py`): Native HTTP POST endpoint (`/api/v1/alert`) for Splunk Enterprise / Developer License.
  * **Splunk Free REST API Poller** (`pollers/splunk_poller.py`): Automated periodic polling (10s) for Splunk Free License (which lacks Webhook Alert Actions).
* **Multi-Source Threat Intelligence**:
  * **AbuseIPDB API v2**: IP confidence score, country code, ISP, total abuse reports.
  * **VirusTotal API v3**: File hash analysis and engine detection counts.
  * **AlienVault OTX API**: Indicator pulse associations and threat tags.
* **Risk Scoring & Decision Engine**: Evaluates Threat Intel metadata + SIEM baseline severity to produce an actionable verdict (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* **Rich Discord Notifications**: Embedded alert cards formatted with color-coded risk levels.
* **Automated Containment Playbook**: Native active firewall response (`iptables` / `netsh`) for high-risk threats (`HIGH` & `CRITICAL`).

---

## 🎯 Supported Attack Detections & MITRE ATT&CK Mapping

The platform automatically detects, enriches, and mitigates the following attack vectors:

| Attack Vector | MITRE ATT&CK Technique | Detection Source | Threat Intel Engine | Automated SOAR Response |
| :--- | :--- | :--- | :--- | :--- |
| **SSH / Credential Brute-Force** | `T1110` - Brute Force | Linux Auth Logs / Sysmon | AbuseIPDB API v2 | 🚨 Discord Card + 🚫 **Auto Block IP (`iptables`)** |
| **Network Recon & Port Scan** | `T1595` / `T1046` Active Scan | Suricata NIDS / Nmap Logs | AlienVault OTX API | 🚨 Discord Card + 🚫 **Auto Block IP (`iptables`)** |
| **Malware & Suspicious Executable** | `T1204` User Execution | Sysmon Event ID 1 / 11 | VirusTotal API v3 | 🚨 Discord Card + 🏷️ **Malware Verdict Tag** |
| **Malicious / C2 IP Traffic** | `T1071` Application Protocol | Web Server / Firewall Logs | AbuseIPDB + OTX | 🚨 Discord Card + 🚫 **Auto Block IP (`iptables`)** |
| **Web Exploits (SQLi, Directory Traversal)** | `T1190` Exploit Public App | Apache / Suricata HTTP Logs | AbuseIPDB API v2 | 🚨 Discord Card + 📄 **Raw Log Context Snippet** |

---

## 🛠️ Environment Setup & Installation

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

Example `.env` configuration:
```env
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ALIENVAULT_OTX_API_KEY=your_otx_key
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_id/your_token

RISK_THRESHOLD_HIGH=50
RISK_THRESHOLD_CRITICAL=80
FLASK_PORT=5000
LOG_LEVEL=INFO
```

---

## 🧪 Comprehensive 3-Level Testing Guide (Hướng Dẫn Kiểm Thử 3 Cấp Độ)

---

### 🟢 Level 1: Unit Testing (Kiểm Thử Đơn Vị)
> **Mục tiêu**: Kiểm tra thuật toán tính điểm rủi ro và parser logic hoạt động chính xác một cách độc lập.

**Lệnh thực thi:**
```bash
PYTHONPATH=. pytest
```
* **Kỳ vọng**: Mọi bài test trong `tests/test_risk_score.py` đều báo **`PASSED`**.

---

### 🟡 Level 2: Integration Testing via Mock Webhook (Kiểm Thử Tích Hợp)
> **Mục tiêu**: Giả lập cảnh báo tấn công Brute Force để kiểm tra luồng tiếp nhận, tra cứu Threat Intel API và bắn tin nhắn cảnh báo về Discord.

**1. Mở Terminal 1 (Khởi chạy Webhook Server):**
```bash
python3 server.py
```

**2. Mở Terminal 2 (Gửi Payload tấn công mẫu bằng cURL):**
```bash
curl -X POST http://127.0.0.1:5000/api/v1/alert \
     -H "Content-Type: application/json" \
     -d @tests/mock_payloads/brute_force_alert.json
```

**3. Kết quả xác minh (Verification):**
- **Terminal 1**: Đưa ra log `Risk Evaluation Result: Verdict=CRITICAL | Score=95/100`.
- **Discord Channel**: Nhận được một thẻ Card màu Đỏ chứa chi tiết IP `185.220.101.5` cùng thông tin tra cứu AbuseIPDB.

---

### 🔴 Level 3: End-to-End Real Attack & Auto Containment (Kiểm Thử Toàn Trình)
> **Mục tiêu**: Thực hiện tấn công thực tế từ máy **Kali Linux** sang **Splunk Server**, tự động quét log, phát hiện sự cố, bắn cảnh báo Discord và kích hoạt `iptables DROP` chặn IP nguồn tấn công.

**1. Khởi chạy Splunk Free Poller trên Splunk Server (`192.168.10.10`):**
```bash
python3 pollers/splunk_poller.py
```

**2. Thực hiện tấn công từ máy Kali Linux (`192.168.10.30`):**
```bash
nmap -sV -p 22,80,8000 192.168.10.10
```
*Hoặc thực hiện SSH Brute Force qua Hydra:*
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.10.10
```

**3. Kết quả xác minh (Verification):**
- Trong vòng 10 giây, Terminal `splunk_poller.py` sẽ in log nhận diện cuộc tấn công từ Splunk.
- Kênh Discord nhận thẻ Cảnh báo sự cố mức `CRITICAL`.
- **Kiểm tra Rule Firewall đã tự động chặn IP Kali Linux**:
  ```bash
  sudo iptables -L -n -v | grep DROP
  ```
  *(Kết quả sẽ xuất hiện dòng rule `DROP all -- 192.168.10.30`)*.
- **Gỡ bỏ block sau khi test thành công**:
  ```bash
  sudo iptables -D INPUT -s 192.168.10.30 -j DROP
  ```

---

## 📜 License & Portfolio
Developed as part of the Enterprise SOC Monitoring & Automation Portfolio Project.
