# 🛡️ AI-Powered Honeypot Threat Detection & Response System

---

## 📌 Overview

This project is an AI-assisted honeypot security framework deployed on a Linux virtual machine using the **Cowrie SSH Honeypot** and custom HTTP logging modules.

It captures real-world attack attempts, analyzes them using **Google Gemini AI**, and generates actionable threat intelligence with an analyst-in-the-loop response system.

---

## 🧠 System Architecture
Attacker
↓
Cowrie SSH / HTTP Honeypot
↓
Log Collection Layer
↓
AI Analysis Engine (Google Gemini)
↓
Threat Intelligence Enrichment
↓
Analyst Review & Decision
↓
IP Blocking via Socket-Based Response System


---

## 🚀 Key Features

### 🐚 Honeypot & Data Collection
- SSH honeypot using **Cowrie**
- HTTP request logging and attacker interaction capture
- Real-world malicious behavior recording

---

### 🤖 AI-Powered Security Analysis
- Log analysis using **Google Gemini**
- Attack classification (brute force, scanning, exploitation)
- Behavioral pattern detection
- Automated defensive recommendations

---

### 🔍 Threat Intelligence Enrichment
- WHOIS lookup for IP attribution
- GeoIP location analysis
- Reverse DNS resolution
- Nmap scanning for service detection
- Banner grabbing for exposed services

---

### ⚡ Response & Mitigation System
- Extracts malicious IPs from AI reports
- Analyst-in-the-loop approval system
- Socket-based IP blocking communication
- Dynamic threat response workflow

---

## 🧪 Attack Types Detected

- SSH brute-force attacks  
- HTTP login brute-force attempts  
- Port scanning activity  
- Directory brute-forcing  
- Command injection attempts  
- Reconnaissance behavior  

---

## 🖥️ Deployment Environment

- Linux Virtual Machine  
- Cowrie SSH Honeypot  
- Custom HTTP logging service  
- Python 3.10+  
- Wireshark & Nmap (analysis tools)  

---

## 🧠 AI Analysis Pipeline

1. Attacker interacts with honeypot  
2. Logs collected from SSH and HTTP modules  
3. Logs chunked and sent to Gemini AI  
4. AI performs:
   - Attack classification  
   - Pattern detection  
   - IP behavior analysis  
   - Defensive recommendations  
5. Reports generated per chunk + aggregated summary  
6. Extracted IPs passed to threat intelligence + response engine  

---

## 🛡️ Response Workflow

- Extract malicious IPs from AI reports  
- Run threat intelligence checks (WHOIS, GeoIP, Nmap)  
- Analyst reviews results  
- Approved IPs are sent via socket to blocking system  

---
## 📁 Project Structure

```
AI-Honeypot-Security-System/
│
├── honeypot/
│   ├── cowrie_config/          # Cowrie honeypot configuration files
│   └── logs/
│       ├── cowrie.json         # SSH honeypot logs (newline-delimited JSON)
│       └── http.log            # HTTP honeypot logs (JSON-lines or combined format)
│
├── ai_engine/
│   ├── gemini_analyzer.py      # Core Gemini API analysis logic
│   └── prompt_templates.py     # All LLM prompts (edit here to tune analysis)
│
├── threat_intel/
│   ├── probes.py               # Active probes: whois, geoip, ping, nmap, banner
│   └── geoip.py                # GeoIP helpers & probe summary printer
│
├── response_engine/
│   ├── ip_blocker_client.py    # Client: sends IPs to the socket server for blocking
│   └── socket_server.py        # Server: receives IPs and applies firewall rules
│
├── notebooks/
│   └── honeypot_analysis.ipynb # Main notebook — end-to-end pipeline
│
├── reports/                    # Auto-generated AI analysis reports
├── requirements.txt
└── README.md
```

---
## 📦 Installation

```bash
pip install -r requirements.txt

#Usage
python ai_engine/gemini_analyzer.py
python threat_intel/probes.py
python response_engine/ip_blocker_client.py
