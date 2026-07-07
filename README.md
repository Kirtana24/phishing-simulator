# 🎣 Phishing Attack Simulation and Detection

> An integrated cybersecurity platform that simulates realistic phishing attacks to test user awareness, combined with automated detection mechanisms using Python to identify and classify malicious emails.

## 🚀 Live Demo
[View the live demo](https://Kirtana24.github.io/phishing-simulator)

---

## 📋 Project Overview

This project has **two core components**:

### 1. 🎯 Phishing Simulation (Frontend)
- 6+ realistic phishing scenarios (Banking, Social Media, Tech Support, Shopping)
- Interactive decision-making with instant feedback
- Gamified learning with score tracking
- Educational red-flag identification

### 2. 🛡️ Phishing Detection (Backend - Python)
- **Email Content Analysis** – Detects urgency keywords, generic greetings, and threats
- **Sender Analysis** – Identifies suspicious domains and spoofing attempts
- **URL Inspection** – Detects malicious links, IP addresses, and suspicious TLDs
- **Risk Scoring** – Automated scoring (0-100) with confidence levels
- **JSON Output** – Machine-readable results for integration

---

## 🛠️ Technologies Used

| Component | Technologies |
|-----------|--------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python 3 |
| **Detection** | Pattern matching, keyword analysis, URL inspection |

---

## 📂 Project Structure
phishing-simulator/
├── index.html # Main simulation interface
├── css/
│ └── style.css # Styling & responsive design
├── js/
│ └── simulator.js # Simulation logic & frontend detection
├── backend/ # Python detection engine
│ ├── detector.py # Main detection logic
│ ├── requirements.txt # Python dependencies
│ └── README.md # Backend documentation
└── README.md # This file

📊 Detection Features
Feature	Description
Urgency Detection	Identifies keywords like "urgent", "immediately", "suspended"
Domain Analysis	Checks for fake domains and spoofing attempts
URL Inspection	Detects IP addresses, suspicious TLDs, and malicious patterns
Risk Scoring	0-100 score with High/Medium/Low confidence
Red Flag Reporting	Lists all detected issues with explanations

📊 Features
✅ Risk scoring (0-100)
✅ Red-flag identification
✅ URL analysis
✅ Domain spoofing detection
✅ Human-readable reports
✅ JSON output

SAMPLE OUTPUT
╔══════════════════════════════════════════════════════════════╗
║                    PHISHING DETECTION REPORT                 ║
╠══════════════════════════════════════════════════════════════╣
║  Status: 🚨 PHISHING DETECTED
║  Risk Score: 85/100
║  Confidence: HIGH
║  Is Phishing: True
╠══════════════════════════════════════════════════════════════╣
║  🔍 Detected Red Flags:                                     ║
║    • ⚠️ Contains keyword: "urgent"
║    • ⚠️ Suspicious sender: chase-bank.secure.com
║    • ⚠️ Generic greeting: "dear customer"
╚══════════════════════════════════════════════════════════════╝

👤 Author
Kirtana Minoy
GitHub: Kirtana24
