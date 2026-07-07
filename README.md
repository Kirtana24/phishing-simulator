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

### 2. 🛡️ Phishing Detection

#### JavaScript Detection (Frontend)
- Real-time analysis in your browser
- Detects urgency keywords, suspicious domains, and malicious links
- Provides risk scoring and red-flag identification

#### Python Detection (Backend)
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
│ └── simulator.js # Simulation + JavaScript detection
├── backend/ # Python detection engine
│ ├── detector.py # Main detection logic
│ ├── detector-output.png # Screenshot of output
│ ├── requirements.txt # Python dependencies
│ └── README.md # Backend documentation
└── README.md # This file

## 🚀 How to Run

### Frontend (Simulation + JavaScript Detection)
1. Open `index.html` in your browser
2. Select a scenario and start learning!
3. Detection results appear after you make a decision

### Backend (Python Detection)

bash

#Navigate to backend folder
cd backend

# Run the detector
 python detector.py

 The Python detector analyzes emails and provides:

🚨 Risk Score (0-100)
🔍 Detected Red Flags
📊 Confidence Level (High/Medium/Low)
✅ JSON Output for integration

📊 Detection Features
Feature	                                           Description
Urgency                                  Detection	Identifies keywords like "urgent", "immediately", "suspended"
Domain Analysis                          Checks for fake domains and spoofing attempts
URL Inspection	                          Detects IP addresses, suspicious TLDs, and malicious patterns
Risk Scoring	                            0-100 score with High/Medium/Low confidence
Red Flag Reporting	                      Lists all detected issues with explanations

OUTPUT SCREENSHOTS
Main 
homepage
<img width="1917" height="861" alt="image" src="https://github.com/user-attachments/assets/696fb27e-603c-42d2-985b-813760bacc23" />

Scenario 
(Bank alert)
<img width="1897" height="866" alt="image" src="https://github.com/user-attachments/assets/00434773-b32b-4d53-823d-7c90cab3d0a4" />
<img width="1897" height="633" alt="image" src="https://github.com/user-attachments/assets/73581717-5c35-403b-b63a-4ed308b255cc" />

Scenario 
(Social Media)
<img width="1898" height="867" alt="image" src="https://github.com/user-attachments/assets/06ed2459-db35-4b56-a0a9-eb9f23c6c753" />
<img width="1895" height="507" alt="image" src="https://github.com/user-attachments/assets/faf1878b-71d3-44c0-ba9b-2181913735b6" />


 Educational Purpose
⚠️ This tool is designed strictly for educational and awareness purposes. Use responsibly and only in authorized environments.

Author
Kirtana Minoy
GitHub: Kirtana24
