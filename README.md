# 🛡️ Enterprise Mini SIEM & SOAR Telemetry Hub

> A lightweight, full-stack Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platform built with Python, Flask, and SQLite.

---

## 🌐 Live Demo & Repository
* **GitHub Repository:** [https://github.com/arnav0631/SIEM_1](https://github.com/arnav0631/SIEM_1)
* **Live App URL:** [https://siem-1-356x.onrender.com]

---


## 📌 Key Features

* **Modular Micro-Architecture:** Cleanly separated routing (`app.py`), database handling (`database.py`), log streaming (`generate_logs.py`), and detection logic (`detector.py`).
* **Stateful Time-Window Correlation:** Correlates `LOGIN_FAILED` events over a **30-second sliding window** to detect brute-force attacks accurately.
* **Log Volume Anomaly Detection:** Identifies rapid log spikes ($\ge 5$ logs in 10 seconds) to flag potential DoS or automated scanning activity.
* **Automated Threat Containment (SOAR):** Automatically bans malicious IP addresses in the SQLite database upon `CRITICAL` breach detection.
* **Interactive Control Panel:** Toggle detection rules (`BRUTE_FORCE`, `POWERSHELL`, `PORT_SCAN`, `ANOMALY_SPIKE`) on and off live from the dashboard.
* **Time-Aware System Health:** System status automatically resets to `SYSTEM STATUS: SECURE` if no critical threats occur within 60 seconds.
* **Compliance Telemetry Export:** Stream raw log history directly to a downloadable CSV report.

---

## 📁 Project Architecture

```text
mini_siem/
│── app.py                 # Core Flask server & API routes
│── database.py            # SQLite database manager & schemas
│── requirements.txt       # Dependencies for deployment
│── Procfile               # Render deployment start command
│── README.md              # Project documentation
│── modules/
│   │── generate_logs.py   # Event stream synthesizer
│   └── detector.py        # Correlation engine & detection logic
└── templates/
    └── index.html         # Enterprise Cyber SOC Dashboard