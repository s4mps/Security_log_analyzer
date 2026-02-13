# 🔐 Security Log Analyzer

A robust, Python-based digital forensics tool designed to transform raw system authentication logs into actionable security intelligence. This tool automates the detection of frequency-based threats like Brute-Force attacks, Credential Stuffing, and Port Scanning using optimized data structures.

---

## 🚀 Key Features

- **Real-Time Threat Detection:** Utilizes a **Sliding Window** algorithm to identify high-frequency attack patterns within specific timeframes.
- **Modular Architecture:** Decoupled design separating the **Ingestion**, **Analysis**, **Storage**, and **Visualization** layers.
- **Optimized Performance:** Implements a custom **Circular Buffer (deque)** to ensure constant time complexity ($O(1)$) for frequency analysis.
- **Data Persistence:** Integrated **SQLite** database to maintain a permanent audit trail of all security alerts for forensic review.
- **Interactive Dashboard:** A user-friendly **Tkinter GUI** with color-coded syntax highlighting (Red for Critical, Green for Success).

---

## 🛠️ Technical Stack

- **Language:** Python 3.10+
- **Database:** SQLite3
- **GUI Framework:** Tkinter
- **Core Modules:** `re` (Regex), `collections` (Deque), `datetime`

---

## 📂 Project Structure

```text
📁 SECURITY-LOG-ANALYSER/
├── 📄 auth_analyzer.py      # Core detection engine & logic
├── 📄 auth_gui.py           # Tkinter dashboard implementation
├── 📄 auth_log_generator.py # Simulation script for testing patterns
├── 📄 security_logs.db      # SQLite database for alert persistence
└── 📄 requirements.txt      # List of dependencies (if any)

⚙️ Installation & Usage
1. Clone the Repository
Bash

git clone [https://github.com/s4mps/security-Log-Analyzer.git](https://github.com/s4mps/Security-Log-Analyzer.git)
cd security-log-analyzer

2. Run the Analyzer

Launch the graphical dashboard:
Bash

python auth_gui.py

3. Generate Test Data (Optional)

To test the detection logic without a live server log, use the simulation script:
Bash

python auth_log_generator.py

🛡️ Detection Capabilities

The analyzer is pre-configured to detect the following anomalies:
Threat Type	Logic Description
Brute-Force	Detects >5 failed attempts from a single IP within 30 seconds.
Dictionary Attack	Flags repeated attempts on sensitive usernames like admin or root.
Credential Stuffing	Tracks one IP testing multiple unique usernames in rapid succession.
Port Scanning	Identifies IPs generating multiple connection errors (e.g., "Connection closed").
Abnormal Hours	Flags successful logins occurring between 1:00 AM and 5:00 AM.
🧪 Testing

The project includes a comprehensive suite of 23 unit tests to validate the mathematical accuracy of the sliding window and regex parsing.

To run the tests:
Bash

python -m unittest test_auth_analyzer.py

🔮 Future Enhancements

    Real-Time Monitoring: Transitioning from static logs to live traffic analysis via system sockets.

    Machine Learning: Integrating anomaly detection for "zero-day" threat identification.

    IPS Integration: Automated firewall response to block malicious IPs in real-time.
```
