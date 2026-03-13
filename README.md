# Aegis-Omni: Monolithic Offensive Security Framework

Aegis-Omni is a high-speed, integrated offensive security framework designed for bug bounty hunters and red teamers. It provides a comprehensive suite of tools for reconnaissance, OSINT, fuzzing, and vulnerability exploitation within a single, monolithic Python file.

## 🚀 Features

- **Module 1: Reconnaissance (The Eye)**: Passive & active subdomain discovery, DNS resolution, and asset mapping.
- **Module 2: Dorking & OSINT (The Ghost)**: Automated Google dorking and sensitive information gathering.
- **Module 3: Fuzzing (The Driller)**: Intelligent directory and parameter fuzzing with soft-404 detection.
- **Module 4: Exploitation (The Striker)**: Automated vulnerability detection for SQLi, XSS, SSTI, XXE, and more.
- **Module 5: Validator (The Brain)**: Zero-false-positive validation using heuristic analysis and differential responses.
- **GUI & UX**: Modern Tkinter-based interface with real-time logging, dashboards, and reporting.

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/lhindindua-collab/REC.git
   cd REC
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   playwright install
   ```

3. Run Aegis-Omni:
   ```bash
   python aegis_omni.py
   ```

## ⚙️ Configuration

Aegis-Omni stores its configuration in `config.json`. You can enter your API keys for Shodan, Censys, VirusTotal, and others directly through the **Settings** tab in the GUI.

## 🛡️ Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain permission before testing any target.
