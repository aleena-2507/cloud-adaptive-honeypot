# Cloud-Based Adaptive Honeypot for Intrusion Detection
# and Attack Behaviour Analysis

## 1. Project Overview

This project uses the Cowrie SSH/Telnet honeypot to record
suspicious interactions in a controlled environment. Python
processes the event logs, analyses attack behaviour, assigns
risk scores, and recommends an appropriate monitoring level.

## 2. Objectives

- Capture SSH honeypot interactions using Cowrie.
- Analyse login attempts and commands from recorded logs.
- Assign risk scores using rule-based analysis.
- Recommend monitoring actions based on risk levels.
- Generate CSV, text, and JSON reports.

## 3. Technologies Used

- Ubuntu Linux
- Python
- Cowrie SSH/Telnet Honeypot
- Pandas
- NumPy
- JSON and CSV
- VirtualBox

## 4. Project Workflow

Cowrie Honeypot
       |
       v
Log Collection and Analysis
       |
       v
Attack Behaviour Analysis
       |
       v
Risk Scoring
       |
       v
Adaptive Monitoring Recommendation
       |
       v
Report Generation

## 5. Main Python Modules

- src/analyze_logs.py
- src/attack_analysis.py
- src/adaptive_response.py

## 6. How to Run

Activate the project environment:

    cd ~/adaptive-honeypot
    source .venv/bin/activate

Run the modules in order:

    python src/analyze_logs.py
    python src/attack_analysis.py
    python src/adaptive_response.py

## 7. Generated Reports

- reports/cowrie_events.csv
- reports/analysis_summary.txt
- reports/attack_analysis.csv
- reports/attack_analysis.txt
- reports/adaptive_response.json

## 8. Current Test Results

A local Cowrie test session produced 13 recorded events
from one source IP. The rule-based analyser assigned a
risk score of 10/100 (LOW) and recommended NORMAL monitoring.

A separate synthetic test produced a high-risk score of
80/100, demonstrating the higher-risk detection rules.

These results represent local and synthetic testing,
not confirmed attacks from external systems.

## 9. Limitations and Future Work

- The adaptive module currently recommends monitoring
  actions; it does not automatically block network traffic.
- Cloud deployment has not yet been validated.
- Additional testing with varied event patterns is needed.
- Future work may include controlled cloud deployment,
  stronger validation, and additional reporting features.

## 10. Safety

Use the honeypot only in an authorised, controlled
environment. Do not expose it publicly without appropriate
isolation and security controls.
