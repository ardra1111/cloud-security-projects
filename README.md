# Cloud Security Projects

This repository contains two practical cloud security projects demonstrating system hardening, log monitoring, and intrusion detection using Python and Linux.

---

## Project 1: Simulated Cloud Server Hardening & Threat Detection

**Overview:**  
Simulated a cloud VM environment using a Linux terminal and Python to practice server hardening and detect potential threats.

**Key Features:**  
- Hardened SSH configuration: disabled root login, changed default port, created restricted users  
- Simulated brute-force login attempts using fake `auth.log` entries  
- Developed a Python detection script using a 5-minute rolling window to identify suspicious IPs  
- Produced **professional incident reports** with detected attacks and recommended remediation  

**Skills & Tools:**  
- Linux commands for server hardening  
- Python for log parsing and detection  
- Log analysis & incident reporting  

---

## Project 2: Login Intrusion Detection System (Python)

**Overview:**  
Built a Python-based IDS to monitor login events and detect abnormal patterns, including brute-force attacks and impossible travel scenarios.

**Key Features:**  
- Parsed login logs to detect ≥5 failed login attempts within 5 minutes  
- Implemented offline geo-mapping and haversine distance calculations to flag impossible travel  
- Generated JSON alerts and Markdown incident reports with suggested remediation steps  
- Mimicked **SIEM-lite playbook rules** to simulate real-world intrusion detection  

**Skills & Tools:**  
- Python (stdlib), regex, and data structures  
- Log parsing and analysis  
- Basic threat modeling and incident reporting  
- Distance math for geolocation anomaly detection  

--- 
