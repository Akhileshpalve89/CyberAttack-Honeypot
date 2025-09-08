# 🛡️ CyberAttack-Honeypot

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Research%20Project-orange.svg)](#)
[![Made with Paramiko](https://img.shields.io/badge/Made%20with-Paramiko-yellow.svg)](http://www.paramiko.org/)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen.svg)](#)

> **"Track and Trace: Investigating Cyber Attacks Using Honeypot"** — A Python-based SSH Honeypot that detects, logs, and analyzes malicious login attempts to enhance cybersecurity defenses.

---

## 📜 Project Overview
Honeypots are **decoy systems** made to appear as legitimate servers, intentionally vulnerable to attract attackers.  
They are deployed to:
- Divert attackers from critical systems  
- Study attack vectors, tools, and techniques  
- Improve defensive strategies using **real threat intelligence**  

This honeypot:
- Simulates a vulnerable SSH server
- Captures usernames and passwords from connection attempts
- Logs activities for forensic analysis

---

## 📂 Repository Structure
CyberAttack-Honeypot/
│
├── honeypot.py # Main Python SSH honeypot script
├── Final_Project_Presentation.pptx # Project presentation slides
├── key # SSH private key (generated locally)
└── README.md # Project documentation

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/CyberAttack-Honeypot.git
cd CyberAttack-Honeypot
```
### 2️⃣ Install Dependencies
```bash
pip install paramiko
```
### 3️⃣ Generate SSH Key
```bash
ssh-keygen -t rsa -b 2048 -f key
```
### 4️⃣ Run the Honeypot
```bash
python honeypot.py
```
### Default Configuration
```yaml
IP: 127.0.0.1
Port: 2222
```

### 🧪 Testing the Honeypot
```bash
ssh testuser@127.0.0.1 -p 2222
```
# 📊 Features

- 🔐 SSH Authentication Capture — Logs usernames/passwords

-⚡ Threaded Connections — Handles multiple attempts simultaneously

-🎯 Customizable — Modify scripts to simulate more services

-📡 Threat Intelligence Ready — Integrates into analysis workflows


## Workflow Diagram
<img width="2816" height="1592" alt="NoteGPT-Flowchart-1757320644931" src="https://github.com/user-attachments/assets/127c5ffa-ffc2-4069-b3d3-33e607575907" />

# 📌 Academic Context

## Title: Track and Trace: Investigating Cyber Attacks Using Honeypot
### Team Members:

- Akhilesh Palve

- Shubham Dorik 

- Sahil Badhe

Guide: Prof. Smita Gumaste
Department: Computer Science & Engineering, MITSOE, Loni Kalbhor


# ⚠️ Disclaimer

This project is for educational and research purposes only.
Do not deploy this honeypot on a public network without explicit permission.

