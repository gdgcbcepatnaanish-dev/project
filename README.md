# CyberShield — AI-Assisted Phishing & Malicious URL Detector

A college-level cybersecurity project built with Python Flask, SQLite, HTML/CSS/JavaScript.

## Features
- URL risk analysis
- Phishing message analysis
- Explainable risk score from 0–100
- SAFE / SUSPICIOUS / MALICIOUS classification
- SQLite scan history
- Live dashboard counters
- Clean cybersecurity-themed interface
- Runs locally without external APIs

## Run on Windows
1. Install Python 3.10+.
2. Open this project folder in IBM Bob.
3. Open a terminal.
4. Run:
   `python -m venv .venv`
5. Activate:
   `.venv\Scripts\activate`
6. Install:
   `pip install -r requirements.txt`
7. Start:
   `python app.py`
8. Open the address shown by Flask, normally `http://127.0.0.1:5000`.

## Suggested demo URLs
Safe-ish:
https://www.wikipedia.org

Suspicious:
http://secure-login-example.com/verify-account

High risk:
http://192.168.1.50/login?verify=password

## Important
This is an educational detector using heuristic indicators. It should not be presented as a production antivirus or a definitive malware scanner.
