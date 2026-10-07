# CyberShield — Project Report

## 1. Title
**CyberShield: AI-Assisted Phishing and Malicious URL Detection System**

## 2. Abstract
CyberShield is a web-based cybersecurity application that helps users identify potentially dangerous URLs and phishing messages. The system extracts security indicators such as HTTPS usage, IP-based hosts, URL length, suspicious keywords, subdomains and special characters. For messages, it looks for urgency, credential requests, financial language and suspicious links. These indicators are combined into an explainable risk score from 0 to 100 and classified as Safe, Suspicious or Malicious.

## 3. Problem Statement
Phishing attacks frequently use deceptive URLs and social-engineering messages to trick users into revealing credentials or financial information. Ordinary users may not recognize these indicators. A simple explainable detection tool can improve awareness and provide a first layer of screening.

## 4. Objectives
- Detect common phishing indicators in URLs.
- Detect social-engineering indicators in messages.
- Produce an understandable risk score.
- Explain the reasons behind the classification.
- Maintain a local history of scans.
- Provide a dashboard for demonstration.

## 5. Technologies
Python, Flask, SQLite, HTML, CSS, JavaScript.

## 6. Methodology
Input → Feature Extraction → Risk Scoring → Classification → Explanation → Database Storage → Dashboard.

## 7. URL Features
HTTPS, IP address, URL length, number of subdomains, hyphens, @ symbol, digits, special characters and phishing-related words.

## 8. Message Features
Urgency language, credential requests, financial language, suspicious keywords, links and click/tap calls to action.

## 9. Classification
0–29: SAFE
30–59: SUSPICIOUS
60–100: MALICIOUS

## 10. Advantages
- Easy to use.
- Explainable results.
- No external API required.
- Local database.
- Suitable for cybersecurity awareness demonstrations.

## 11. Limitations
- It is not a replacement for commercial threat intelligence.
- A sophisticated phishing site may evade simple rules.
- Domain reputation and real-time malware databases are not included.
- A risk score is not proof that a website is malicious.

## 12. Future Scope
- Integrate VirusTotal or another approved threat-intelligence API.
- Add a trained machine-learning classifier using a real public phishing dataset.
- Add browser-extension support.
- Add WHOIS/domain-age checks.
- Add email-header analysis.
- Add user authentication and role-based access.
