from flask import Flask, render_template, request, jsonify
import sqlite3, re, math
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

app = Flask(__name__)
DB = Path("cybershield.db")

SUSPICIOUS_WORDS = [
    "verify", "urgent", "login", "signin", "account", "password",
    "payment", "winner", "prize", "refund", "crypto", "bank",
    "security", "confirm", "suspended", "unlock"
]

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT, target TEXT, verdict TEXT,
            score INTEGER, reasons TEXT, created_at TEXT
        )""")

def url_features(url):
    u = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    p = urlparse(u)
    host = p.netloc.lower().split(":")[0]
    path = (p.path or "") + ("?" + p.query if p.query else "")
    return {
        "https": int(p.scheme.lower() == "https"),
        "length": len(u),
        "host_length": len(host),
        "dots": host.count("."),
        "hyphen": host.count("-"),
        "at": int("@" in u),
        "ip": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),
        "subdomains": max(0, len(host.split(".")) - 2),
        "digits": sum(c.isdigit() for c in host),
        "special": sum(c in "@?=&%_" for c in u),
        "suspicious_words": sum(w in u.lower() for w in SUSPICIOUS_WORDS)
    }

def analyze_url(url):
    f = url_features(url)
    reasons, score = [], 0
    if not f["https"]:
        score += 18; reasons.append("The URL does not use HTTPS.")
    if f["ip"]:
        score += 24; reasons.append("The host is an IP address instead of a normal domain.")
    if f["at"]:
        score += 20; reasons.append("The URL contains '@', which can hide the real destination.")
    if f["length"] > 90:
        score += 10; reasons.append("The URL is unusually long.")
    if f["subdomains"] >= 3:
        score += 12; reasons.append("The URL contains many subdomains.")
    if f["hyphen"] >= 3:
        score += 8; reasons.append("The domain contains several hyphens.")
    if f["suspicious_words"]:
        score += min(22, f["suspicious_words"] * 6)
        reasons.append("The URL contains words commonly associated with phishing.")
    if f["special"] >= 8:
        score += 8; reasons.append("The URL contains many special/query characters.")
    score = min(100, score)
    verdict = "SAFE" if score < 30 else ("SUSPICIOUS" if score < 60 else "MALICIOUS")
    if not reasons:
        reasons.append("No strong phishing indicators were detected by the local checks.")
    return verdict, score, reasons

def analyze_message(message):
    text = message.strip()
    low = text.lower()
    reasons, score = [], 0
    matches = [w for w in SUSPICIOUS_WORDS if re.search(r"\b"+re.escape(w)+r"\b", low)]
    urgency = sum(x in low for x in ["immediately", "within 24 hours", "act now", "urgent", "asap"])
    credential = sum(x in low for x in ["password", "otp", "pin", "cvv", "login", "credential"])
    money = sum(x in low for x in ["pay", "payment", "refund", "bank", "upi", "transfer"])
    link_count = len(re.findall(r"https?://\S+|www\.\S+", text))
    if matches:
        score += min(28, len(matches)*4)
        reasons.append("Contains phishing-related keywords.")
    if urgency:
        score += 20
        reasons.append("Uses urgency or pressure tactics.")
    if credential:
        score += 22
        reasons.append("Requests or mentions sensitive account credentials.")
    if money:
        score += 15
        reasons.append("Contains financial/payment-related language.")
    if link_count:
        score += min(15, link_count*5)
        reasons.append("Contains a link that should be verified before opening.")
    if "click" in low or "tap here" in low:
        score += 8
        reasons.append("Uses a call-to-action to click/tap a link.")
    score = min(100, score)
    verdict = "SAFE" if score < 30 else ("SUSPICIOUS" if score < 60 else "MALICIOUS")
    if not reasons:
        reasons.append("No strong phishing language indicators were detected.")
    return verdict, score, reasons

def save_scan(scan_type, target, verdict, score, reasons):
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO scans(scan_type,target,verdict,score,reasons,created_at) VALUES(?,?,?,?,?,?)",
                    (scan_type, target[:2000], verdict, score, " | ".join(reasons), datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/scan")
def scan():
    data = request.get_json(force=True)
    scan_type = data.get("type", "url")
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Please enter something to scan."}), 400
    if scan_type == "message":
        verdict, score, reasons = analyze_message(target)
    else:
        verdict, score, reasons = analyze_url(target)
    save_scan(scan_type, target, verdict, score, reasons)
    return jsonify({"verdict": verdict, "score": score, "reasons": reasons})

@app.get("/api/stats")
def stats():
    with sqlite3.connect(DB) as con:
        rows = con.execute("SELECT verdict, COUNT(*) FROM scans GROUP BY verdict").fetchall()
        recent = con.execute("SELECT scan_type,target,verdict,score,created_at FROM scans ORDER BY id DESC LIMIT 8").fetchall()
    counts = {"SAFE":0,"SUSPICIOUS":0,"MALICIOUS":0}
    for v,c in rows: counts[v] = c
    return jsonify({"counts": counts, "recent":[
        {"type":r[0],"target":r[1],"verdict":r[2],"score":r[3],"time":r[4]} for r in recent
    ]})

init_db()

if __name__ == "__main__":
    app.run(debug=True)
