from flask import Flask, request, jsonify
from threat_agent import check_virustotal, check_abuseipdb, classify_threat
from gemini_summary import generate_report
from database import init_db, log_threat

app = Flask(__name__)
init_db()

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    ip = data.get("ip")
    
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    
    # Step 1 — Query both APIs
    vt_result = check_virustotal(ip)
    abuse_result = check_abuseipdb(ip)
    
    # Step 2 — Classify threat using ML logic
    threat_level = classify_threat(vt_result, abuse_result)
    
    # Step 3 — Generate Gemini report
    report = generate_report(ip, vt_result, abuse_result, threat_level)
    
    # Step 4 — Log to SQLite
    log_threat(ip, vt_result, abuse_result, threat_level, report)
    
    # Step 5 — Return JSON response
    return jsonify({
        "ip": ip,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "threat_level": threat_level,
        "report": report
    })
@app.route("/analyze/batch", methods=["POST"])
def analyze_batch():
    data = request.get_json()
    ips = data.get("ips", [])
    
    if not ips:
        return jsonify({"error": "List of IPs is required"}), 400
    
    results = []
    for ip in ips:
        vt_result = check_virustotal(ip)
        abuse_result = check_abuseipdb(ip)
        threat_level = classify_threat(vt_result, abuse_result)
        report = generate_report(ip, vt_result, abuse_result, threat_level)
        log_threat(ip, vt_result, abuse_result, threat_level, report)
        results.append({
            "ip": ip,
            "threat_level": threat_level,
            "abuse_score": abuse_result["abuse_score"],
            "malicious_detections": vt_result["malicious"],
            "report": report
        })
    
    return jsonify({
        "total_analyzed": len(ips),
        "results": results
    })
@app.route("/logs", methods=["GET"])
def logs():
    import sqlite3
    conn = sqlite3.connect("threat_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(debug=True)