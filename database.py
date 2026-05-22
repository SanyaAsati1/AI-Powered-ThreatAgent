import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("threat_logs.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            malicious INTEGER,
            suspicious INTEGER,
            harmless INTEGER,
            abuse_score INTEGER,
            total_reports INTEGER,
            country TEXT,
            threat_level TEXT,
            report TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_threat(ip, vt_result, abuse_result, threat_level, report):
    conn = sqlite3.connect("threat_logs.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO threat_logs 
        (ip, malicious, suspicious, harmless, abuse_score, total_reports, country, threat_level, report, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        ip,
        vt_result["malicious"],
        vt_result["suspicious"],
        vt_result["harmless"],
        abuse_result["abuse_score"],
        abuse_result["total_reports"],
        abuse_result["country"],
        threat_level,
        report,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()