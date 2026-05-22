import requests
import config

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    
    return {
        "abuse_score": data["data"]["abuseConfidenceScore"],
        "total_reports": data["data"]["totalReports"],
        "country": data["data"]["countryCode"]
    }

def classify_threat(vt_result, abuse_result):
    score = 0
    if vt_result["malicious"] >= 5:
        score += 3
    elif vt_result["malicious"] >= 1:
        score += 2
    if abuse_result["abuse_score"] >= 50:
        score += 3
    elif abuse_result["abuse_score"] >= 10:
        score += 1
    if abuse_result["total_reports"] >= 10:
        score += 1

    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"