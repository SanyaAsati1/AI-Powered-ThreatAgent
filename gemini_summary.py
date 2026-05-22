from google import genai
import config
import time

client = genai.Client(api_key=config.GEMINI_API_KEY)

def generate_report(ip, vt_result, abuse_result, threat_level):
    prompt = f"""
    You are a cybersecurity analyst. Analyze this IP address and give a short threat report.
    
    IP Address: {ip}
    VirusTotal Results: {vt_result["malicious"]} malicious, {vt_result["suspicious"]} suspicious, {vt_result["harmless"]} harmless detections
    AbuseIPDB Results: Abuse score {abuse_result["abuse_score"]}%, {abuse_result["total_reports"]} total reports, Country: {abuse_result["country"]}
    ML Threat Level: {threat_level}
    
    Give a 3-4 line professional threat assessment report. Be concise and clear.
    """
    
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        time.sleep(10)
        try:
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Threat Level: {threat_level}. Automated analysis temporarily unavailable. Manual review recommended."
