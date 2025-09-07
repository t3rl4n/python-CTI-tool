# report_generator.py - Module for Stage 3: Generating reports.
import os, json, requests
from datetime import datetime
from config import GEMINI_API_KEY

def get_gemini_analysis(prompt):
    if not GEMINI_API_KEY or "YOUR" in GEMINI_API_KEY: return "[AI ANALYSIS UNAVAILABLE]"
    try:
        r = requests.post(f"[https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=](https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=){GEMINI_API_KEY}", json={"contents": [{"parts": [{"text": prompt}]}]})
        r.raise_for_status()
        return r.json()['candidates'][0]['content']['parts'][0]['text']
    except requests.RequestException as e: return f"[AI ANALYSIS FAILED: {e}]"

def create_report(suspicious_ips, log_stats):
    print("\n[+] Starting Stage 3: Generating reports...")
    if not os.path.exists('reports'): os.makedirs('reports')
    
    high_risk_ip = sorted(suspicious_ips, key=lambda x: x['high_priority'], reverse=True)[0] if suspicious_ips else None
    prompt1 = f"Explain the threat from IP {high_risk_ip['ip']} in one simple sentence for a non-technical person in Azerbaijan. Reasons: {', '.join(high_risk_ip['reasons'])}." if high_risk_ip else ""
    ai_explanation = get_gemini_analysis(prompt1) if prompt1 else "No high-risk threats to explain."

    prompt2 = f"Briefly describe anomalies in these log stats for a SOC in Azerbaijan: Total Requests: {log_stats['total_requests']}, Unique IPs: {log_stats['unique_ips']}, 404/200 Ratio: {log_stats['ratio_404_to_200']:.2f}."
    ai_summary = get_gemini_analysis(prompt2)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = f"Cybersecurity Threat Report - {ts}\n\n--- AI Summary ---\nOverall Analysis: {ai_summary}\nHigh-Risk Threat: {ai_explanation}\n\n--- Suspicious IP Details ---\n"
    if not suspicious_ips: report += "No suspicious activities detected."
    else:
        for ip in sorted(suspicious_ips, key=lambda x: x['high_priority'], reverse=True):
            report += f"\n- IP: {ip['ip']} {'[!! HIGH PRIORITY !!]' if ip['high_priority'] else ''}\n"
            report += f"  Reasons: {', '.join(ip['reasons'])}\n"
            if ip['cti_abuse']: report += f"  AbuseIPDB -> Score: {ip['cti_abuse']['score']}, Country: {ip['cti_abuse']['country']}\n"
            if ip['cti_vt']: report += f"  VirusTotal -> {ip['cti_vt']['malicious']} malicious detections\n"

    for ext in ['txt', 'md']:
        path = f"reports/security_report_{ts}.{ext}"
        with open(path, 'w') as f: f.write(report)
        print(f"[SUCCESS] Report saved to '{path}'")
