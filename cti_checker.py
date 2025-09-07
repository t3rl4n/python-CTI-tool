# cti_checker.py - Module for Stage 2: Checking IP reputation.
import requests
from config import *

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY: return None
    try:
        r = requests.get('[https://api.abuseipdb.com/api/v2/check](https://api.abuseipdb.com/api/v2/check)', headers={'Key': ABUSEIPDB_API_KEY}, params={'ipAddress': ip})
        r.raise_for_status()
        d = r.json().get('data', {})
        return {'score': d.get('abuseConfidenceScore', 0), 'country': d.get('countryCode', 'N/A')}
    except requests.RequestException as e: return None

def check_virustotal(ip):
    if not VIRUSTOTAL_API_KEY: return None
    try:
        r = requests.get(f"[https://www.virustotal.com/api/v3/ip_addresses/](https://www.virustotal.com/api/v3/ip_addresses/){ip}", headers={'x-apikey': VIRUSTOTAL_API_KEY})
        r.raise_for_status()
        s = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {'malicious': s.get('malicious', 0), 'suspicious': s.get('suspicious', 0)}
    except requests.RequestException as e: return None

def analyze_ips(ip_data):
    print("\n[+] Starting Stage 2: Checking IP reputations...")
    suspicious_ips = []
    for i, (ip, data) in enumerate(ip_data.items()):
        print(f"  -> Checking IP {i+1}/{len(ip_data)}: {ip}")
        reasons = []
        abuse_res = check_abuseipdb(ip)
        vt_res = check_virustotal(ip)
        
        if abuse_res and abuse_res['score'] > SUSPICIOUS_SCORE_THRESHOLD: reasons.append("High AbuseIPDB Score")
        if vt_res and vt_res['malicious'] > VT_SUSPICIOUS_THRESHOLD: reasons.append("VirusTotal Detections")
        
        is_high_priority = any(tool in agent.lower() for agent in data['user_agents'] for tool in MALICIOUS_USER_AGENTS)
        if is_high_priority: reasons.append("Malicious User-Agent")

        if reasons:
            suspicious_ips.append({'ip': ip, 'reasons': reasons, 'high_priority': is_high_priority, **data, 'cti_abuse': abuse_res, 'cti_vt': vt_res})
    
    print(f"[SUCCESS] Stage 2 complete. Found {len(suspicious_ips)} suspicious IPs.")
    return suspicious_ips