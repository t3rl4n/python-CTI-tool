# Single-File Log Analysis & CTI Tool - Final Version
# This script combines all stages: Log Parsing, CTI Checks, and AI Reporting.
# Includes a universal parser and built-in debugging for problematic log lines.

import os
import re
import sys
import requests
import getpass  # To hide API key input
from datetime import datetime
from collections import defaultdict

# --- Constants and Thresholds ---
SUSPICIOUS_SCORE_THRESHOLD = 50
VT_SUSPICIOUS_THRESHOLD = 2
MALICIOUS_USER_AGENTS = ['sqlmap', 'nmap', 'hydra', 'nikto', 'wfuzz', 'nessus', 'metasploit']

# --- STAGE 0: GET API KEYS INTERACTIVELY ---
def prompt_for_api_keys():
    """Prompts the user to enter their API keys securely."""
    print("\n[+] Configuration: Please enter your API keys.")
    print("    (Your input will be hidden for security)")
    abuseipdb_key = getpass.getpass("  -> Enter your AbuseIPDB API Key: ")
    virustotal_key = getpass.getpass("  -> Enter your VirusTotal API Key: ")
    gemini_key = getpass.getpass("  -> Enter your Google Gemini API Key: ")
    if not all([abuseipdb_key, virustotal_key, gemini_key]):
        print("[WARNING] One or more API keys were not provided. Limited CTI/AI functionality.")
    return {"abuseipdb": abuseipdb_key, "virustotal": virustotal_key, "gemini": gemini_key}

# --- STAGE 1: PARSE THE LOG ---
def parse_log_file(filepath):
    """Parses an access.log file with a flexible regex and built-in debugging."""
    print(f"\n[+] Starting Stage 1: Parsing log file '{filepath}'...")
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: '{filepath}'. Please check the path.")
        return None, None

    # This is a more universal "master key" regex. It's less strict and finds the
    # key components even if the log format varies slightly.
    log_pattern = re.compile(
        r'(?P<ip>\S+)\s'
        r'(?:\S+\s){2}'
        r'\[(?P<timestamp>.*?)\]\s'
        r'"(?P<request>.*?)"\s'
        r'(?P<status>\d{3})\s'
        r'(?P<size>\S+)\s'
        r'".*?"\s'
        r'"(?P<user_agent>.*?)"'
    )

    ip_data = defaultdict(lambda: {'total_requests': 0, '4xx_errors': 0, 'user_agents': set()})
    total_requests, skipped_lines, printed_skips = 0, 0, 0
    status_code_counts = defaultdict(int)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = log_pattern.match(line)
                if not match:
                    skipped_lines += 1
                    # --- BUILT-IN DEBUGGING ---
                    # Print the first 5 lines that don't match the pattern.
                    if printed_skips < 5:
                        if printed_skips == 0:
                            print("\n[DEBUG] Could not parse the following lines (showing first 5):")
                        print(f"  -> {line.strip()}")
                        printed_skips += 1
                    continue

                log_parts = match.groupdict()
                ip, status, ua = log_parts['ip'], int(log_parts['status']), log_parts['user_agent']

                ip_data[ip]['total_requests'] += 1
                if 400 <= status < 500:
                    ip_data[ip]['4xx_errors'] += 1
                if ua != "-":
                    ip_data[ip]['user_agents'].add(ua)

                total_requests += 1
                status_code_counts[status] += 1
    except Exception as e:
        print(f"[ERROR] Failed to read or parse the log file: {e}")
        return None, None

    if skipped_lines > 0:
        print(f"\n[INFO] Skipped a total of {skipped_lines} lines due to non-standard formatting.")

    if not ip_data:
        print("[ERROR] No valid log entries were parsed. Please check the log file format.")
        return None, None

    print(f"[SUCCESS] Stage 1 complete. Parsed {total_requests} requests from {len(ip_data)} unique IPs.")
    ratio_404_to_200 = status_code_counts.get(404, 0) / status_code_counts.get(200, 1)
    log_stats = {'total_requests': total_requests, 'unique_ips': len(ip_data), 'ratio_404_to_200': ratio_404_to_200}
    return ip_data, log_stats

# --- STAGE 2 & 3 (UNCHANGED) ---

def check_abuseipdb(ip, api_key):
    if not api_key: return None
    try:
        r = requests.get('https://api.abuseipdb.com/api/v2/check', headers={'Key': api_key, 'Accept': 'application/json'}, params={'ipAddress': ip})
        r.raise_for_status()
        d = r.json().get('data', {})
        return {'score': d.get('abuseConfidenceScore', 0), 'country': d.get('countryCode', 'N/A')}
    except requests.RequestException: return None

def check_virustotal(ip, api_key):
    if not api_key: return None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={'x-apikey': api_key})
        r.raise_for_status()
        s = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {'malicious': s.get('malicious', 0), 'suspicious': s.get('suspicious', 0)}
    except requests.RequestException: return None

def analyze_ips(ip_data, api_keys):
    print("\n[+] Starting Stage 2: Checking IP reputations...")
    suspicious_ips = []
    for i, (ip, data) in enumerate(ip_data.items()):
        print(f"  -> Checking IP {i+1}/{len(ip_data)}: {ip}", end='\r')
        reasons = []
        abuse_result = check_abuseipdb(ip, api_keys['abuseipdb'])
        vt_result = check_virustotal(ip, api_keys['virustotal'])
        if abuse_result and abuse_result['score'] > SUSPICIOUS_SCORE_THRESHOLD:
            reasons.append(f"High AbuseIPDB Score ({abuse_result['score']})")
        if vt_result and (vt_result['malicious'] > 0 or vt_result['suspicious'] > VT_SUSPICIOUS_THRESHOLD):
            reasons.append("VirusTotal Detections")
        is_high_priority = any(tool in agent.lower() for agent in data['user_agents'] for tool in MALICIOUS_USER_AGENTS)
        if is_high_priority:
            reasons.append("Malicious User-Agent Detected")
        if reasons:
            suspicious_ips.append({'ip': ip, 'reasons': reasons, 'high_priority': is_high_priority, **data, 'cti_abuse': abuse_result, 'cti_vt': vt_result})
    print(" " * 50, end='\r')
    print(f"[SUCCESS] Stage 2 complete. Found {len(suspicious_ips)} suspicious IPs.")
    return suspicious_ips

def get_gemini_analysis(prompt, api_key):
    if not api_key: return "[AI ANALYSIS UNAVAILABLE: Gemini API Key not provided]"
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        candidates = r.json().get('candidates', [])
        if candidates and 'content' in candidates[0] and 'parts' in candidates[0]['content']:
            return candidates[0]['content']['parts'][0]['text'].strip()
        return "[AI ANALYSIS FAILED: Unexpected response format]"
    except requests.RequestException as e: return f"[AI ANALYSIS FAILED: Network error - {e}]"
    except (KeyError, IndexError): return "[AI ANALYSIS FAILED: Could not parse API response]"

def create_report(suspicious_ips, log_stats, api_keys):
    print("\n[+] Starting Stage 3: Generating security report...")
    if not os.path.exists('reports'): os.makedirs('reports')
    ai_explanation = "No high-risk threats identified to explain."
    if suspicious_ips:
        high_risk_ip = sorted(suspicious_ips, key=lambda x: x.get('high_priority', False), reverse=True)[0]
        prompt1 = f"You are a cybersecurity analyst for a SOC in Azerbaijan. In one simple sentence, explain the threat from IP address {high_risk_ip['ip']}. This IP was flagged for these reasons: {', '.join(high_risk_ip['reasons'])}. Explain it to a non-technical manager."
        ai_explanation = get_gemini_analysis(prompt1, api_keys['gemini'])
    prompt2 = f"You are a cybersecurity analyst. Briefly describe any anomalies in the following web server log statistics for a SOC team in Azerbaijan. Total Requests: {log_stats['total_requests']}, Unique IPs: {log_stats['unique_ips']}, Ratio of 404 to 200 status codes: {log_stats['ratio_404_to_200']:.2f}."
    ai_summary = get_gemini_analysis(prompt2, api_keys['gemini'])
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_content = f"""# Cybersecurity Threat Report - {timestamp}\n\n## AI-Powered Summary\n\n**Overall Log Analysis:** > {ai_summary}\n\n**Highest-Risk Threat Explanation:**\n> {ai_explanation}\n\n---\n\n## Suspicious IP Details\n"""
    if not suspicious_ips:
        report_content += "No suspicious IP addresses were detected during this analysis."
    else:
        sorted_ips = sorted(suspicious_ips, key=lambda x: (x.get('high_priority', False), x['total_requests']), reverse=True)
        for ip_info in sorted_ips:
            priority_tag = "🔥 **HIGH PRIORITY**" if ip_info.get('high_priority') else ""
            report_content += f"\n### IP Address: {ip_info['ip']} {priority_tag}\n"
            report_content += f"- **Reasons for Flagging:** {', '.join(ip_info['reasons'])}\n"
            report_content += f"- **Total Requests:** {ip_info['total_requests']}\n"
            report_content += f"- **4xx Errors:** {ip_info['4xx_errors']}\n"
            if ip_info['cti_abuse']:
                abuse = ip_info['cti_abuse']
                report_content += f"- **AbuseIPDB:** Score: {abuse['score']}, Country: {abuse['country']}\n"
            if ip_info['cti_vt']:
                vt = ip_info['cti_vt']
                report_content += f"- **VirusTotal:** {vt['malicious']} malicious, {vt['suspicious']} suspicious detections\n"
    for ext in ['txt', 'md']:
        report_path = os.path.join('reports', f'security_report_{timestamp}.{ext}')
        try:
            with open(report_path, 'w', encoding='utf-8') as f: f.write(report_content.strip())
            print(f"[SUCCESS] Report saved to '{report_path}'")
        except Exception as e: print(f"[ERROR] Could not write report to '{report_path}': {e}")

# --- MAIN EXECUTION ---
def main():
    """The main function to orchestrate the log analysis workflow."""
    print("--- Azerbaijan Cybersecurity Center: Log Analysis & CTI Tool ---")
    if len(sys.argv) != 2:
        print("\n[ERROR] Incorrect usage.\n"
              "Please provide the path to the access.log file.\n"
              "Example: python3 log_analyzer.py /var/log/nginx/access.log")
        sys.exit(1)
    log_filepath = sys.argv[1]
    api_keys = prompt_for_api_keys()
    ip_data, log_stats = parse_log_file(log_filepath)
    if ip_data and log_stats:
        suspicious_ips = analyze_ips(ip_data, api_keys)
        create_report(suspicious_ips, log_stats, api_keys)
    print("\n[+] Analysis complete. Exiting.")

if __name__ == "__main__":
    main()

