# This script intelligently detects the log format (Text vs. JSON) and parses accordingly.
# It combines Log Parsing, CTI Checks, and AI Reporting into one robust tool.
import os
import re
import sys
import json
import requests
import getpass  # To hide API key input
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Style, init
import pyfiglet
import random

# --- Initialize Colorama ---
init(autoreset=True)

# --- Constants and Thresholds ---
SUSPICIOUS_SCORE_THRESHOLD = 50
VT_SUSPICIOUS_THRESHOLD = 2
MALICIOUS_USER_AGENTS = ['sqlmap', 'nmap', 'hydra', 'nikto', 'wfuzz', 'nessus', 'metasploit']

# --- Fancy Banner ---
def print_banner():
    """Displays a colorful ASCII banner for the tool."""
    colors = [Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW]
    banner_text = pyfiglet.figlet_format("CTI Tool", font="slant")
    color = random.choice(colors)  # random color every run
    print(color + banner_text + Style.RESET_ALL)
    print(Fore.CYAN + "Author : Tarlan" + Style.RESET_ALL)
    print(Fore.CYAN + "Version: 1.0" + Style.RESET_ALL)
    print(Fore.CYAN + "Powered by Python + CTI + AI 🤖" + Style.RESET_ALL)
    print("-" * 60)

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

# --- STAGE 1: PARSE THE LOG (WITH AUTO-DETECTION) ---
def parse_text_log(line, pattern):
    """Parses a single line from a standard text-based log file."""
    match = pattern.match(line.strip())
    if not match:
        return None
    log_parts = match.groupdict()
    return {
        'ip': log_parts.get('ip'),
        'status': int(log_parts.get('status', 0)),
        'user_agent': log_parts.get('user_agent', '-')
    }

def parse_json_log(line):
    """Parses a single line from a JSON-formatted log file."""
    try:
        json_start_index = line.find('{')
        if json_start_index == -1:
            return None
        json_str = line[json_start_index:]
        log_entry = json.loads(json_str)
        return {
            'ip': log_entry.get('remote_addr'),
            'status': int(log_entry.get('status', 0)),
            'user_agent': log_entry.get('user_agent', '-')
        }
    except (json.JSONDecodeError, KeyError, TypeError):
        return None

def parse_log_file(filepath):
    """
    Auto-detects the log format (Text or JSON) and parses the file accordingly.
    """
    print(f"\n[+] Starting Stage 1: Parsing log file '{filepath}'...")
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: '{filepath}'. Please check the path.")
        return None, None

    # --- Auto-Detection Engine ---
    log_format = "unknown"
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            stripped_line = line.strip()
            if not stripped_line:
                continue
            if stripped_line.startswith('{') or '{"' in stripped_line:
                log_format = "json"
                print("[INFO] Auto-detected JSON log format.")
                break
            elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', stripped_line):
                log_format = "text"
                print("[INFO] Auto-detected Text log format.")
                break

    if log_format == "unknown":
        print("[ERROR] Could not determine the log file format. Exiting.")
        return None, None

    # --- Data Aggregation Setup ---
    ip_data = defaultdict(lambda: {'total_requests': 0, '4xx_errors': 0, 'user_agents': set()})
    total_requests, skipped_lines = 0, 0
    status_code_counts = defaultdict(int)

    text_log_pattern = re.compile(
        r'(?P<ip>\S+)\s(?:\S+\s){2}\[(?P<timestamp>.*?)\]\s"(?P<request>.*?)"\s(?P<status>\d{3})\s(?P<size>\S+)\s".*?"\s"(?P<user_agent>.*?)"'
    )

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed_data = None
                if log_format == "text":
                    parsed_data = parse_text_log(line, text_log_pattern)
                elif log_format == "json":
                    parsed_data = parse_json_log(line)

                if not parsed_data or not parsed_data.get('ip'):
                    skipped_lines += 1
                    continue

                ip, status, ua = parsed_data['ip'], parsed_data['status'], parsed_data['user_agent']
                ip_data[ip]['total_requests'] += 1
                if 400 <= status < 500:
                    ip_data[ip]['4xx_errors'] += 1
                if ua and ua != "-":
                    ip_data[ip]['user_agents'].add(ua)

                total_requests += 1
                status_code_counts[status] += 1
    except Exception as e:
        print(f"[ERROR] Failed during file processing: {e}")
        return None, None

    if skipped_lines > 0:
        print(f"[INFO] Skipped {skipped_lines} malformed or unparsable lines.")
    if not ip_data:
        print("[ERROR] No valid log entries were found. Please check the file content.")
        return None, None

    print(f"[SUCCESS] Stage 1 complete. Parsed {total_requests} requests from {len(ip_data)} unique IPs.")

    ratio_404_to_200 = status_code_counts.get(404, 0) / status_code_counts.get(200, 1)
    log_stats = {'total_requests': total_requests, 'unique_ips': len(ip_data), 'ratio_404_to_200': ratio_404_to_200}
    return ip_data, log_stats

# --- STAGE 2: CHECK IP REPUTATION (CTI) ---
def check_abuseipdb(ip, api_key):
    """Queries the AbuseIPDB API for an IP's reputation with extended details."""
    if not api_key:
        return None
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
            timeout=10
        )
        response.raise_for_status()
        data = response.json().get('data', {})
        return {
            'score': data.get('abuseConfidenceScore', 0),
            'totalReports': data.get('totalReports', 0),
            'isp': data.get('isp', 'Unknown'),
            'usageType': data.get('usageType', 'Unknown'),
            'asn': data.get('asn', 'Unknown'),
            'hostname': data.get('hostnames', ['N/A'])[0] if data.get('hostnames') else 'N/A',
            'domain': data.get('domain', 'Unknown'),
            'country': data.get('countryCode', 'N/A'),
            'city': data.get('city', 'Unknown')
        }
    except requests.RequestException:
        return None


def check_virustotal(ip, api_key):
    """Queries the VirusTotal API for an IP's reputation with extended details."""
    if not api_key:
        return None
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={'x-apikey': api_key},
            timeout=10
        )
        response.raise_for_status()
        attributes = response.json().get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'last_analysis': attributes.get('last_analysis_date', 'N/A'),
            'categories': attributes.get('categories', {})  # extra info
        }
    except requests.RequestException:
        return None


def analyze_ips(ip_data, api_keys):
    """Analyzes a list of IPs using CTI sources and flags suspicious ones."""
    print("\n[+] Starting Stage 2: Checking IP reputations...")
    suspicious_ips = []
    total_ips = len(ip_data)
    for i, (ip, data) in enumerate(ip_data.items()):
        print(f"  -> Checking IP {i+1}/{total_ips}: {ip}", end='\r')
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
            suspicious_ips.append({
                'ip': ip,
                'reasons': reasons,
                'high_priority': is_high_priority,
                **data,
                'cti_abuse': abuse_result,
                'cti_vt': vt_result
            })

    print(" " * 50, end='\r')
    print(f"[SUCCESS] Stage 2 complete. Found {len(suspicious_ips)} suspicious IPs.")
    return suspicious_ips

# --- STAGE 3: EXPLAIN & REPORT ---
def get_gemini_analysis(prompt, api_key):
    """Gets a natural language explanation from the Google Gemini API."""
    if not api_key:
        return "[AI ANALYSIS UNAVAILABLE: Gemini API Key not provided]"
    if not prompt.strip():
        return "[AI ANALYSIS FAILED: Empty prompt]"
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}]
                }
            ]
        }
        response = requests.post(url, headers={"Content-Type": "application/json"}, json=payload, timeout=20)
        response.raise_for_status()
        candidates = response.json().get('candidates', [])
        if candidates and 'content' in candidates[0] and 'parts' in candidates[0]['content']:
            return candidates[0]['content']['parts'][0]['text'].strip()
        return "[AI ANALYSIS FAILED: Unexpected response format]"
    except requests.RequestException as e:
        return f"[AI ANALYSIS FAILED: Network error - {e}]"
    except (KeyError, IndexError):
        return "[AI ANALYSIS FAILED: Could not parse API response]"

def create_report(suspicious_ips, log_stats, api_keys):
    """Generates a final security report in TXT and Markdown formats."""
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

    report_content = f"""# Cybersecurity Threat Report - {timestamp}

## AI-Powered Summary

**Overall Log Analysis:** > {ai_summary}

**Highest-Risk Threat Explanation:**
> {ai_explanation}

---

## Suspicious IP Details
"""
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
                report_content += (
                    f"- **AbuseIPDB:** Reported {abuse['totalReports']} times, "
                    f"Score: {abuse['score']}%\n"
                    f"- **ISP:** {abuse['isp']}\n"
                    f"- **Usage Type:** {abuse['usageType']}\n"
                    f"- **ASN:** {abuse['asn']}\n"
                    f"- **Hostname:** {abuse['hostname']}\n"
                    f"- **Domain:** {abuse['domain']}\n"
                    f"- **Country/City:** {abuse['country']} / {abuse['city']}\n"
                )

            if ip_info['cti_vt']:
                vt = ip_info['cti_vt']
                report_content += (
                    f"- **VirusTotal:** {vt['malicious']} malicious, "
                    f"{vt['suspicious']} suspicious, "
                    f"{vt['harmless']} harmless, "
                    f"{vt['undetected']} undetected\n"
                )
                if vt['categories']:
                    categories_str = ", ".join(f"{k}: {v}" for k, v in vt['categories'].items())
                    report_content += f"- **Categories:** {categories_str}\n"

    for ext in ['txt', 'md']:
        report_path = os.path.join('reports', f'security_report_{timestamp}.{ext}')
        try:
            with open(report_path, 'w', encoding='utf-8') as f: f.write(report_content.strip())
            print(f"[SUCCESS] Report saved to '{report_path}'")
        except Exception as e: print(f"[ERROR] Could not write report to '{report_path}': {e}")

# --- MAIN EXECUTION ---
def main():
    """The main function to orchestrate the log analysis workflow."""
    print_banner()  # Show the banner at startup
    print(" Azerbaijan Cybersecurity Center: Log Analysis & CTI Tool ")

    if len(sys.argv) != 2:
        print("\n[ERROR] Incorrect usage.\n"
              "Please provide the path to the log file.\n"
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
