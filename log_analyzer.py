# This script combines all stages: Log Parsing, CTI Checks, and AI Reporting.

import os
import re
import sys
import requests
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

# --- STAGE 0: CONFIGURATION & SETUP ---
# Load environment variables from a .env file for security
load_dotenv()

# Retrieve API keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- Constants and Thresholds ---
# Score from AbuseIPDB above which an IP is considered suspicious
SUSPICIOUS_SCORE_THRESHOLD = 50
# Number of VirusTotal detections above which an IP is considered suspicious
VT_SUSPICIOUS_THRESHOLD = 2
# List of User-Agent strings indicating potential scanning or attack tools
MALICIOUS_USER_AGENTS = ['sqlmap', 'nmap', 'hydra', 'nikto', 'wfuzz', 'nessus', 'metasploit']

def check_api_keys():
    """Checks if the necessary API keys have been set in the .env file."""
    print("[+] Checking for API keys...")
    if not all([ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, GEMINI_API_KEY]):
        print("[WARNING] One or more API keys are missing in your .env file.")
        print("          The script will run with limited functionality.")
    else:
        print("[SUCCESS] All API keys found.")

# --- STAGE 1: PARSE THE LOG ---
def parse_log_file(filepath):
    """
    Parses an access.log file to extract IP data and overall statistics.

    Args:
        filepath (str): The path to the access.log file.

    Returns:
        A tuple containing:
        - ip_data (dict): A dictionary with IPs as keys and their activity as values.
        - log_stats (dict): A dictionary with overall log statistics.
    """
    print(f"\n[+] Starting Stage 1: Parsing log file '{filepath}'...")
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: '{filepath}'. Please check the path and try again.")
        return None, None

    # Regex to capture: IP, timestamp, method, status code, and user agent
    log_pattern = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)] "(GET|POST|PUT|DELETE|HEAD) .*?" (\d{3}) \d+ ".*?" "(.*?)"'
    )

    # Use defaultdict to easily manage nested dictionaries and counters
    ip_data = defaultdict(lambda: {'total_requests': 0, '4xx_errors': 0, 'user_agents': set()})
    total_requests = 0
    status_code_counts = defaultdict(int)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = log_pattern.match(line)
                if not match:
                    continue  # Skip malformed lines

                ip, _, _, status, ua = match.groups()

                # Aggregate data for each IP
                ip_data[ip]['total_requests'] += 1
                if 400 <= int(status) < 500:
                    ip_data[ip]['4xx_errors'] += 1
                if ua != "-":
                    ip_data[ip]['user_agents'].add(ua)

                # Aggregate overall log stats
                total_requests += 1
                status_code_counts[int(status)] += 1
    except Exception as e:
        print(f"[ERROR] Failed to read or parse the log file: {e}")
        return None, None

    if not ip_data:
        print("[WARNING] No valid log entries were parsed from the file.")
        return None, None

    print(f"[SUCCESS] Stage 1 complete. Parsed {total_requests} requests from {len(ip_data)} unique IPs.")

    # Calculate statistics for the final report
    ratio_404_to_200 = status_code_counts.get(404, 0) / status_code_counts.get(200, 1) # Avoid division by zero
    log_stats = {
        'total_requests': total_requests,
        'unique_ips': len(ip_data),
        'ratio_404_to_200': ratio_404_to_200
    }

    return ip_data, log_stats

# --- STAGE 2: CHECK IP REPUTATION (CTI) ---
def check_abuseipdb(ip):
    """Queries the AbuseIPDB API for an IP's reputation."""
    if not ABUSEIPDB_API_KEY or "YOUR" in ABUSEIPDB_API_KEY:
        return None
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip}
        )
        response.raise_for_status()
        data = response.json().get('data', {})
        return {'score': data.get('abuseConfidenceScore', 0), 'country': data.get('countryCode', 'N/A')}
    except requests.RequestException:
        return None

def check_virustotal(ip):
    """Queries the VirusTotal API for an IP's reputation."""
    if not VIRUSTOTAL_API_KEY or "YOUR" in VIRUSTOTAL_API_KEY:
        return None
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={'x-apikey': VIRUSTOTAL_API_KEY}
        )
        response.raise_for_status()
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0)}
    except requests.RequestException:
        return None

def analyze_ips(ip_data):
    """
    Analyzes a list of IPs using CTI sources and flags suspicious ones.

    Args:
        ip_data (dict): The dictionary of IP activity from the log parser.

    Returns:
        list: A list of dictionaries, where each dictionary represents a suspicious IP.
    """
    print("\n[+] Starting Stage 2: Checking IP reputations...")
    suspicious_ips = []

    for i, (ip, data) in enumerate(ip_data.items()):
        # Provide progress feedback to the user
        print(f"  -> Checking IP {i+1}/{len(ip_data)}: {ip}", end='\r')

        reasons = []

        # Query CTI sources
        abuse_result = check_abuseipdb(ip)
        vt_result = check_virustotal(ip)

        # Check against thresholds
        if abuse_result and abuse_result['score'] > SUSPICIOUS_SCORE_THRESHOLD:
            reasons.append(f"High AbuseIPDB Score ({abuse_result['score']})")

        if vt_result and (vt_result['malicious'] > 0 or vt_result['suspicious'] > VT_SUSPICIOUS_THRESHOLD):
            reasons.append("VirusTotal Detections")

        # Check for malicious user agents (Bonus)
        is_high_priority = any(tool in agent.lower() for agent in data['user_agents'] for tool in MALICIOUS_USER_AGENTS)
        if is_high_priority:
            reasons.append("Malicious User-Agent Detected")

        # If any suspicious activity was found, add it to our list
        if reasons:
            suspicious_ips.append({
                'ip': ip,
                'reasons': reasons,
                'high_priority': is_high_priority,
                **data,
                'cti_abuse': abuse_result,
                'cti_vt': vt_result
            })

    # A final print to clear the progress line
    print(" " * 50, end='\r')
    print(f"[SUCCESS] Stage 2 complete. Found {len(suspicious_ips)} suspicious IPs.")
    return suspicious_ips

# --- STAGE 3: EXPLAIN & REPORT ---
def get_gemini_analysis(prompt):
    """Gets a natural language explanation from the Google Gemini API."""
    if not GEMINI_API_KEY or "YOUR" in GEMINI_API_KEY:
        return "[AI ANALYSIS UNAVAILABLE: Gemini API Key not set]"
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        response = requests.post(url, json=payload, timeout=20)
        response.raise_for_status()
        # Safely access the nested dictionary
        candidates = response.json().get('candidates', [])
        if candidates and 'content' in candidates[0] and 'parts' in candidates[0]['content']:
            return candidates[0]['content']['parts'][0]['text'].strip()
        return "[AI ANALYSIS FAILED: Unexpected response format]"
    except requests.RequestException as e:
        return f"[AI ANALYSIS FAILED: Network error - {e}]"
    except (KeyError, IndexError):
        return "[AI ANALYSIS FAILED: Could not parse the API response]"

def create_report(suspicious_ips, log_stats):
    """
    Generates a final security report in TXT and Markdown formats.

    Args:
        suspicious_ips (list): The list of suspicious IP dictionaries.
        log_stats (dict): The dictionary of overall log statistics.
    """
    print("\n[+] Starting Stage 3: Generating security report...")

    # Create the reports directory if it doesn't exist
    if not os.path.exists('reports'):
        os.makedirs('reports')

    # AI Explanation for the highest-risk IP (Bonus)
    ai_explanation = "No high-risk threats were identified to explain."
    if suspicious_ips:
        # Sort to find the highest priority IP (or just the first one if none are high priority)
        high_risk_ip = sorted(suspicious_ips, key=lambda x: x.get('high_priority', False), reverse=True)[0]
        prompt1 = f"You are a cybersecurity analyst for a SOC in Azerbaijan. In one simple sentence, explain the threat from IP address {high_risk_ip['ip']}. This IP was flagged for these reasons: {', '.join(high_risk_ip['reasons'])}. Explain it to a non-technical manager."
        ai_explanation = get_gemini_analysis(prompt1)

    # AI Summary of the overall log file (Bonus)
    prompt2 = f"You are a cybersecurity analyst. Briefly describe any anomalies in the following web server log statistics for a SOC team in Azerbaijan. Total Requests: {log_stats['total_requests']}, Unique IPs: {log_stats['unique_ips']}, Ratio of 404 to 200 status codes: {log_stats['ratio_404_to_200']:.2f}."
    ai_summary = get_gemini_analysis(prompt2)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # --- Report Content ---
    report_content = f"""
# Cybersecurity Threat Report - {timestamp}

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
        # Sort by high priority first, then by number of requests
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

    # --- Save Reports ---
    for ext in ['txt', 'md']:
        report_path = os.path.join('reports', f'security_report_{timestamp}.{ext}')
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content.strip())
            print(f"[SUCCESS] Report saved to '{report_path}'")
        except Exception as e:
            print(f"[ERROR] Could not write report to '{report_path}': {e}")


# --- MAIN EXECUTION ---
def main():
    """The main function to orchestrate the log analysis workflow."""
    print("--- Azerbaijan Cybersecurity Center: Log Analysis & CTI Tool ---")

    # Check that a log file path was provided as a command-line argument
    if len(sys.argv) != 2:
        print("\n[ERROR] Incorrect usage.")
        print("Please provide the path to the access.log file.")
        print("Example: python3 log_analyzer.py /var/log/nginx/access.log")
        sys.exit(1)

    log_filepath = sys.argv[1]

    # Run the full workflow
    check_api_keys()
    ip_data, log_stats = parse_log_file(log_filepath)

    if ip_data and log_stats:
        suspicious_ips = analyze_ips(ip_data)
        create_report(suspicious_ips, log_stats)

    print("\n[+] Analysis complete. Exiting.")

if __name__ == "__main__":
    main()