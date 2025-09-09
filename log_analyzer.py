# Enhanced Log Analysis Tool with AI + CTI + Advanced Reporting
import os
import re
import sys
import json
import requests
import getpass
from datetime import datetime
from collections import defaultdict, Counter
from colorama import Fore, Style, init
import pyfiglet
import random

# --- Initialize Colorama ---
init(autoreset=True)

# --- Constants and Thresholds ---
SUSPICIOUS_SCORE_THRESHOLD = 50
VT_SUSPICIOUS_THRESHOLD = 2
DEFAULT_MALICIOUS_USER_AGENTS = ['sqlmap', 'nmap', 'hydra', 'nikto', 'wfuzz', 'nessus', 'metasploit']

# --- Fancy Banner ---
def print_banner():
    colors = [Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.YELLOW]
    banner_text = pyfiglet.figlet_format("CTI Tool", font="slant")
    color = random.choice(colors)
    print(color + banner_text + Style.RESET_ALL)
    print(Fore.CYAN + "Author : Tarlan" + Style.RESET_ALL)
    print(Fore.CYAN + "Version: 2.0" + Style.RESET_ALL)
    print(Fore.CYAN + "Enhanced AI + CTI + HTML Reporting" + Style.RESET_ALL)
    print("-" * 60)

# --- Load external malicious user-agents if available ---
def load_malicious_user_agents(filepath='malicious_user_agents.json'):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return DEFAULT_MALICIOUS_USER_AGENTS

# --- STAGE 0: GET API KEYS ---
def prompt_for_api_keys():
    abuseipdb_key = getpass.getpass("Enter AbuseIPDB API Key: ")
    virustotal_key = getpass.getpass("Enter VirusTotal API Key: ")
    gemini_key = getpass.getpass("Enter Google Gemini API Key: ")
    return {'abuseipdb': abuseipdb_key, 'virustotal': virustotal_key, 'gemini': gemini_key}

# --- STAGE 1: PARSE LOG ---
def parse_text_log(line, pattern):
    match = pattern.match(line.strip())
    if not match: return None
    log_parts = match.groupdict()
    return {'ip': log_parts.get('ip'), 'status': int(log_parts.get('status',0)), 'user_agent': log_parts.get('user_agent','-'), 'url': log_parts.get('request','-')}

def parse_json_log(line):
    try:
        json_start = line.find('{')
        if json_start == -1: return None
        log_entry = json.loads(line[json_start:])
        return {'ip': log_entry.get('remote_addr'), 'status': int(log_entry.get('status',0)), 'user_agent': log_entry.get('user_agent','-'), 'url': log_entry.get('request','-')}
    except: return None

def parse_log_file(filepath):
    if not os.path.exists(filepath): return None, None

    log_format = 'unknown'
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s=line.strip()
            if not s: continue
            if s.startswith('{') or '{"' in s: log_format='json'; break
            elif re.search(r'\d{1,3}(\.\d{1,3}){3}', s): log_format='text'; break

    if log_format=='unknown': return None, None

    ip_data=defaultdict(lambda:{'total_requests':0,'4xx_errors':0,'5xx_errors':0,'user_agents':set(),'urls':Counter(),'hourly':Counter()})
    status_counts=defaultdict(int)

    text_pattern = re.compile(r'(?P<ip>\S+)\s(?:\S+\s){2}\[(?P<timestamp>.*?)\]\s"(?P<request>.*?)"\s(?P<status>\d{3})\s(?P<size>\S+)\s".*?"\s"(?P<user_agent>.*?)"')

    with open(filepath,'r',encoding='utf-8',errors='ignore') as f:
        for line in f:
            parsed=None
            if log_format=='text': parsed=parse_text_log(line,text_pattern)
            else: parsed=parse_json_log(line)
            if not parsed or not parsed.get('ip'): continue

            ip=parsed['ip']; status=parsed['status']; ua=parsed['user_agent']; url=parsed['url']
            ip_data[ip]['total_requests']+=1
            if 400<=status<500: ip_data[ip]['4xx_errors']+=1
            if 500<=status<600: ip_data[ip]['5xx_errors']+=1
            if ua and ua!='-': ip_data[ip]['user_agents'].add(ua)
            if url and url!='-': ip_data[ip]['urls'][url]+=1

            # Hour extraction from timestamp
            try:
                hour=int(re.search(r'\d{2}:\d{2}:\d{2}', line).group(0)[:2])
                ip_data[ip]['hourly'][hour]+=1
            except: pass

            status_counts[status]+=1

    total_requests=sum(status_counts.values())
    ratio_404_200=status_counts.get(404,0)/status_counts.get(200,1)
    log_stats={'total_requests':total_requests,'unique_ips':len(ip_data),'ratio_404_to_200':ratio_404_200,'status_counts':dict(status_counts)}
    return ip_data,log_stats

# --- STAGE 2: CTI Checks (same as your original functions) ---
def check_abuseipdb(ip, api_key):
    if not api_key: return None
    try:
        r=requests.get('https://api.abuseipdb.com/api/v2/check',headers={'Key':api_key,'Accept':'application/json'},params={'ipAddress':ip,'maxAgeInDays':90,'verbose':True},timeout=10)
        r.raise_for_status(); data=r.json().get('data',{})
        return {'score':data.get('abuseConfidenceScore',0),'totalReports':data.get('totalReports',0),'isp':data.get('isp','Unknown'),'usageType':data.get('usageType','Unknown'),'asn':data.get('asn','Unknown'),'hostname':data.get('hostnames',['N/A'])[0],'domain':data.get('domain','Unknown'),'country':data.get('countryCode','N/A'),'city':data.get('city','Unknown')}
    except: return None

def check_virustotal(ip, api_key):
    if not api_key: return None
    try:
        r=requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",headers={'x-apikey':api_key},timeout=10)
        r.raise_for_status(); attr=r.json().get('data',{}).get('attributes',{})
        stats=attr.get('last_analysis_stats',{})
        return {'malicious':stats.get('malicious',0),'suspicious':stats.get('suspicious',0),'harmless':stats.get('harmless',0),'undetected':stats.get('undetected',0),'last_analysis':attr.get('last_analysis_date','N/A'),'categories':attr.get('categories',{})}
    except: return None

def analyze_ips(ip_data, api_keys, malicious_agents):
    suspicious_ips=[]
    for ip,data in ip_data.items():
        reasons=[]
        abuse=check_abuseipdb(ip,api_keys['abuseipdb']); vt=check_virustotal(ip,api_keys['virustotal'])
        if abuse and abuse['score']>SUSPICIOUS_SCORE_THRESHOLD: reasons.append(f"High AbuseIPDB Score ({abuse['score']})")
        if vt and (vt['malicious']>0 or vt['suspicious']>VT_SUSPICIOUS_THRESHOLD): reasons.append("VirusTotal Detections")
        high_priority=any(tool in ua.lower() for ua in data['user_agents'] for tool in malicious_agents)
        if high_priority: reasons.append("Malicious User-Agent Detected")
        if reasons: suspicious_ips.append({'ip':ip,'reasons':reasons,'high_priority':high_priority,**data,'cti_abuse':abuse,'cti_vt':vt})
    return suspicious_ips

# --- STAGE 3: AI & REPORT ---
def get_gemini_analysis(prompt, api_key):
    if not api_key: return "[AI ANALYSIS UNAVAILABLE]"
    try:
        url=f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
        payload={'contents':[{'role':'user','parts':[{'text':prompt}]}]}
        r=requests.post(url,json=payload,headers={'Content-Type':'application/json'},timeout=20)
        r.raise_for_status()
        c=r.json().get('candidates',[])
        return c[0]['content']['parts'][0]['text'].strip() if c else "[AI ANALYSIS FAILED]"
    except: return "[AI ANALYSIS FAILED]"

# --- Generate HTML report ---
def create_report(suspicious_ips, log_stats, api_keys):
    if not os.path.exists('reports'): os.makedirs('reports')
    timestamp=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    malicious_agents=load_malicious_user_agents()

    prompt_summary=f"Total Requests: {log_stats['total_requests']}, Unique IPs: {log_stats['unique_ips']}, Ratio 404/200: {log_stats['ratio_404_to_200']:.2f}" 
    ai_summary=get_gemini_analysis(prompt_summary,api_keys['gemini'])

    # TXT and MD report
    report_content=f"""# Cybersecurity Threat Report - {timestamp}

## AI Summary
{ai_summary}

## Suspicious IPs
"""
    if not suspicious_ips: report_content+="No suspicious IPs detected."
    else:
        for ip in suspicious_ips:
            tag="🔥 HIGH PRIORITY" if ip.get('high_priority') else ""
            report_content+=f"\n### {ip['ip']} {tag}\n- Reasons: {', '.join(ip['reasons'])}\n- Total Requests: {ip['total_requests']}\n- 4xx Errors: {ip['4xx_errors']}\n- 5xx Errors: {ip['5xx_errors']}\n"

    # Write TXT and MD
    for ext in ['txt','md']:
        with open(os.path.join('reports',f'security_report_{timestamp}.{ext}'),'w',encoding='utf-8') as f: f.write(report_content)

    # HTML Report
    html_content=f"""<html><head><title>Cybersecurity Report</title></head><body><h1>Cybersecurity Threat Report - {timestamp}</h1><h2>AI Summary</h2><p>{ai_summary}</p><h2>Suspicious IPs</h2>"""
    if not suspicious_ips: html_content+="<p>No suspicious IPs detected.</p>"
    else:
        for ip in suspicious_ips:
            tag="<b style='color:red'>HIGH PRIORITY</b>" if ip.get('high_priority') else ""
            html_content+=f"<h3>{ip['ip']} {tag}</h3><ul><li>Reasons: {', '.join(ip['reasons'])}</li><li>Total Requests: {ip['total_requests']}</li><li>4xx Errors: {ip['4xx_errors']}</li><li>5xx Errors: {ip['5xx_errors']}</li></ul>"
    html_content+="</body></html>"
    with open(os.path.join('reports',f'security_report_{timestamp}.html'),'w',encoding='utf-8') as f: f.write(html_content)

# --- MAIN ---
def main():
    print_banner()
    if len(sys.argv)!=2: print("Usage: python3 script.py /path/to/log"); sys.exit(1)
    log_file=sys.argv[1]
    api_keys=prompt_for_api_keys()
    malicious_agents=load_malicious_user_agents()
    ip_data,log_stats=parse_log_file(log_file)
    if ip_data and log_stats:
        suspicious_ips=analyze_ips(ip_data,api_keys,malicious_agents)
        create_report(suspicious_ips,log_stats,api_keys)
    print("Analysis complete.")

if __name__=="__main__": main()
