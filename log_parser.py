# log_parser.py - Module for Stage 1: Parsing the web server log file.
import os, re
from collections import defaultdict

def parse_log_file(filepath):
    print(f"[+] Starting Stage 1: Parsing log file '{filepath}'...")
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: '{filepath}'")
        return None, None
    
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)] "(GET|POST|PUT|DELETE|HEAD) .*?" (\d{3}) \d+ ".*?" "(.*?)"')
    ip_data = defaultdict(lambda: {'total_requests': 0, '4xx_errors': 0, 'user_agents': set()})
    total_requests, status_code_counts = 0, defaultdict(int)

    with open(filepath, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
            if not match: continue
            ip, _, _, status, ua = match.groups()
            ip_data[ip]['total_requests'] += 1
            if 400 <= int(status) < 500: ip_data[ip]['4xx_errors'] += 1
            if ua != "-": ip_data[ip]['user_agents'].add(ua)
            total_requests += 1
            status_code_counts[int(status)] += 1
            
    print(f"[SUCCESS] Stage 1 complete. Parsed {total_requests} requests from {len(ip_data)} unique IPs.")
    log_stats = {'total_requests': total_requests, 'unique_ips': len(ip_data), 'ratio_404_to_200': status_code_counts.get(404, 0) / status_code_counts.get(200, 1)}
    return ip_data, log_stats
