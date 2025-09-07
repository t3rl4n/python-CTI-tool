# main.py - The main entry point for the Log Analysis & CTI Tool.
import sys
from config import check_api_keys
from log_parser import parse_log_file
from cti_checker import analyze_ips
from report_generator import create_report

def run_analysis():
    if len(sys.argv) != 2:
        print("Usage: python main.py <path_to_access.log>")
        sys.exit(1)
    
    check_api_keys()
    log_filepath = sys.argv[1]

    ip_data, log_stats = parse_log_file(log_filepath)
    if not ip_data:
        sys.exit(1)

    suspicious_ips = analyze_ips(ip_data)
    create_report(suspicious_ips, log_stats)
    print("\n[+] Analysis complete.")

if __name__ == "__main__":
    run_analysis()
