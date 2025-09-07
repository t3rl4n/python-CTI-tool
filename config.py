# config.py - Handles loading configuration and API keys from the .env file.
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

SUSPICIOUS_SCORE_THRESHOLD = 50
VT_SUSPICIOUS_THRESHOLD = 2
MALICIOUS_USER_AGENTS = ['sqlmap', 'nmap', 'hydra', 'nikto', 'wfuzz']

def check_api_keys():
    if not all([ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, GEMINI_API_KEY]):
        print("[WARNING] One or more API keys are missing. The script will have limited functionality.")
