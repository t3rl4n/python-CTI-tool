🎯 About The Project

In today's digital landscape, security analysts are flooded with log data. This tool was built to automate the initial, critical steps of threat hunting. It reads a standard access.log file, identifies every unique IP address, and automatically investigates them using world-class Cyber Threat Intelligence (CTI) sources.

Finally, it leverages the power of Google's Gemini AI to translate complex technical findings into simple, human-readable reports, empowering the SOC team in Azerbaijan to act faster and more decisively.
✨ Key Features

    🖥️ Automated Log Parsing: Effortlessly processes standard web server access logs to extract crucial information.

    🛡️ Multi-Source CTI Enrichment: Cross-references IP addresses with AbuseIPDB and VirusTotal to assess their reputation.

    ❗ High-Priority Threat Flagging: Automatically identifies high-risk threats by detecting malicious user agents from common attack tools (sqlmap, nmap, etc.).

    🤖 AI-Powered Reporting: Utilizes Google Gemini to generate clear, concise summaries for both technical analysts and non-technical managers.

    🔑 Interactive & Secure: Asks for your API keys when you run it, keeping your secrets safe and out of configuration files.

⚙️ Project Workflow

The tool follows a simple, three-stage process to turn raw logs into actionable intelligence.

┌──────────────────┐   ┌───────────────────┐   ┌────────────────────┐   ┌──────────────────┐
│   access.log     │──>│  1. Parse Log     │──>│  2. CTI Analysis   │──>│  3. AI Reporting │
│ (Raw Data Input) │   │ (Extract IPs/Data)│   │  (Check Reputations) │   │ (Generate Report)│
└──────────────────┘   └───────────────────┘   └────────────────────┘   └──────────────────┘

🚀 Getting Started

Follow these steps to get the CTI Log Analyzer running on your local machine.
Prerequisites

    Python 3.7 or higher

    Git command-line tools

1. Clone the Repository

First, clone the project to your machine and navigate into the directory.

git clone https://github.com/t3rl4n/python-CTI-tool.git

2. Set Up the Virtual Environment

Using a virtual environment is crucial to keep project dependencies isolated.

    On Linux or macOS:

    python3 -m venv .venv
    source .venv/bin/activate

    On Windows (CMD/PowerShell):

    python -m venv .venv
    .venv\Scripts\activate

Your terminal prompt should now start with (.venv).
3. Install Dependencies

Install the necessary Python libraries with a single command.

pip install -r requirements.txt

▶️ How to Use

Running the analyzer is simple.

    Make sure your virtual environment is active.

    Execute the script and provide the path to the access.log file you wish to analyze.

    python3 log_analyzer.py /path/to/your/access.log

    Example using the included sample log file:

    python3 log_analyzer.py access.log

    The script will then interactively prompt you to enter your API keys. Your input will be hidden for security.

    [+] Configuration: Please enter your API keys.
        (Your input will be hidden for security)
      -> Enter your AbuseIPDB API Key:
      -> Enter your VirusTotal API Key:
      -> Enter your Google Gemini API Key:

    Once the analysis is complete, you will find a detailed report in both .txt and .md formats inside the newly created reports/ folder.
