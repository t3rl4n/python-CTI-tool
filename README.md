## ✨ Features

- 🔍 **Auto-detects log format (Text / JSON)**  
  No need to worry about the log type — the tool intelligently detects whether your logs are plain text or JSON and parses them correctly.  

- 🛡️ **Enriches suspicious IPs with AbuseIPDB + VirusTotal**  
  Each IP address found in the logs is checked against well-known threat intelligence sources to identify if it has a history of abuse or malware activity.  

- 🤖 **AI-powered analysis via Gemini**  
  Google Gemini is used to generate natural-language insights, making the reports understandable for both technical teams and non-technical managers.  

- 📊 **Exports detailed Markdown + TXT reports**  
  The final results are saved in both `.md` and `.txt` formats, making them easy to share, view in GitHub, or import into documentation systems.  


## 🚀 Quickstart
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

Execute the script and provide the path to the access.log file you wish to analyze.
python3 log_analyzer.py /path/to/access.log
