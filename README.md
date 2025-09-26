Two python scripts that enrich nginx access and ufw logs with geo information on IP addresses

lge.sh - original script

lgeaccess.py - This Python script is a tool for enriching your Nginx access logs with geographic and network information using the ipinfo.io API. It processes your logs, looks up IP addresses, and saves the enriched data into a JSON database. It also generates a summary of the most common requests, countries, and status codes, providing valuable insights into your web traffic.

lgeufw.py - enrich firewall logs with geo information, writes two files ufw_ipinfo_db.json contains all information about entries from log, ufw_summary.json contains summarized top information about log entries.

Display information from .json files with jq or create webserver that presents information.

Example html site can be viewed on:
https://krokodilsvans.github.io/

Get top blocked IP in ufw jq -r 'select(.action=="BLOCK") | .ip' ufw_ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10

Got top requested IP for specific uri jq -r 'select(.uri=="/.env") | .ip' ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10

------------------------------------------------------------------------------------

Nginx Log Analyzer (lgeaccess.py)

Quick Start

1. Prerequisites

    Python 3.x

    ipinfo.io API token: Sign up for a free account at ipinfo.io to get your token. The free tier is generous and suitable for most personal projects.

    Nginx access log: The script is configured to use /var/log/nginx/access.log by default.

2. Configuration

    Open the script and update the Config class at the top.

    TOKEN: Replace "YOUR_TOKEN_CHANGE" with your actual ipinfo.io API token.

    ACCESS_LOG: If your Nginx log file is in a different location, update this path.

    OUTPUT_DB and SUMMARY_FILE: You can change the names of the output files if you wish.

3. Installation

    Install the required Python library:
    Bash

pip install requests

Make the script executable:
Bash

    chmod +x lgeaccess.py

Running with Cron

To automatically enrich your logs every hour, you can use crontab. This ensures that you have up-to-date information without manual intervention.

    Open your crontab editor:
    Bash

crontab -e

Add the following line to the file. Make sure to replace /path/to/your/script/ with the actual directory where you've saved the script.
Code snippet

    0 * * * * /usr/bin/python3 /path/to/your/script/lgeaccess.py

        0 * * * * means the script will run at the beginning of every hour (e.g., 1:00, 2:00, 3:00, etc.).

        /usr/bin/python3 is the full path to the Python 3 interpreter. You can verify your path with which python3.

        /path/to/your/script/lgeaccess.py is the full path to the script itself.

Using jq for Data Analysis

The script generates a summary.json file, which is perfect for parsing with jq. jq is a lightweight and flexible command-line JSON processor.

Get the Top 5 Countries

This command shows the top 5 countries by request count.
Bash

jq '.country_stats[:5]' summary.json

Example output:
JSON

[
  {
    "country": "US",
    "hits": 1500
  },
  {
    "country": "DE",
    "hits": 800
  },
  {
    "country": "GB",
    "hits": 650
  },
  {
    "country": "RU",
    "hits": 420
  },
  {
    "country": "CN",
    "hits": 310
  }
]

Find all Status Codes and their Counts

This is useful for quickly spotting a large number of 404 Not Found or 5xx errors.
Bash

jq '.status_codes[] | "\(.status): \(.hits)"' summary.json

Example output:
Plaintext

"200: 4500"
"304: 1200"
"404: 350"
"502: 5"

Analyze Specific URI Traffic

If you want to focus on a particular URI, you can filter the ipinfo_db.json file. This example finds all requests for /api/data that resulted in a 200 status code.
Bash

jq 'select(.uri=="/api/data" and .status=="200")' ipinfo_db.json

Example output:
JSON

{
  "ip": "1.2.3.4",
  "uri": "/api/data",
  "status": "200",
  "asn": "AS12345 Example ISP",
  "type": "valid_http",
  "ipinfo": {
    "ip": "1.2.3.4",
    "city": "New York",
    "region": "New York",
    "country": "US",
    ...
  },
  "timestamp": "2025-09-26T15:00:00Z"
}

------------------------------------------------

UFW Log Analyzer(lgeufw.py): IP Enrichment and Summary Generator

This script, ufw_log_analyzer.py, processes the ufw.log file, extracts critical firewall connection details (Source IP, Destination Port, Protocol, Action), and enriches the external source IP addresses with geolocation and ASN (Autonomous System Number) data using the ipinfo.io API.

It's designed to run periodically to build a historical database of connection attempts and generate actionable summaries, helping you quickly identify top attackers, most scanned ports, and traffic patterns.
Quick Setup
1. Prerequisites

    Python 3.x

    ipinfo.io API Token: Required for IP enrichment. Sign up for a token on the ipinfo.io website.

    Required Python Libraries:

    pip install requests

    (Note: ipaddress is part of the standard library and does not require a separate installation.)

2. Configuration

Before running the script, you must update the Config class inside the Python file:

class Config:
    # Path to the UFW log file (standard location)
    ACCESS_LOG = "/var/log/ufw.log" 
    # Output database of enriched log entries
    OUTPUT_DB = "ufw_ipinfo_db.json"
    # Summary statistics file
    SUMMARY_FILE = "ufw_summary.json"
    # ipinfo.io API token (REPLACE THIS)
    TOKEN = "YOUR_TOKEN_CHANGE" 
    # ... other settings

    TOKEN: Replace "YOUR_TOKEN_CHANGE" with your actual ipinfo.io API token.

    ACCESS_LOG: Verify that this path points to your UFW log file.

3. Execution

Make the script executable and run it once:

chmod +x lgeufw.py
./lgeufw.py

This will create two files:

    ufw_ipinfo_db.json: A newline-delimited JSON file (.jsonl) containing every unique, enriched log entry.

    ufw_summary.json: A summary of aggregated statistics.

Automation with Cron

To keep your log database and summary up-to-date hourly, set up a simple crontab entry.

    Open your crontab editor:

    crontab -e

    Add the following line, ensuring you use the full path to the Python script:

    0 * * * * /usr/bin/python3 /path/to/your/script/lgeufw.py

        This schedules the script to run every hour at the start of the hour (e.g., 01:00, 02:00, etc.).

        Using the absolute path for Python (/usr/bin/python3) and the script itself is highly recommended for cron jobs to avoid environment path issues.

🔍 Data Analysis with jq

The ufw_summary.json file is generated with top statistics. Here are several useful jq commands to analyze the output.
1. Identify Top 10 Attacking Countries (All Actions)

This command pulls the top countries that have generated traffic, regardless of whether they were blocked or allowed.

jq '.country_stats' ufw_summary.json

2. Find the Top 5 Most Targeted Ports

Identify which destination ports (DPT) on your server are receiving the most traffic attempts. This helps prioritize hardening services.

jq '.top_ports[:5]' ufw_summary.json

Example Output:

[
  {
    "port": "22",
    "hits": 1500
  },
  {
    "port": "80",
    "hits": 800
  },
  ...
]

3. Summarize Blocked vs. Allowed Actions

Check the overall ratio of firewall actions. A high count of BLOCK actions is normal; a high count of UNKNOWN might indicate parsing issues.

jq '.actions[] | "\(.action): \(.hits)"' ufw_summary.json

Example Output:

"BLOCK: 5200"
"ALLOW: 450"
"UNKNOWN: 3"

4. Detailed Lookup: Filter Full Database for Blocked SSH Attempts

Use the ufw_ipinfo_db.json file for granular searches. This example filters for all entries where the action was BLOCK and the destination port was 22 (SSH). The -c flag outputs the result in a compact (single-line) format.

jq -c 'select(.action=="BLOCK" and .dst_port=="22")' ufw_ipinfo_db.json

5. Aggregate Hits by ASN for Top IPs

If you want to see which ASN is responsible for the top 10 source IPs, you can pipe the output:

jq -r '.top_src_ips[] | .ip + " | " + (.ipinfo.org // "N/A")' ufw_summary.json

(Note: If the summary structure has been flattened and doesn't contain ipinfo details, use the asn field instead for a simpler query: jq -r '.asn_stats[] | "\(.asn): \(.hits)"' ufw_summary.json)
