Two python scripts that enrich nginx access and ufw logs with geo information on IP addresses

lge.sh - original script

lgeaccess.py - This Python script is a tool for enriching your Nginx access logs with geographic and network information using the ipinfo.io API. It processes your logs, looks up IP addresses, and saves the enriched data into a JSON database. It also generates a summary of the most common requests, countries, and status codes, providing valuable insights into your web traffic.

lgeufw.py - enrich firewall logs with geo information, writes two files ufw_ipinfo_db.json contains all information about entries from log, ufw_summary.json contains summarized top information about log entries.

Display information from .json files with jq or create webserver that presents information.

Get top blocked IP in ufw jq -r 'select(.action=="BLOCK") | .ip' ufw_ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10

Got top requested IP for specific uri jq -r 'select(.uri=="/.env") | .ip' ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10


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
