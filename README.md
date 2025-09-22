Two python scripts that enrich nginx access and ufw logs with geo information on IP addresses

lge.sh - original script

lgeaccess.py - enrich nginx access logs and write to two json files ipinfo_db.json contains information about all visitors, summary.json contains summarized information about where visitor hits, status_code, request_type, uri, country etc

lgeufw.py - enrich firewall logs with geo information, writes two files ufw_ipinfo_db.json contains all information about entries from log, ufw_summary.json contains summarized top information about log entries.

Display information from .json files with jq or create webserver that presents information.

Get top blocked IP in ufw jq -r 'select(.action=="BLOCK") | .ip' ufw_ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10

Got top requested IP for specific uri jq -r 'select(.uri=="/.env") | .ip' ipinfo_db.json | sort | uniq -c | sort -nr | head -n 10
