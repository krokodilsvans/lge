#!/bin/bash
ACCESS_LOG="/var/log/nginx/access.log"
OUTPUT_DB="./ipinfo_db.json"
TOKEN="YOUR_IPINFO_TOKEN"

# Ensure output file exists
touch "$OUTPUT_DB"

tail -f "$ACCESS_LOG" | while read line; do
  ip=$(echo "$line" | awk '{print $1}')
  uri=$(echo "$line" | awk -F\" '{print $2}' | awk '{print $2}')

  # Skip invalid IPs (like localhost or -)
  if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    continue
  fi

  # Query IPinfo Lite
  data=$(curl -s "https://ipinfo.io/$ip?token=$TOKEN")

  # Merge with log info
  enriched=$(jq -n \
    --arg ip "$ip" \
    --arg uri "$uri" \
    --argjson info "$data" \
    '{ip: $ip, uri: $uri, ipinfo: $info}')

  # Append as JSON line ("database")
  echo "$enriched" >> "$OUTPUT_DB"

  echo "[+] Enriched $ip → stored in DB"
done

