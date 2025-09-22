#!/usr/bin/env python3
import re, json, requests, ipaddress
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone, timedelta

# --- Config ---
class Config:
    # Path to the UFW log file
    ACCESS_LOG = "/var/log/ufw.log"
    # Output database of enriched log entries
    OUTPUT_DB = "ufw_ipinfo_db.json"
    # Summary statistics file
    SUMMARY_FILE = "ufw_summary.json"
    # ipinfo.io API token (replace with your own)
    TOKEN = "YOUR_TOKEN_CHANGE"
    # API settings
    API_TIMEOUT = 5
    CACHE_TTL_MINUTES = 60

    # Regex for extracting log fields
    LOG_PATTERN = re.compile(
        r"SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?"
        r"PROTO=(?P<proto>\w+)\s+"
        r"SPT=(?P<src_port>\d+)\s+"
        r"DPT=(?P<dst_port>\d+)"
    )
    # Regex for extracting timestamp
    TS_PATTERN = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)")
    # Regex for extracting UFW action (BLOCK/ALLOW)
    ACTION_PATTERN = re.compile(r"\[UFW\s+(?P<action>[A-Z]+)\]")


class LogProcessor:
    def __init__(self):
        self.processed_keys = set()
        self.ip_cache = {}

    def _load_existing(self):
        """Load already processed entries to avoid duplicates."""
        if Path(Config.OUTPUT_DB).exists():
            with open(Config.OUTPUT_DB) as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        self.processed_keys.add(
                            (r["ip"], r.get("proto", ""), r.get("dst_port", ""), r.get("action", ""))
                        )
                    except:
                        pass
        print(f"Loaded {len(self.processed_keys)} entries")

    def _is_private_ip(self, ip: str) -> bool:
        """Return True if the IP is private, loopback, or link-local."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return True

    def _get_ipinfo(self, ip):
        """Fetch ASN and geo info from ipinfo.io, with caching."""
        now = datetime.now(timezone.utc)
        if (
            ip in self.ip_cache
            and now - self.ip_cache[ip]["ts"] < timedelta(minutes=Config.CACHE_TTL_MINUTES)
        ):
            return self.ip_cache[ip]["data"]
        try:
            r = requests.get(
                f"https://ipinfo.io/{ip}?token={Config.TOKEN}",
                timeout=Config.API_TIMEOUT,
            )
            r.raise_for_status()
            data = r.json()
            self.ip_cache[ip] = {"data": data, "ts": now}
            return data
        except:
            return {}

    def enrich_logs(self):
        """Process log file, enrich IPs, and write to the output database."""
        self._load_existing()
        try:
            with open(Config.ACCESS_LOG) as f_in, open(Config.OUTPUT_DB, "a") as f_out:
                for line in f_in:
                    m = Config.LOG_PATTERN.search(line)
                    if not m:
                        continue

                    # Extract main fields
                    ip = m.group("src_ip")
                    dst_ip = m.group("dst_ip")
                    proto = m.group("proto")
                    src_port = m.group("src_port")
                    dst_port = m.group("dst_port")

                    # Extract timestamp
                    ts_match = Config.TS_PATTERN.match(line)
                    log_ts = ts_match.group("ts") if ts_match else datetime.now(timezone.utc).isoformat()

                    # Extract UFW action
                    a_match = Config.ACTION_PATTERN.search(line)
                    action = a_match.group("action") if a_match else "UNKNOWN"

                    # Skip private source IPs
                    if self._is_private_ip(ip):
                        continue

                    # Deduplication key
                    key = (ip, proto, dst_port, action)
                    if key in self.processed_keys:
                        continue

                    # Fetch enrichment data
                    info = self._get_ipinfo(ip)
                    rec = {
                        "ip": ip,
                        "dst_ip": dst_ip,
                        "proto": proto,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "asn": info.get("org", "Unknown"),
                        "country": info.get("country", "Unknown"),
                        "ipinfo": info,
                        "timestamp": log_ts,
                        "action": action,
                    }
                    f_out.write(json.dumps(rec) + "\n")
                    self.processed_keys.add(key)
                    print(f"Stored {ip}:{src_port}->{dst_port}/{proto} [{action}] ({rec['asn']})")
        except FileNotFoundError:
            print(f"[!] Log not found: {Config.ACCESS_LOG}")

    def generate_summary(self):
        """Aggregate statistics and write a summary JSON file."""
        if not Path(Config.OUTPUT_DB).exists():
            return
        asn_c, country_c, port_c, proto_c, ip_c, action_c = (
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
            Counter(),
        )
        with open(Config.OUTPUT_DB) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    asn_c[r.get("asn", "Unknown")] += 1
                    country_c[r.get("country", "Unknown")] += 1
                    port_c[r.get("dst_port", "")] += 1
                    proto_c[r.get("proto", "unknown")] += 1
                    ip_c[r.get("ip", "")] += 1
                    action_c[r.get("action", "UNKNOWN")] += 1
                except:
                    pass
        summary = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "asn_stats": [{"asn": a, "hits": c} for a, c in asn_c.most_common(10)],
            "country_stats": [{"country": c, "hits": n} for c, n in country_c.most_common(10)],
            "top_ports": [{"port": p, "hits": n} for p, n in port_c.most_common(10)],
            "protocols": [{"proto": t, "hits": n} for t, n in proto_c.most_common()],
            "top_src_ips": [{"ip": ip, "hits": n} for ip, n in ip_c.most_common(10)],
            "actions": [{"action": a, "hits": n} for a, n in action_c.most_common()],
        }
        with open(Config.SUMMARY_FILE, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"Summary written to {Config.SUMMARY_FILE}")


def main():
    lp = LogProcessor()
    lp.enrich_logs()
    lp.generate_summary()


if __name__ == "__main__":
    main()

