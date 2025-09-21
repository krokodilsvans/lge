#!/usr/bin/env python3
import re, json, requests
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone, timedelta

# --- Config ---
class Config:
    #Update with log path to enrich
    ACCESS_LOG = "/var/log/nginx/access.log"
    OUTPUT_DB = "ipinfo_db.json"
    SUMMARY_FILE = "summary.json"
    TOKEN = "YOUR_TOKEN_CHANGE" 
    API_TIMEOUT = 5
    CACHE_TTL_MINUTES = 60
    # capture ip, method, uri, status
    LOG_PATTERN = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>\w+)\s+(?P<uri>\S+)[^"]*"\s+(?P<status>\d{3})')

class LogProcessor:
    def __init__(self):
        self.processed_keys=set(); self.ip_cache={}

    def _load_existing(self):
        if Path(Config.OUTPUT_DB).exists():
            with open(Config.OUTPUT_DB) as f:
                for line in f:
                    try:
                        r=json.loads(line)
                        self.processed_keys.add((r["ip"], r.get("uri") or "", r.get("type",""), r.get("status","")))
                    except: pass
        print(f"Loaded {len(self.processed_keys)} entries")

    def _detect_type(self,line):
        if "\\x16\\x03" in line: return "tls_on_http"
        if any(f'"{m} ' in line for m in ["GET","POST","HEAD"]): return "valid_http"
        return "other"

    def _get_ipinfo(self,ip):
        now=datetime.now(timezone.utc)
        if ip in self.ip_cache and now-self.ip_cache[ip]["ts"]<timedelta(minutes=Config.CACHE_TTL_MINUTES):
            return self.ip_cache[ip]["data"]
        try:
            r=requests.get(f"https://ipinfo.io/{ip}?token={Config.TOKEN}",timeout=Config.API_TIMEOUT); r.raise_for_status()
            data=r.json(); self.ip_cache[ip]={"data":data,"ts":now}; return data
        except: return {}

    def enrich_logs(self):
        self._load_existing()
        try:
            with open(Config.ACCESS_LOG) as f_in, open(Config.OUTPUT_DB,"a") as f_out:
                for line in f_in:
                    m=Config.LOG_PATTERN.search(line)
                    if not m: continue
                    ip,uri,status=m.group("ip"),m.group("uri"),m.group("status")
                    req_type=self._detect_type(line)
                    if req_type!="valid_http": uri=None
                    key=(ip,uri or "",req_type,status)
                    if key in self.processed_keys: continue
                    info=self._get_ipinfo(ip)
                    rec={
                        "ip":ip,"uri":uri,"status":status,
                        "asn":info.get("org","Unknown"),
                        "type":req_type,"ipinfo":info,
                        "timestamp":datetime.now(timezone.utc).isoformat()
                    }
                    f_out.write(json.dumps(rec)+"\n")
                    self.processed_keys.add(key)
                    print(f"Stored {ip} {uri or ''} {status} ({rec['asn']}, {req_type})")
        except FileNotFoundError: print(f"[!] Log not found: {Config.ACCESS_LOG}")

    def generate_summary(self):
        if not Path(Config.OUTPUT_DB).exists(): return
        asn_c,country_c,uri_c,type_c,status_c=Counter(),Counter(),Counter(),Counter(),Counter()
        with open(Config.OUTPUT_DB) as f:
            for line in f:
                try:
                    r=json.loads(line)
                    asn_c[r.get("asn","Unknown")]+=1
                    country_c[r.get("ipinfo",{}).get("country","Unknown")]+=1
                    if r.get("uri"): uri_c[r["uri"]]+=1
                    type_c[r.get("type","unknown")]+=1
                    status_c[r.get("status","")]+=1
                except: pass
        summary={
            "generated":datetime.now(timezone.utc).isoformat(),
            "asn_stats":[{"asn":a,"hits":c} for a,c in asn_c.most_common(10)],
            "country_stats":[{"country":c,"hits":n} for c,n in country_c.most_common(10)],
            "top_uris":[{"uri":u,"hits":n} for u,n in uri_c.most_common(10)],
            "request_types":[{"type":t,"hits":n} for t,n in type_c.most_common()],
            "status_codes":[{"status":s,"hits":n} for s,n in status_c.most_common()]
        }
        with open(Config.SUMMARY_FILE,"w") as f: json.dump(summary,f,indent=2)
        print(f"Summary written to {Config.SUMMARY_FILE}")

def main(): lp=LogProcessor(); lp.enrich_logs(); lp.generate_summary()
if __name__=="__main__": main()

