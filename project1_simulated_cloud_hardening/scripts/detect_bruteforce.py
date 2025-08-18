#!/usr/bin/env python3
"""
detect_bruteforce.py
Simple log parser: find IPs with many Failed password entries
Usage: python3 detect_bruteforce.py ../logs/auth.log
"""
import sys
import re
from collections import Counter
from datetime import datetime

LOGPATH = sys.argv[1] if len(sys.argv) > 1 else "../logs/auth.log"
THRESHOLD = 10  # mark IPs with > THRESHOLD failed attempts

# regex to find Failed password lines and extract IP
pat = re.compile(r'Failed password .* from (\d+\.\d+\.\d+\.\d+)')

counts = Counter()
times = {}

with open(LOGPATH, 'r', errors='ignore') as fh:
    for line in fh:
        m = pat.search(line)
        if m:
            ip = m.group(1)
            counts[ip] += 1
            # record last seen timestamp (if present)
            try:
                ts_str = " ".join(line.split()[:3])
                times[ip] = ts_str
            except Exception:
                pass

offenders = [(ip, counts[ip], times.get(ip, 'N/A')) for ip in counts if counts[ip] > THRESHOLD]
offenders.sort(key=lambda x: -x[1])

report = {
    "generated_at": datetime.utcnow().isoformat()+"Z",
    "threshold": THRESHOLD,
    "offenders": []
}

for ip, c, last_seen in offenders:
    report["offenders"].append({
        "ip": ip,
        "failed_attempts": c,
        "last_seen": last_seen,
        "recommendation": "Block IP via firewall, investigate source, consider temporary ban"
    })

if report["offenders"]:
    import json
    print(json.dumps(report, indent=2))
else:
    print("No IP exceeded threshold =", THRESHOLD)
