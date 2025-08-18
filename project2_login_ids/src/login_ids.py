#!/usr/bin/env python3
import re
import json
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta, timezone
from math import radians, sin, cos, asin, sqrt
from ip_geo_map import IP_GEO

LOG_PATH = "../data/auth_events.log"
OUT_JSON = "../out/alerts.json"
OUT_MD   = "../docs/incident_report.md"

# Tunables
FAILED_THRESHOLD = 5       # >=5 FAILs
WINDOW_MINUTES   = 5       # within 5 minutes
IMPOSSIBLE_SPEED = 800.0   # km/h, if required speed > this => impossible travel
MIN_BASELINE_SUCCESSES = 1 # min past successes before considering new-country alert

KV_RE = re.compile(r'(\w+)=([^\s]+)')

def parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"): 
        return None
    # Expect leading ISO timestamp then key=value pairs
    # e.g., 2025-08-17T11:04:50Z user=admin event=FAIL ip=203.0.113.200
    parts = line.split()
    ts_raw = parts[0]
    kvs = " ".join(parts[1:])
    data = dict(KV_RE.findall(kvs))
    # normalize timestamp
    if ts_raw.endswith("Z"):
        ts_raw = ts_raw.replace("Z", "+00:00")
    ts = datetime.fromisoformat(ts_raw)
    # shape event
    evt = {
        "ts": ts,
        "user": data.get("user", "unknown"),
        "event": data.get("event", "UNKNOWN"),
        "ip": data.get("ip", "0.0.0.0")
    }
    return evt

def haversine_km(lat1, lon1, lat2, lon2):
    # great-circle distance between two points (km)
    R = 6371.0
    dlat = radians(lat2-lat1)
    dlon = radians(lon2-lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    c = 2*asin(sqrt(a))
    return R*c

def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            evt = parse_line(line)
            if evt:
                events.append(evt)
    events.sort(key=lambda e: e["ts"])
    return events

def detect_bruteforce(events):
    """Detect >= FAILED_THRESHOLD FAILs from same IP within WINDOW_MINUTES."""
    window = timedelta(minutes=WINDOW_MINUTES)
    fails_by_ip = defaultdict(deque)
    alerts = []

    for e in events:
        if e["event"] != "FAIL":
            continue
        ip = e["ip"]
        q = fails_by_ip[ip]
        q.append(e["ts"])
        # drop outside window
        while q and (e["ts"] - q[0]) > window:
            q.popleft()
        if len(q) >= FAILED_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "count": len(q),
                "window_minutes": WINDOW_MINUTES,
                "last_seen": e["ts"].isoformat(),
                "recommendation": "Block IP; enable MFA; enforce key-based auth; add temporary ban."
            })
    # dedupe by ip taking the highest count
    dedup = {}
    for a in alerts:
        k = a["ip"]
        if k not in dedup or a["count"] > dedup[k]["count"]:
            dedup[k] = a
    return list(dedup.values())

def detect_impossible_travel(events):
    """Detect same user SUCCESS from far locations too quickly."""
    last_success = {}  # user -> (ts, cc, city, lat, lon, ip)
    alerts = []

    for e in events:
        if e["event"] != "SUCCESS":
            continue
        ip = e["ip"]
        user = e["user"]
        geo = IP_GEO.get(ip)
        if not geo:
            # unknown/priv IPs => skip impossible-travel
            continue
        cc, city, lat, lon = geo
        if user in last_success:
            ts0, cc0, city0, lat0, lon0, ip0 = last_success[user]
            dt_hours = (e["ts"] - ts0).total_seconds()/3600.0
            if dt_hours > 0:
                dist = haversine_km(lat0, lon0, lat, lon)
                speed = dist / dt_hours
                if speed > IMPOSSIBLE_SPEED:
                    alerts.append({
                        "type": "IMPOSSIBLE_TRAVEL",
                        "user": user,
                        "from": {"ip": ip0, "cc": cc0, "city": city0},
                        "to":   {"ip": ip,  "cc": cc,  "city": city},
                        "time_delta_hours": round(dt_hours,2),
                        "distance_km": round(dist,1),
                        "required_speed_kmh": round(speed,1),
                        "threshold_kmh": IMPOSSIBLE_SPEED,
                        "recommendation": "Challenge user; require MFA; review session risk; alert SOC."
                    })
        # update last success
        last_success[user] = (e["ts"], cc, city, lat, lon, ip)
    return alerts

def summarize(events, alerts):
    by_type = Counter(a["type"] for a in alerts)
    total = len(alerts)
    # top fail IPs
    fail_counts = Counter(e["ip"] for e in events if e["event"]=="FAIL")
    top_fail = fail_counts.most_common(5)
    return {"total_alerts": total, "by_type": dict(by_type), "top_fail_ips": top_fail}

def write_outputs(alerts, summary):
    # JSON
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump({"alerts": alerts, "summary": summary}, f, indent=2)

    # Markdown report
    lines = []
    lines.append("# Incident Report — Login Intrusion Detection (Simulated)")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Total alerts: **{summary['total_alerts']}**")
    for t, c in summary["by_type"].items():
        lines.append(f"- {t.replace('_',' ').title()}: **{c}**")
    lines.append("")
    lines.append("## Top failing IPs")
    if summary["top_fail_ips"]:
        for ip, c in summary["top_fail_ips"]:
            lines.append(f"- {ip}: {c} failed attempts")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Detailed Alerts")
    for a in alerts:
        lines.append(f"### {a['type']}")
        for k,v in a.items():
            if k=="type": continue
            lines.append(f"- **{k}**: {v}")
        lines.append("")
    lines.append("## Recommendations")
    lines.append("- Enforce key-based SSH + disable passwords")
    lines.append("- Require MFA for privileged logins")
    lines.append(f"- Brute-force rule: >= {FAILED_THRESHOLD} FAILs in {WINDOW_MINUTES} minutes → alert/ban")
    lines.append("- Investigate impossible-travel alerts; reset sessions if necessary")
    md = "\n".join(lines)
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write(md)

def main():
    events = load_events(LOG_PATH)
    alerts = []
    alerts += detect_bruteforce(events)
    alerts += detect_impossible_travel(events)
    summary = summarize(events, alerts)
    # Console output
    print("=== ALERTS ===")
    for a in alerts:
        print(json.dumps(a, indent=2))
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    # Files
    write_outputs(alerts, summary)
    print(f"\nWrote JSON: {OUT_JSON}")
    print(f"Wrote Report: {OUT_MD}")

if __name__ == "__main__":
    main()
