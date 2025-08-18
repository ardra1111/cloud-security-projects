# Project 2: Login Intrusion Detection System 

**Goal:** Detect suspicious login behavior from logs 

## Detects
- **Brute-force**: >=5 failed logins from the same IP within 5 minutes
- **Impossible travel**: user success logins from far-apart geos too quickly (>800 km/h implied)

## How it works
- Parses a simple `key=value` log format with ISO timestamps
- Uses an offline IP→Geo map for demo geolocations
- Outputs JSON alerts and a Markdown incident report

## Quick start
```bash
cd project2_login_ids/src
python3 login_ids.py
```

## Outputs

../out/alerts.json

../docs/incident_report.md


