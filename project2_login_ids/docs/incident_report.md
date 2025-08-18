# Incident Report — Login Intrusion Detection (Simulated)
**Generated:** 2025-08-18T16:19:15.669211+00:00

## Summary
- Total alerts: **2**
- Brute Force: **1**
- Impossible Travel: **1**

## Top failing IPs
- 203.0.113.200: 6 failed attempts
- 203.0.113.77: 3 failed attempts
- 198.51.100.5: 1 failed attempts

## Detailed Alerts
### BRUTE_FORCE
- **ip**: 203.0.113.200
- **count**: 6
- **window_minutes**: 5
- **last_seen**: 2025-08-17T11:05:00+00:00
- **recommendation**: Block IP; enable MFA; enforce key-based auth; add temporary ban.

### IMPOSSIBLE_TRAVEL
- **user**: ardra
- **from**: {'ip': '203.0.113.10', 'cc': 'IN', 'city': 'Mumbai'}
- **to**: {'ip': '198.51.100.23', 'cc': 'GB', 'city': 'London'}
- **time_delta_hours**: 0.5
- **distance_km**: 7191.7
- **required_speed_kmh**: 14383.4
- **threshold_kmh**: 800.0
- **recommendation**: Challenge user; require MFA; review session risk; alert SOC.

## Recommendations
- Enforce key-based SSH + disable passwords
- Require MFA for privileged logins
- Brute-force rule: >= 5 FAILs in 5 minutes → alert/ban
- Investigate impossible-travel alerts; reset sessions if necessary