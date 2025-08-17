# Incident Report — Simulated Brute-Force Attack

## Summary
Multiple failed SSH login attempts were detected against the simulated cloud server. The automated detection script identified IPs with excessive failed attempts within a 5-minute rolling window, reflecting realistic brute-force behavior.

## Findings
- IPs exceeding threshold (3 failed logins / 5 min): 192.168.1.10, 203.0.113.1-203.0.113.60
- Attack pattern indicates brute-force attempts targeting 'admin' and 'root' users.
- Some legitimate logins were observed, showing that the system is actively used.

## Actions Taken
1. Hardened SSH configuration applied (`sshd_config.hardened`)  
   - Port 2222, PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3
2. Offending IPs added to temporary firewall/denylist
3. Continuous monitoring implemented via detection script run as cron

## Recommendations
- Enforce key-based SSH login; disable password authentication  
- Limit SSH port access and restrict allowed users  
- Use automated tools like fail2ban for dynamic blocking  
- Run detection scripts as cron jobs to monitor real-time attempts  
- Document incidents for future audits
