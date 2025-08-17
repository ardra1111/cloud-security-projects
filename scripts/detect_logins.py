import re
from datetime import datetime, timedelta
from collections import defaultdict

# Regex to parse SSH log lines
LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s.*sshd.*Failed password for invalid user (?P<user>\w+) from (?P<ip>[0-9.]+)'
)

# Month lookup table
MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

def parse_timestamp(month, day, time_str):
    now = datetime.now()
    return datetime(
        now.year,
        MONTHS[month],
        int(day),
        int(time_str.split(':')[0]),
        int(time_str.split(':')[1]),
        int(time_str.split(':')[2])
    )

def detect_bruteforce(log_file, threshold=3, window_minutes=5):
    failed_attempts = defaultdict(list)
    alerts = []

    with open(log_file, "r") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                ts = parse_timestamp(match["month"], match["day"], match["time"])
                ip = match["ip"]
                failed_attempts[ip].append(ts)

    # Analyze failed logins in rolling windows
    for ip, times in failed_attempts.items():
        times.sort()
        for i in range(len(times)):
            window = [
                t for t in times
                if t >= times[i] and t <= times[i] + timedelta(minutes=window_minutes)
            ]
            if len(window) >= threshold:
                alerts.append(
                    f"Potential brute force: {len(window)} failed logins "
                    f"from {ip} within {window_minutes} mins at {times[i]}"
                )
                break

    return alerts

if __name__ == "__main__":
    alerts = detect_bruteforce("../logs/auth.log")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious activity detected.")
