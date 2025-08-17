#!/bin/bash
LOGFILE=../logs/auth.log
mkdir -p ../logs
for i in $(seq 1 180); do
  TIMESTAMP=$(date +"%b %d %H:%M:%S")
  IP="203.0.113.$(( (i % 60) + 1 ))"
  echo "$TIMESTAMP server sshd[1]: Failed password for invalid user admin from $IP port $((30000 + i)) ssh2" >> $LOGFILE
  if (( i % 40 == 0 )); then
    echo "$TIMESTAMP server sshd[1]: Accepted password for ardra from 198.51.100.$(( (i/40) )) port $((40000 + i)) ssh2" >> $LOGFILE
  fi
done
echo "Simulation complete. Wrote $LOGFILE"
