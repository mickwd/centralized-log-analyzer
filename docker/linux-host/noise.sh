#!/bin/sh
# Genera actividad de logs. NOISE_PROFILE=bruteforce | crashloop
set -u
PROFILE="${NOISE_PROFILE:-bruteforce}"
i=0

while true; do
    i=$((i + 1))
    logger -p cron.info -t "CRON[$$]" "(root) CMD (/usr/local/bin/backup-check.sh > /dev/null 2>&1)"
    logger -p auth.info -t "sshd[$$]" "Accepted publickey for deploy from 10.10.0.5 port $((40000 + i % 20000)) ssh2"

    # Cada ~5 minutos, un evento del perfil elegido
    if [ $((i % 10)) -eq 0 ]; then
        case "$PROFILE" in
            bruteforce)
                n=0
                while [ $n -lt 15 ]; do
                    logger -p auth.info -t "sshd[$((2000 + n))]" \
                        "Failed password for invalid user admin from 203.0.113.45 port $((50000 + n)) ssh2"
                    n=$((n + 1))
                    sleep 1
                done
                ;;
            crashloop)
                n=1
                while [ $n -le 4 ]; do
                    logger -p daemon.err -t "demo-app[$((3000 + n))]" "Error: connect ECONNREFUSED 10.10.0.21:5432"
                    logger -p daemon.notice -t "systemd[1]" \
                        "demo-app.service: Main process exited, code=exited, status=1/FAILURE"
                    logger -p daemon.notice -t "systemd[1]" \
                        "demo-app.service: Scheduled restart job, restart counter is at $n."
                    n=$((n + 1))
                    sleep 5
                done
                ;;
        esac
    fi
    sleep 30
done
