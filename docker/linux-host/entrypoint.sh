#!/bin/sh
set -eu

# Password del usuario de solo lectura (grupo adm: puede leer /var/log sin sudo)
echo "collector:${COLLECTOR_PASSWORD:-collector-lab}" | chpasswd

ssh-keygen -A >/dev/null
rsyslogd
/usr/local/bin/noise.sh &

exec /usr/sbin/sshd -D -e
