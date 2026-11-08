#!/bin/bash
# Makes Outline UDP replies come back from the address the client used.
# Needed when Outline advertises a secondary IPv4: outline-ss-server answers
# from the primary address, and clients drop those replies.
# Usage: install-udp-fix.sh ADVERTISED_IP PRIMARY_IP PORT
set -euo pipefail
ADV=${1:?advertised ip}
PRI=${2:?primary ip}
PORT=${3:?outline port}
ip -4 -o addr show | grep -q " $ADV/" || { echo "$ADV is not on this host" >&2; exit 1; }
ip -4 -o addr show | grep -q " $PRI/" || { echo "$PRI is not on this host" >&2; exit 1; }
IPT=$(command -v iptables)
RULE="-d $ADV -p udp --dport $PORT -j DNAT --to-destination $PRI"

cat > /etc/systemd/system/outline-udp-src.service <<EOF
[Unit]
Description=Outline UDP replies from the advertised address ($ADV:$PORT)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/bin/sh -c 'while $IPT -t nat -D PREROUTING $RULE 2>/dev/null; do :; done'
ExecStart=$IPT -t nat -I PREROUTING 1 $RULE
ExecStop=-/bin/sh -c 'while $IPT -t nat -D PREROUTING $RULE 2>/dev/null; do :; done'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable outline-udp-src >/dev/null 2>&1
systemctl restart outline-udp-src
$IPT -t nat -C PREROUTING $RULE && echo "udp $ADV:$PORT -> $PRI:$PORT active"
