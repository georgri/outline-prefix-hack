#!/bin/bash
# Installs outline-prefix-compat in front of the local outline-ss-server.
# Usage: install.sh /path/to/outline-prefix-compat.static [PROXY_PORT]
set -euo pipefail

BIN_SRC=${1:?binary path}
PROXY_PORT=${2:-26392}

pid=$(pgrep -x outline-ss-serv | head -1 || true)
[ -n "$pid" ] || { echo "outline-ss-server is not running" >&2; exit 1; }
[ "$(readlink /proc/$pid/ns/net)" = "$(readlink /proc/1/ns/net)" ] || { echo "outline-ss-server is not in the host network namespace" >&2; exit 1; }

cfg=$(tr '\0' '\n' < /proc/$pid/cmdline | awk 'p{print;exit} /^-config$/{p=1}')
[ -n "$cfg" ] || { echo "cannot find -config in outline-ss-server cmdline" >&2; exit 1; }
hostcfg=$cfg
[ -f "$hostcfg" ] || { echo "config $cfg is not visible on the host" >&2; exit 1; }

ports=$(grep -E '^\s*port:' "$hostcfg" | awk '{print $2}' | sort -u)
[ "$(echo "$ports" | wc -l)" -eq 1 ] || { echo "expected one Outline port, found: $ports" >&2; exit 1; }
PORT=$ports
grep -q 'chacha20-ietf-poly1305' "$hostcfg" || { echo "no chacha20-ietf-poly1305 keys" >&2; exit 1; }
if grep -E '^\s*cipher:' "$hostcfg" | grep -vq 'chacha20-ietf-poly1305'; then
	echo "warning: some keys use other ciphers; those keys pass through unchanged" >&2
fi
if ss -ltn "( sport = :$PROXY_PORT )" | grep -q LISTEN && ! systemctl is-active -q outline-prefix-compat; then
	echo "port $PROXY_PORT is already used" >&2; exit 1
fi

install -m 755 "$BIN_SRC" /usr/local/sbin/outline-prefix-compat

RULE="-p tcp --dport $PORT ! -i lo -m addrtype --dst-type LOCAL -j REDIRECT --to-ports $PROXY_PORT"
IPT=$(command -v iptables)

cat > /etc/systemd/system/outline-prefix-compat.service <<EOF
[Unit]
Description=Outline TCP prefix compatibility proxy (port $PORT)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStartPre=-/bin/sh -c 'while $IPT -t nat -D PREROUTING $RULE 2>/dev/null; do :; done'
ExecStart=/usr/local/sbin/outline-prefix-compat $PROXY_PORT $PORT $hostcfg
ExecStartPost=/bin/sh -c 'for i in \$(seq 50); do ss -ltn | grep -q ":$PROXY_PORT " && exec $IPT -t nat -I PREROUTING 1 $RULE; sleep 0.1; done; exit 1'
ExecStopPost=-/bin/sh -c 'while $IPT -t nat -D PREROUTING $RULE 2>/dev/null; do :; done'
Restart=always
RestartSec=1
LimitNOFILE=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable outline-prefix-compat >/dev/null 2>&1
systemctl restart outline-prefix-compat
sleep 1
systemctl is-active outline-prefix-compat
$IPT -t nat -C PREROUTING $RULE && echo "redirect tcp/$PORT -> $PROXY_PORT active"
echo "PORT=$PORT PROXY_PORT=$PROXY_PORT CONFIG=$hostcfg"
