Apply the "Happ prefix" fix to the Outline server at root@<IP> over SSH.

Background
- Outline clients with `prefix=%16%03%01%00%C2%A8%01%01` send the 7 bytes
  `16 03 01 00 a8 01 01` as the first bytes of the 32-byte Shadowsocks salt.
- Happ (Xray finalmask `header-custom`) sends the same 7 bytes in front of a
  full 32-byte salt. Stock outline-ss-server cannot decrypt that, so Happ
  profiles with the prefix get no reply.
- Fix: a small TCP proxy (`outline-prefix-compat`) sits in front of
  outline-ss-server. It removes the 7 bytes only when they are followed by a
  salt that opens an AEAD chunk with one of the server's keys. Real Outline
  handshakes, plain Shadowsocks, and anything else are forwarded byte-for-byte.
  UDP is not touched.

Files (in this folder)
- `outline-prefix-compat.c`: proxy source. Args: `LISTEN_PORT UPSTREAM_PORT CONFIG_YML`.
  Reloads keys when config.yml changes.
- `install.sh`: run on the server. Detects the Outline port and config from the
  running outline-ss-server, installs `/usr/local/sbin/outline-prefix-compat`, and
  creates `outline-prefix-compat.service`. The service adds an iptables nat
  PREROUTING REDIRECT (external tcp/<port> -> 26392) only after the proxy is
  listening, and removes it whenever the proxy stops or crashes, so clients fall
  back to talking to Outline directly.
- `selftest.py`: from a client machine, `selftest.py HOST PORT` with a key's password
  on stdin. It tests outline-prefix, plain, happ-prefix, and happ-split handshakes.

Steps
1. Survey without changing anything: `outline-ss-server` must run in the host
   network namespace with `-config /opt/outline/persisted-state/outline-ss-server/config.yml`,
   all keys on a single port, cipher `chacha20-ietf-poly1305`. Note `ip -4 addr`.
   If SSH reports a changed host key or auth fails, stop and ask; do not bypass it.
2. Get a binary. Target servers usually have no gcc, so build a static one on any
   Ubuntu host with `gcc` and `libssl-dev` (OpenSSL 3):
   `gcc -O2 -Wall -static -o outline-prefix-compat.static outline-prefix-compat.c -l:libcrypto.a -lpthread`
   (dlopen/getaddrinfo static warnings are harmless). The static binary also runs on
   Ubuntu 20 (OpenSSL 1.1 hosts).
3. Baseline: run `selftest.py <IP> <PORT>` with one key's password piped in from the
   server (never print secrets). Expect outline-prefix and plain OK, happ-* FAIL.
4. Copy the binary and `install.sh` to `/root/`, then run
   `bash /root/install.sh /root/outline-prefix-compat.static`.
5. Re-run selftest: all four must be OK.
6. Check fail-safe: `systemctl kill -s KILL outline-prefix-compat`. The redirect rule
   must disappear (`iptables -t nat -S PREROUTING | grep 26392` empty), outline-prefix
   and plain must still work, and within about 2 s the service must be active again
   with the rule back.
7. Watch `journalctl -u outline-prefix-compat -o cat`: `stats outline=N strip=M raw=K`,
   with no `upstream-fail`.

UDP on servers with more than one IPv4
Check `hostname` in /opt/outline/persisted-state/shadowbox_server_config.json.
If it is not the primary address (the source of the default route), outline-ss-server
answers UDP from the primary address and clients drop the replies, so DNS and QUIC
through Happ break. Run on the server:
  bash install-udp-fix.sh <ADVERTISED_IP> <PRIMARY_IP> <PORT>
It DNATs UDP sent to the advertised IP onto the primary IP, so conntrack restores
the advertised IP as the reply source. Clients that use the primary IP are unaffected.
Verify from a host whose network does not filter that UDP port (many office networks
do): send a Shadowsocks UDP DNS query to each IP and check that the reply comes from
the same IP:port.

Side effect: outline-ss-server now sees TCP clients as 127.0.0.1, so per-country
and per-ASN TCP metrics in the Outline Manager become "unknown". Per-key data
usage is unaffected.

Rollback: `systemctl disable --now outline-prefix-compat` (also removes the redirect).
