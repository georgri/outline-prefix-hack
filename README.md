# outline-prefix-hack

Lets Happ (Xray `finalmask` `header-custom`) clients that send the Outline
prefix `16 03 01 00 a8 01 01` connect to a stock Outline server, without
breaking real Outline clients.

Outline puts the prefix inside the 32-byte Shadowsocks salt. Happ sends it in
front of a full salt, which outline-ss-server cannot decrypt.
`outline-prefix-compat` is a small TCP proxy in front of outline-ss-server that
strips the 7 bytes only when the following salt opens an AEAD chunk with one of
the server's keys. Everything else is forwarded unchanged. UDP is not touched.

- `outline-prefix-compat.c`: the proxy.
- `install.sh`: installs it as a systemd service with a fail-safe iptables redirect.
- `selftest.py`: checks Outline, plain, and Happ handshakes against a server.
- `PROMPT.md`: step-by-step instructions, including build, verification, and rollback.

Build (static, runs on Ubuntu 20+):

```sh
gcc -O2 -Wall -static -o outline-prefix-compat.static outline-prefix-compat.c -l:libcrypto.a -lpthread
```
