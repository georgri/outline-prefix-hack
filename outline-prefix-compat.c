/* TCP front for outline-ss-server.
 * Outline clients put 16 03 01 00 a8 01 01 at the start of the 32-byte salt.
 * Happ's header-custom sends those 7 bytes and then a normal salt.
 * Strip the 7 bytes only when the following salt opens an AEAD chunk.
 * Anything else, including a real Outline handshake, is forwarded unchanged.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_KEYS 1024
#define SECRET_MAX 128
#define CAP 16384
#define MAX_CONN 8192
#define PROBE_SECS 5

static const uint8_t PREFIX[7] = {0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01};

struct key {
	uint8_t master[32];
};

static struct key g_keys[MAX_KEYS];
static int g_nkeys;
static time_t g_mtime;
static unsigned long n_outline, n_strip, n_raw;
static const char *g_config = "/opt/outline/persisted-state/outline-ss-server/config.yml";
static int g_listen_port = 26392;
static int g_upstream_port = 26390;

static void die(const char *m) {
	perror(m);
	exit(1);
}

static void evp_bytes_to_key(const uint8_t *pass, size_t passlen, uint8_t out[32]) {
	uint8_t prev[EVP_MAX_MD_SIZE];
	unsigned int prevlen = 0;
	size_t filled = 0;
	while (filled < 32) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (!ctx) die("md");
		EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
		if (prevlen) EVP_DigestUpdate(ctx, prev, prevlen);
		EVP_DigestUpdate(ctx, pass, passlen);
		EVP_DigestFinal_ex(ctx, prev, &prevlen);
		EVP_MD_CTX_free(ctx);
		size_t take = 32 - filled;
		if (take > prevlen) take = prevlen;
		memcpy(out + filled, prev, take);
		filled += take;
	}
}

static int hkdf_subkey(const uint8_t master[32], const uint8_t salt[32], uint8_t out[32]) {
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (!kdf) return 0;
	EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (!ctx) return 0;
	char digest[] = "SHA1";
	unsigned char info[] = "ss-subkey";
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string("digest", digest, 0),
		OSSL_PARAM_construct_octet_string("key", (void *)master, 32),
		OSSL_PARAM_construct_octet_string("salt", (void *)salt, 32),
		OSSL_PARAM_construct_octet_string("info", info, sizeof(info) - 1),
		OSSL_PARAM_construct_end(),
	};
	int ok = EVP_KDF_derive(ctx, out, 32, params) == 1;
	EVP_KDF_CTX_free(ctx);
	return ok;
}

/* Shadowsocks AEAD length chunk: 2-byte ciphertext + 16-byte tag, nonce 0. */
static int open_len_chunk(const uint8_t subkey[32], const uint8_t chunk[18]) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return 0;
	uint8_t iv[12] = {0};
	uint8_t plain[8];
	int len = 0, fin = 0, ok = 0;
	if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto done;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto done;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, subkey, iv) != 1) goto done;
	if (EVP_DecryptUpdate(ctx, plain, &len, chunk, 2) != 1) goto done;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)(chunk + 2)) != 1) goto done;
	if (EVP_DecryptFinal_ex(ctx, plain + len, &fin) != 1) goto done;
	ok = 1;
done:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

static int salt_opens(const uint8_t *salt, const uint8_t *chunk) {
	for (int i = 0; i < g_nkeys; i++) {
		uint8_t sub[32];
		if (!hkdf_subkey(g_keys[i].master, salt, sub)) continue;
		if (open_len_chunk(sub, chunk)) return 1;
	}
	return 0;
}

static void load_keys(void) {
	FILE *f = fopen(g_config, "r");
	if (!f) die("open config");
	struct key next[MAX_KEYS];
	int n = 0;
	char line[512];
	while (fgets(line, sizeof line, f)) {
		char *p = strstr(line, "secret:");
		if (!p) continue;
		p += 7;
		while (*p == ' ' || *p == '\t') p++;
		size_t len = strcspn(p, " \t\r\n");
		if (len == 0 || len > SECRET_MAX || n >= MAX_KEYS) continue;
		evp_bytes_to_key((uint8_t *)p, len, next[n].master);
		n++;
	}
	fclose(f);
	if (n == 0) {
		fprintf(stderr, "no secrets in config\n");
		return;
	}
	memcpy(g_keys, next, sizeof(next[0]) * n);
	g_nkeys = n;
	struct stat st;
	if (stat(g_config, &st) == 0) g_mtime = st.st_mtime;
	fprintf(stderr, "loaded %d keys\n", g_nkeys);
}

static void maybe_reload(void) {
	struct stat st;
	if (stat(g_config, &st) != 0) return;
	if (st.st_mtime != g_mtime) load_keys();
}

struct conn {
	int fd[2];
	int up[2];
	unsigned char *buf[2];
	int len[2];
	int off[2];
	int probing;
	time_t started;
};

static struct conn conns[MAX_CONN];

static void conn_close(struct conn *c) {
	for (int i = 0; i < 2; i++) {
		if (c->fd[i] >= 0) close(c->fd[i]);
		free(c->buf[i]);
	}
	memset(c, 0, sizeof *c);
	c->fd[0] = c->fd[1] = -1;
}

static int set_nb(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int dial_upstream(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	struct sockaddr_in a = {0};
	a.sin_family = AF_INET;
	a.sin_port = htons(g_upstream_port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (set_nb(fd) < 0) {
		close(fd);
		return -1;
	}
	int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
	if (rc < 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	struct pollfd p = {.fd = fd, .events = POLLOUT};
	if (poll(&p, 1, 3000) <= 0) {
		close(fd);
		return -1;
	}
	int err = 0;
	socklen_t el = sizeof err;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Returns bytes to skip: 0 keep, 7 strip. */
static int classify(const unsigned char *b, int n, const char **why) {
	if (n >= 32 + 18 && salt_opens(b, b + 32)) {
		*why = "outline";
		n_outline++;
		return 0;
	}
	if (n >= 7 + 32 + 18 && memcmp(b, PREFIX, 7) == 0 && salt_opens(b + 7, b + 7 + 32)) {
		*why = "strip";
		n_strip++;
		return 7;
	}
	*why = "raw";
	n_raw++;
	return 0;
}

static int alloc_slot(void) {
	for (int i = 0; i < MAX_CONN; i++)
		if (conns[i].fd[0] < 0) return i;
	return -1;
}

static int have_decision(const unsigned char *b, int n, int client_open, int expired) {
	if (n >= 32 + 18 && salt_opens(b, b + 32)) return 1;
	if (n >= 32 + 18 && memcmp(b, PREFIX, 7) != 0) return 1;
	if (n >= 7 + 32 + 18) return 1;
	if ((!client_open || expired) && n > 0) return 1;
	return 0;
}

static void finish_probe(struct conn *c, time_t now) {
	if (!c->probing) return;
	int n = c->len[0] - c->off[0];
	unsigned char *b = c->buf[0] + c->off[0];
	int expired = now - c->started >= PROBE_SECS;
	if (expired && n == 0) {
		conn_close(c);
		return;
	}
	if (!have_decision(b, n, c->up[0], expired)) return;
	const char *why = "raw";
	int skip = classify(b, n, &why);
	struct sockaddr_in peer;
	socklen_t pl = sizeof peer;
	char ip[INET_ADDRSTRLEN] = "?";
	if (getpeername(c->fd[0], (struct sockaddr *)&peer, &pl) == 0)
		inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
	if (skip || strcmp(why, "outline") != 0)
		fprintf(stderr, "%s %s n=%d\n", ip, why, n);
	if ((n_outline + n_strip + n_raw) % 50 == 0)
		fprintf(stderr, "stats outline=%lu strip=%lu raw=%lu\n", n_outline, n_strip, n_raw);
	int ufd = dial_upstream();
	if (ufd < 0) {
		fprintf(stderr, "%s upstream-fail\n", ip);
		conn_close(c);
		return;
	}
	c->buf[1] = malloc(CAP);
	if (!c->buf[1]) {
		close(ufd);
		conn_close(c);
		return;
	}
	if (skip) {
		memmove(b, b + skip, n - skip);
		c->len[0] -= skip;
	}
	c->fd[1] = ufd;
	c->up[1] = 1;
	c->probing = 0;
}

static void accept_one(int lfd) {
	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) return;
		int one = 1;
		setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
		if (set_nb(cfd) < 0) {
			close(cfd);
			continue;
		}
		maybe_reload();
		int slot = alloc_slot();
		if (slot < 0) {
			close(cfd);
			return;
		}
		struct conn *c = &conns[slot];
		memset(c, 0, sizeof *c);
		c->fd[0] = cfd;
		c->fd[1] = -1;
		c->up[0] = 1;
		c->buf[0] = malloc(CAP);
		if (!c->buf[0]) {
			conn_close(c);
			continue;
		}
		c->probing = 1;
		c->started = time(NULL);
	}
}

/* buf[i] holds bytes read from fd[i] and not yet written to the other socket. */
static void drive(struct conn *c, int i) {
	int src = 1 - i;
	if (c->fd[i] >= 0 && c->off[src] < c->len[src]) {
		int left = c->len[src] - c->off[src];
		int w = write(c->fd[i], c->buf[src] + c->off[src], left);
		if (w > 0) {
			c->off[src] += w;
			if (c->off[src] == c->len[src]) c->off[src] = c->len[src] = 0;
		} else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			c->up[i] = 0;
			c->len[src] = c->off[src] = 0;
		}
	}
	if (c->fd[i] >= 0 && c->up[i] && c->len[i] < CAP) {
		int r = read(c->fd[i], c->buf[i] + c->len[i], CAP - c->len[i]);
		if (r > 0) c->len[i] += r;
		else if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
			c->up[i] = 0;
	}
	if (!c->probing && !c->up[0] && c->len[0] == 0 && c->fd[1] >= 0) shutdown(c->fd[1], SHUT_WR);
	if (!c->probing && !c->up[1] && c->len[1] == 0 && c->fd[0] >= 0) shutdown(c->fd[0], SHUT_WR);
	if (c->probing && !c->up[0] && c->len[0] == 0) conn_close(c);
	else if (!c->probing && !c->up[0] && !c->up[1] && c->len[0] == 0 && c->len[1] == 0) conn_close(c);
}

static void loop(int lfd) {
	for (;;) {
		struct pollfd pf[1 + MAX_CONN * 2];
		int map[1 + MAX_CONN * 2];
		int side[1 + MAX_CONN * 2];
		int np = 0;
		pf[np].fd = lfd;
		pf[np].events = POLLIN;
		map[np] = -1;
		np++;
		for (int i = 0; i < MAX_CONN; i++) {
			if (conns[i].fd[0] < 0) continue;
			for (int s = 0; s < 2; s++) {
				if (conns[i].fd[s] < 0) continue;
				short ev = 0;
				int src = 1 - s;
				if (conns[i].off[src] < conns[i].len[src]) ev |= POLLOUT;
				if (conns[i].up[s] && conns[i].len[s] < CAP) ev |= POLLIN;
				if (!ev) continue;
				pf[np].fd = conns[i].fd[s];
				pf[np].events = ev;
				map[np] = i;
				side[np] = s;
				np++;
			}
		}
		int pr = poll(pf, np, 1000);
		if (pr < 0) {
			if (errno == EINTR) continue;
			die("poll");
		}
		if (pr == 0) {
			static unsigned long po, ps, prw;
			if (po != n_outline || ps != n_strip || prw != n_raw) {
				fprintf(stderr, "stats outline=%lu strip=%lu raw=%lu\n", n_outline, n_strip, n_raw);
				po = n_outline;
				ps = n_strip;
				prw = n_raw;
			}
		}
		if (pf[0].revents & POLLIN) accept_one(lfd);
		for (int i = 1; i < np; i++) {
			if (!pf[i].revents) continue;
			struct conn *c = &conns[map[i]];
			if (c->fd[0] < 0) continue;
			if (pf[i].revents & POLLNVAL) {
				conn_close(c);
				continue;
			}
			drive(c, side[i]);
			if (c->fd[0] >= 0 && c->probing) finish_probe(c, time(NULL));
		}
		time_t now = time(NULL);
		static time_t last_sweep;
		if (now != last_sweep) {
			last_sweep = now;
			for (int i = 0; i < MAX_CONN; i++)
				if (conns[i].fd[0] >= 0 && conns[i].probing) finish_probe(&conns[i], now);
		}
	}
}

int main(int argc, char **argv) {
	if (argc != 1 && argc != 4) {
		fprintf(stderr, "usage: %s [LISTEN_PORT UPSTREAM_PORT CONFIG_YML]\n", argv[0]);
		return 2;
	}
	if (argc == 4) {
		g_listen_port = atoi(argv[1]);
		g_upstream_port = atoi(argv[2]);
		g_config = argv[3];
	}
	signal(SIGPIPE, SIG_IGN);
	for (int i = 0; i < MAX_CONN; i++) conns[i].fd[0] = conns[i].fd[1] = -1;
	load_keys();
	if (g_nkeys == 0) return 1;
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) die("socket");
	int one = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in a = {0};
	a.sin_family = AF_INET;
	a.sin_port = htons(g_listen_port);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(lfd, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
	if (listen(lfd, 4096) < 0) die("listen");
	set_nb(lfd);
	fprintf(stderr, "listening %d -> 127.0.0.1:%d\n", g_listen_port, g_upstream_port);
	loop(lfd);
}
