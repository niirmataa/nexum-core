#include "cli_common.h"

#include "util.h"

#include <sodium.h>
#include <jansson.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h> /* close */

char *prompt_pass(const char *label) {
#ifdef __linux__
    char *p = getpass(label);
    if (!p) return NULL;
    /* getpass zwraca wskaźnik do statycznego bufora -> kopiujemy natychmiast */
    char *dup = strdup(p);
    sodium_memzero(p, strlen(p));
    return dup;
#else
    char tmp[256];
    memset(tmp, 0, sizeof(tmp));
    fprintf(stderr, "%s", label);
    if (!fgets(tmp, sizeof(tmp), stdin)) {
        sodium_memzero(tmp, sizeof(tmp));
        return NULL;
    }
    tmp[strcspn(tmp, "\r\n")] = 0;
    char *dup = strdup(tmp);
    sodium_memzero(tmp, sizeof(tmp));
    return dup;
#endif
}

void secure_free_str(char **p) {
    if (!p || !*p) return;
    size_t n = strlen(*p);
    if (n) sodium_memzero(*p, n);
    free(*p);
    *p = NULL;
}

void secure_free_mem(void *p, size_t len) {
    if (!p) return;
    if (len) sodium_memzero(p, len);
    free(p);
}

int str_append(char **buf, size_t *len, const char *s) {
    if (!buf || !len || !s) return -1;
    size_t sl = strlen(s);
    char *p = (char*)realloc(*buf, *len + sl + 1);
    if (!p) return -1;
    memcpy(p + *len, s, sl);
    *len += sl;
    p[*len] = 0;
    *buf = p;
    return 0;
}

void append_or_die(char **buf, size_t *len, const char *s) {
    if (str_append(buf, len, s) != 0) ff_die("oom");
}

char *json_escape_or_die(const char *s) {
    char *out = NULL;
    if (ff_json_escape(s ? s : "", &out) != 0) ff_die("oom");
    return out;
}

void append_json_escaped_or_die(char **buf, size_t *len, const char *s) {
    char *esc = json_escape_or_die(s);
    append_or_die(buf, len, esc);
    free(esc);
}

static int parse_socks5_hostport(const char *socks5, char *host, size_t host_cap, int *port) {
    if (!socks5 || !host || !port || host_cap == 0) return -1;
    const char *p = socks5;
    if (strncmp(p, "socks5h://", 10) == 0) p += 10;
    else if (strncmp(p, "socks5://", 9) == 0) p += 9;

    const char *at = strchr(p, '@');
    if (at) p = at + 1;

    size_t hlen = 0;
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end) return -1;
        hlen = (size_t)(end - p - 1);
        if (hlen == 0 || hlen + 1 > host_cap) return -1;
        memcpy(host, p + 1, hlen);
        host[hlen] = 0;
        p = end + 1;
        if (*p != ':') return -1;
        p++;
    } else {
        const char *colon = strchr(p, ':');
        if (!colon) return -1;
        hlen = (size_t)(colon - p);
        if (hlen == 0 || hlen + 1 > host_cap) return -1;
        memcpy(host, p, hlen);
        host[hlen] = 0;
        p = colon + 1;
    }

    char *endp = NULL;
    long pr = strtol(p, &endp, 10);
    if (endp == p || pr <= 0 || pr > 65535) return -1;
    *port = (int)pr;
    return 0;
}

int url_host_is_onion_suffix(const char *url) {
    if (!url || !url[0]) return 0;
    const char *p = strstr(url, "://");
    const char *host = p ? (p + 3) : url;
    if (!host[0]) return 0;
    size_t host_len = strcspn(host, "/?#");
    if (host_len == 0) return 0;
    const char *host_end = host + host_len;
    const char *bare_start = host;
    if (*host == '[') {
        const char *end = memchr(host, ']', host_len);
        if (!end) return 0;
        bare_start = host + 1;
        host_end = end;
    } else {
        const char *colon = memchr(host, ':', host_len);
        if (colon) host_end = colon;
    }
    size_t bare_len = (size_t)(host_end - bare_start);
    if (bare_len < 6) return 0;
    return strncasecmp(host_end - 6, ".onion", 6) == 0;
}

int tor_proxy_reachable(const char *socks5) {
    char host[256];
    int port = 0;
    if (parse_socks5_hostport(socks5, host, sizeof(host), &port) != 0) return -1;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int ok = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int conn_ok = 0;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
                close(fd);
                continue;
            }
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = fd;
            pfd.events = POLLOUT;
            for (;;) {
                int pr = poll(&pfd, 1, 3000);
                if (pr < 0 && errno == EINTR) continue;
                if (pr <= 0) break;
                if (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) {
                    int so_err = 0;
                    socklen_t so_len = (socklen_t)sizeof(so_err);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) == 0 && so_err == 0) {
                        conn_ok = 1;
                    }
                }
                break;
            }
        } else {
            conn_ok = 1;
        }
        if (!conn_ok) {
            close(fd);
            continue;
        }

        /* Handshake na niektorych hostach bywa flaky przy nonblocking send/recv.
           Po udanym connect wracamy do trybu blokujacego z krotkimi timeoutami. */
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }
        struct timeval tv;
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = 3;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t hello[3] = {0x05, 0x01, 0x00};
        size_t off = 0;
        while (off < sizeof(hello)) {
            ssize_t wr = send(fd, hello + off, sizeof(hello) - off, 0);
            if (wr > 0) {
                off += (size_t)wr;
                continue;
            }
            if (wr < 0 && errno == EINTR) continue;
            off = 0;
            break;
        }
        if (off == sizeof(hello)) {
            uint8_t resp[2] = {0};
            size_t roff = 0;
            while (roff < sizeof(resp)) {
                ssize_t rr = recv(fd, resp + roff, sizeof(resp) - roff, 0);
                if (rr > 0) {
                    roff += (size_t)rr;
                    continue;
                }
                if (rr == 0) break;
                if (errno == EINTR) continue;
                roff = 0;
                break;
            }
            if (roff == sizeof(resp) && resp[0] == 0x05 && resp[1] == 0x00) {
                ok = 0;
                close(fd);
                break;
            }
        }
        close(fd);
    }
    freeaddrinfo(res);
    return ok;
}

void require_tor(const char *base, const char *socks5) {
    if (!socks5 || !socks5[0]) {
        ff_die("Tor required: use --socks5 socks5h://127.0.0.1:9050");
    }
    if (strncmp(socks5, "socks5h://", 10) != 0) {
        ff_die("Tor required: use socks5h:// (DNS over Tor)");
    }
    if (!url_host_is_onion_suffix(base)) {
        ff_die("Tor required: --base must be a .onion address");
    }
    if (tor_proxy_reachable(socks5) != 0) {
        ff_die("Tor not reachable at %s (is Tor running? socks5h on 127.0.0.1:9050)", socks5);
    }
}

char *read_file_str(const char *path, size_t *out_len) {
    uint8_t *buf = NULL;
    size_t len = 0;
    if (ff_read_file(path, &buf, &len) != 0) return NULL;
    char *s = (char*)malloc(len + 1);
    if (!s) { free(buf); return NULL; }
    memcpy(s, buf, len);
    s[len] = 0;
    if (out_len) *out_len = len;
    sodium_memzero(buf, len);
    free(buf);
    return s;
}

int json_split_messages(const char *json, char ***out_msgs, size_t *out_count) {
    if (!json || !out_msgs || !out_count) return -1;
    *out_msgs = NULL;
    *out_count = 0;

    json_error_t err;
    json_t *root = json_loads(json, 0, &err);
    if (!root) return -1;
    if (!json_is_object(root)) { json_decref(root); return -1; }

    json_t *msgs = json_object_get(root, "messages");
    if (!msgs || !json_is_array(msgs)) { json_decref(root); return -1; }

    size_t n = json_array_size(msgs);
    char **arr = (char**)calloc(n ? n : 1, sizeof(char*));
    if (!arr && n > 0) { json_decref(root); return -1; }

    for (size_t i = 0; i < n; i++) {
        json_t *obj = json_array_get(msgs, i);
        if (!obj || !json_is_object(obj)) continue;
        char *dump = json_dumps(obj, JSON_COMPACT);
        if (!dump) { json_decref(root); for (size_t j = 0; j < n; j++) free(arr[j]); free(arr); return -1; }
        arr[i] = dump;
    }

    *out_msgs = arr;
    *out_count = n;
    json_decref(root);
    return 0;
}
