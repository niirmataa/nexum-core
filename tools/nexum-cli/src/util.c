#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "util.h"

#include <sodium.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

void ff_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

int ff_mkdir_p(const char *dir) {
    if (!dir || !*dir) return -1;

    char tmp[4096];
    size_t n = strnlen(dir, sizeof(tmp) - 1);
    if (n == 0 || n >= sizeof(tmp)) return -1;

    memcpy(tmp, dir, n);
    tmp[n] = 0;

    /* usuń trailing slash */
    while (n > 1 && tmp[n - 1] == '/') {
        tmp[n - 1] = 0;
        n--;
    }

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

int ff_read_file(const char *path, uint8_t **out, size_t *out_len) {
    if (!path || !out || !out_len) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (st.st_size < 0) { close(fd); return -1; }

    size_t n = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (!buf) { close(fd); return -1; }

    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);

    if (off != n) { free(buf); return -1; }

    *out = buf;
    *out_len = n;
    return 0;
}

/* Atomic save:
   - tmp w tym samym katalogu (eliminuje EXDEV)
   - fsync(file) + fsync(dir) */
int ff_write_file_atomic(const char *path, const uint8_t *buf, size_t len, int mode) {
    if (!path || !buf) return -1;

    char tmp[4096];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path) >= (int)sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = mkstemp(tmp);
    if (fd < 0) {
        perror("ff_write_file_atomic: mkstemp");
        return -1;
    }
    if (fchmod(fd, (mode_t)mode) != 0) {
        perror("ff_write_file_atomic: fchmod(tmp)");
        close(fd);
        unlink(tmp);
        return -1;
    }
    {
        int flags = fcntl(fd, F_GETFD);
        if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }

    if (write_all(fd, buf, len) != 0) {
        perror("ff_write_file_atomic: write");
        close(fd);
        unlink(tmp);
        return -1;
    }

    if (fsync(fd) != 0) {
        perror("ff_write_file_atomic: fsync(file)");
        close(fd);
        unlink(tmp);
        return -1;
    }

    if (close(fd) != 0) {
        perror("ff_write_file_atomic: close");
        unlink(tmp);
        return -1;
    }

    {
        struct stat st_target;
        if (lstat(path, &st_target) == 0 && S_ISLNK(st_target.st_mode)) {
            errno = ELOOP;
            perror("ff_write_file_atomic: target is symlink");
            unlink(tmp);
            return -1;
        }
    }
    if (rename(tmp, path) != 0) {
        perror("ff_write_file_atomic: rename");
        unlink(tmp);
        return -1;
    }

    char dir[4096];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;

    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        int dfd = open(dir, O_RDONLY);
        if (dfd >= 0) {
            if (fsync(dfd) != 0) {
                perror("ff_write_file_atomic: fsync(dir)");
                close(dfd);
                return -1;
            }
            close(dfd);
        }
    }

    return 0;
}

/* Base64 (standard) */
int ff_b64enc(const uint8_t *in, size_t in_len, char **out) {
    if (!in || !out) return -1;
    if (sodium_init() < 0) return -1;

    size_t out_len = sodium_base64_encoded_len(in_len, sodium_base64_VARIANT_ORIGINAL);
    char *s = (char *)malloc(out_len);
    if (!s) return -1;

    sodium_bin2base64(s, out_len, in, in_len, sodium_base64_VARIANT_ORIGINAL);
    *out = s;
    return 0;
}

int ff_b64dec(const char *in, uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    if (sodium_init() < 0) return -1;

    size_t in_len = strlen(in);
    uint8_t *buf = (uint8_t *)malloc(in_len ? in_len : 1);
    if (!buf) return -1;

    size_t bin_len = 0;
    if (sodium_base642bin(buf, in_len, in, in_len, NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        free(buf);
        return -1;
    }

    uint8_t *shrunk = (uint8_t *)realloc(buf, bin_len ? bin_len : 1);
    if (shrunk) buf = shrunk;

    *out = buf;
    *out_len = bin_len;
    return 0;
}

/* Base64url (no padding) – potrzebne do PoW tokenów */
int ff_b64u_enc(const uint8_t *in, size_t in_len, char **out) {
    if (!in || !out) return -1;
    if (sodium_init() < 0) return -1;

    size_t out_len = sodium_base64_encoded_len(in_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *s = (char *)malloc(out_len);
    if (!s) return -1;

    sodium_bin2base64(s, out_len, in, in_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    *out = s;
    return 0;
}

int ff_b64u_dec(const char *in, uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    if (sodium_init() < 0) return -1;

    size_t in_len = strlen(in);
    uint8_t *buf = (uint8_t *)malloc(in_len ? in_len : 1);
    if (!buf) return -1;

    size_t bin_len = 0;
    if (sodium_base642bin(buf, in_len, in, in_len, NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(buf);
        return -1;
    }

    uint8_t *shrunk = (uint8_t *)realloc(buf, bin_len ? bin_len : 1);
    if (shrunk) buf = shrunk;

    *out = buf;
    *out_len = bin_len;
    return 0;
}

int ff_json_escape(const char *in, char **out) {
    if (!in || !out) return -1;
    *out = NULL;

    size_t len = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        switch (*p) {
            case '\"':
            case '\\':
                len += 2;
                break;
            case '\b':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
                len += 2;
                break;
            default:
                if (*p < 0x20) {
                    len += 6; /* \u00XX */
                } else {
                    len += 1;
                }
                break;
        }
    }

    char *buf = (char *)malloc(len + 1);
    if (!buf) return -1;

    char *w = buf;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        switch (*p) {
            case '\"': *w++ = '\\'; *w++ = '\"'; break;
            case '\\': *w++ = '\\'; *w++ = '\\'; break;
            case '\b': *w++ = '\\'; *w++ = 'b'; break;
            case '\f': *w++ = '\\'; *w++ = 'f'; break;
            case '\n': *w++ = '\\'; *w++ = 'n'; break;
            case '\r': *w++ = '\\'; *w++ = 'r'; break;
            case '\t': *w++ = '\\'; *w++ = 't'; break;
            default:
                if (*p < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    *w++ = '\\';
                    *w++ = 'u';
                    *w++ = '0';
                    *w++ = '0';
                    *w++ = hex[(*p >> 4) & 0xF];
                    *w++ = hex[*p & 0xF];
                } else {
                    *w++ = (char)*p;
                }
                break;
        }
    }
    *w = 0;
    *out = buf;
    return 0;
}

void ff_strlcpy(char *dst, const char *src, size_t dst_len) {
    if (!dst || dst_len == 0) return;
    if (!src) {
        dst[0] = 0;
        return;
    }
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = 0;
}

void ff_u16be(uint16_t x, uint8_t out[2]) {
    out[0] = (uint8_t)(x >> 8);
    out[1] = (uint8_t)(x);
}

void ff_u32be(uint32_t x, uint8_t out[4]) {
    out[0] = (uint8_t)(x >> 24);
    out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8);
    out[3] = (uint8_t)(x);
}

void ff_u64be(uint64_t x, uint8_t out[8]) {
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)(x);
}

void ff_hmac_sha512(uint8_t out64[64], const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len) {
    uint8_t k0[128];
    uint8_t ipad[128];
    uint8_t opad[128];
    uint8_t inner[64];

    memset(k0, 0, sizeof(k0));
    if (key_len > sizeof(k0)) {
        crypto_hash_sha512(k0, key, (unsigned long long)key_len);
    } else if (key_len > 0) {
        memcpy(k0, key, key_len);
    }

    for (size_t i = 0; i < sizeof(k0); i++) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36);
        opad[i] = (uint8_t)(k0[i] ^ 0x5c);
    }

    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, ipad, sizeof(ipad));
    if (msg_len > 0) {
        crypto_hash_sha512_update(&st, msg, (unsigned long long)msg_len);
    }
    crypto_hash_sha512_final(&st, inner);

    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, opad, sizeof(opad));
    crypto_hash_sha512_update(&st, inner, sizeof(inner));
    crypto_hash_sha512_final(&st, out64);

    sodium_memzero(k0, sizeof(k0));
    sodium_memzero(ipad, sizeof(ipad));
    sodium_memzero(opad, sizeof(opad));
    sodium_memzero(inner, sizeof(inner));
}
