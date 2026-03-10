#include "cli_config.h"
#include "util.h"

#include <jansson.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLI_DEFAULT_BASE "http://127.0.0.1:8000"
#define CLI_DEFAULT_SOCKS5 "socks5h://127.0.0.1:9050"

static const char *def_dir(char *buf, size_t n) {
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(buf, n, "%s/.nexum", home);
    return buf;
}

const char *ff_cli_config_default_path(char *buf, size_t n) {
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(buf, n, "%s/.nexum/config.json", home);
    return buf;
}

void ff_cli_config_defaults(ff_cli_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    def_dir(cfg->dir, sizeof(cfg->dir));
    ff_strlcpy(cfg->base, CLI_DEFAULT_BASE, sizeof(cfg->base));
    ff_strlcpy(cfg->socks5, CLI_DEFAULT_SOCKS5, sizeof(cfg->socks5));
}

static void cfg_apply_string(json_t *obj, const char *key, char *out, size_t out_cap) {
    if (!obj || !key || !out || out_cap == 0) return;
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) return;
    const char *s = json_string_value(v);
    if (!s || !s[0]) return;
    ff_strlcpy(out, s, out_cap);
}

int ff_cli_config_load(const char *path, ff_cli_config_t *cfg) {
    if (!path || !cfg) return -1;
    json_error_t err;
    errno = 0;
    json_t *root = json_load_file(path, 0, &err);
    if (!root) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "config load failed (%s): %s\n", path, err.text);
        return -1;
    }
    if (!json_is_object(root)) {
        json_decref(root);
        fprintf(stderr, "config load failed (%s): root must be JSON object\n", path);
        return -1;
    }

    cfg_apply_string(root, "dir", cfg->dir, sizeof(cfg->dir));
    cfg_apply_string(root, "base", cfg->base, sizeof(cfg->base));
    cfg_apply_string(root, "socks5", cfg->socks5, sizeof(cfg->socks5));

    json_t *network = json_object_get(root, "network");
    if (json_is_object(network)) {
        cfg_apply_string(network, "base", cfg->base, sizeof(cfg->base));
        cfg_apply_string(network, "socks5", cfg->socks5, sizeof(cfg->socks5));
    }

    json_decref(root);
    return 1;
}

int ff_cli_config_write(const char *path, const ff_cli_config_t *cfg) {
    if (!path || !cfg) return -1;

    char parent[4096];
    ff_strlcpy(parent, path, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = 0;
        if (parent[0] && ff_mkdir_p(parent) != 0) return -1;
    }

    json_t *root = json_object();
    json_t *network = json_object();
    if (!root || !network) {
        if (root) json_decref(root);
        if (network) json_decref(network);
        return -1;
    }

    if (json_object_set_new(root, "dir", json_string(cfg->dir)) != 0 ||
        json_object_set_new(root, "base", json_string(cfg->base)) != 0 ||
        json_object_set_new(root, "socks5", json_string(cfg->socks5)) != 0 ||
        json_object_set_new(network, "base", json_string(cfg->base)) != 0 ||
        json_object_set_new(network, "socks5", json_string(cfg->socks5)) != 0 ||
        json_object_set_new(root, "network", network) != 0) {
        json_decref(network);
        json_decref(root);
        return -1;
    }

    char *dump = json_dumps(root, JSON_INDENT(2));
    json_decref(root);
    if (!dump) return -1;

    int rc = ff_write_file_atomic(path, (const uint8_t *)dump, strlen(dump), 0600);
    free(dump);
    return rc;
}
