#pragma once

#include <stddef.h>

typedef struct {
    char dir[4096];
    char base[512];
    char socks5[256];
} ff_cli_config_t;

const char *ff_cli_config_default_path(char *buf, size_t n);
void ff_cli_config_defaults(ff_cli_config_t *cfg);
int ff_cli_config_load(const char *path, ff_cli_config_t *cfg);
int ff_cli_config_write(const char *path, const ff_cli_config_t *cfg);
