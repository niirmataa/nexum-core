#pragma once

#include <stddef.h>

char *prompt_pass(const char *label);
void secure_free_str(char **p);
void secure_free_mem(void *p, size_t len);

int str_append(char **buf, size_t *len, const char *s);
void append_or_die(char **buf, size_t *len, const char *s);
char *json_escape_or_die(const char *s);
void append_json_escaped_or_die(char **buf, size_t *len, const char *s);

int tor_proxy_reachable(const char *socks5);
int url_host_is_onion_suffix(const char *url);
void require_tor(const char *base, const char *socks5);

char *read_file_str(const char *path, size_t *out_len);
int json_split_messages(const char *json, char ***out_msgs, size_t *out_count);
