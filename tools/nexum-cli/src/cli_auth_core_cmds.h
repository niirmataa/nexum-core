#pragma once

#include <stdint.h>

int cmd_init(const char *dir);
int cmd_keygen(const char *dir, const char *kem_alg);
int cmd_show_keys(const char *dir);
int cmd_register(const char *dir, const char *base, const char *nick, const char *socks5);
int cmd_login(const char *dir, const char *base, const char *nick, const char *socks5);
int cmd_list_kem(const char *filter);
int cmd_pow_solve_cli(const char *token, const char *purpose, const char *nick, int difficulty, uint64_t start);
int cmd_respond(const char *dir, const char *challenge_path);
