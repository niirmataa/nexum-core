#pragma once
#include <stdint.h>

int ff_pow_solve(const char *token_b64u, const char *purpose, const char *nick,
                 int difficulty, uint64_t start_nonce, uint64_t *found_nonce);
