#pragma once
#include <stddef.h>
#include <stdint.h>

/* Minimal JSON helper for trusted CLI packet files.
   Supports extracting string and integer values by key from a JSON object.
   It is NOT a general JSON parser. It expects:
     - double-quoted keys
     - string values: "..."
     - integer values: digits (base10)
   It ignores whitespace. It allows escaped sequences by copying the character after '\'.
*/

int ff_json_get_string(const char *json, const char *key, char **out);
int ff_json_get_int64(const char *json, const char *key, int64_t *out);
