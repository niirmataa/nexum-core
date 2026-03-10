#include "json_min.h"
#include <jansson.h>
#include <stdlib.h>
#include <string.h>

int ff_json_get_string(const char *json, const char *key, char **out) {
    if (!json || !key || !out) return -1;
    *out = NULL;

    json_error_t err;
    json_t *root = json_loads(json, 0, &err);
    if (!root) return -1;
    if (!json_is_object(root)) { json_decref(root); return -1; }

    json_t *v = json_object_get(root, key);
    if (!v || !json_is_string(v)) { json_decref(root); return -1; }

    const char *s = json_string_value(v);
    if (!s) { json_decref(root); return -1; }

    char *dup = strdup(s);
    if (!dup) { json_decref(root); return -1; }

    *out = dup;
    json_decref(root);
    return 0;
}

int ff_json_get_int64(const char *json, const char *key, int64_t *out) {
    if (!json || !key || !out) return -1;
    *out = 0;

    json_error_t err;
    json_t *root = json_loads(json, 0, &err);
    if (!root) return -1;
    if (!json_is_object(root)) { json_decref(root); return -1; }

    json_t *v = json_object_get(root, key);
    if (!v || !json_is_integer(v)) { json_decref(root); return -1; }

    *out = json_integer_value(v);
    json_decref(root);
    return 0;
}
