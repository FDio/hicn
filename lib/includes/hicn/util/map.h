/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTIL_MAP_H
#define UTIL_MAP_H

#include <stdlib.h>

#include "set.h"

#define ERR_MAP_EXISTS -2
#define ERR_MAP_NOT_FOUND -3

#define TYPEDEF_MAP_H(NAME, KEY_T, VAL_T)                                       \
                                                                                \
typedef struct {                                                                \
    KEY_T key;                                                                  \
    VAL_T value;                                                                \
} NAME ## _pair_t;                                                              \
                                                                                \
NAME ## _pair_t * NAME ## _pair_create(KEY_T key, VAL_T value);                 \
                                                                                \
void NAME ## _pair_free(NAME ## _pair_t * pair);                                \
                                                                                \
int NAME ## _pair_cmp(const NAME ## _pair_t * p1, const NAME ## _pair_t * p2);  \
                                                                                \
TYPEDEF_SET_H(NAME ## _pair_set, NAME ## _pair_t *)                             \
                                                                                \
typedef struct NAME ## _s {                                                     \
    NAME ## _pair_set_t pair_set;                                               \
} NAME ## _t;                                                                   \
                                                                                \
int NAME ## _initialize(NAME ## _t * map);                                      \
                                                                                \
int NAME ## _finalize(NAME ## _t * map);                                        \
                                                                                \
NAME ## _t * NAME ## _create();                                                 \
                                                                                \
void NAME ## _free(NAME ## _t * map);                                           \
                                                                                \
int NAME ## _add(NAME ## _t * map, KEY_T key, VAL_T value);                     \
                                                                                \
int NAME ## _remove(NAME ## _t * map, KEY_T key, VAL_T * value);                \
                                                                                \
int NAME ## _get(NAME ## _t * map, KEY_T key, VAL_T * value);                   \
                                                                                \
void NAME ## _dump(NAME ## _t * map);




#define TYPEDEF_MAP(NAME, KEY_T, VAL_T, CMP, KEY_SNPRINTF, VALUE_SNPRINTF)      \
                                                                                \
NAME ## _pair_t * NAME ## _pair_create(KEY_T key, VAL_T value)                  \
{                                                                               \
    /* Create pair */                                                           \
    NAME ## _pair_t * pair = malloc(sizeof(NAME ## _pair_t));                   \
    if (!pair)                                                                  \
        return NULL;                                                            \
                                                                                \
    pair->key = key;                                                            \
    pair->value = value;                                                        \
                                                                                \
    return pair;                                                                \
}                                                                               \
                                                                                \
void NAME ## _pair_free(NAME ## _pair_t * pair)                                 \
{                                                                               \
    free(pair);                                                                 \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _pair_cmp(const NAME ## _pair_t * p1, const NAME ## _pair_t * p2)       \
{                                                                               \
    return (CMP(p1->key, p2->key));                                             \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _pair_snprintf(char * buf, size_t size, const NAME ## _pair_t * pair) { \
    int rc;                                                                     \
    rc = KEY_SNPRINTF(buf, BUFSIZE/2, (KEY_T)pair->key);                        \
    if (rc < 0)                                                                 \
        return rc;                                                              \
    rc = VALUE_SNPRINTF(buf+rc, BUFSIZE/2, (VAL_T)pair->value);                 \
    return (int)rc;                                                                  \
}                                                                               \
                                                                                \
TYPEDEF_SET(NAME ## _pair_set, NAME ## _pair_t *, NAME ## _pair_cmp, NAME ## _pair_snprintf); \
                                                                                \
int                                                                             \
NAME ## _initialize(NAME ## _t * map)                                           \
{                                                                               \
    return NAME ## _pair_set_initialize(&map->pair_set);                        \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _finalize(NAME ## _t * map)                                             \
{                                                                               \
    NAME ## _pair_t ** array;                                                   \
    int n = NAME ## _pair_set_get_array(&map->pair_set, &array);                \
    if (n < 0)                                                                  \
        return -1;                                                              \
    for (unsigned i = 0; i < n; i++) {                                          \
        NAME ## _pair_t * pair = array[i];                                      \
        NAME ## _pair_set_remove(&map->pair_set, pair, NULL);                   \
        NAME ## _pair_free(pair);                                               \
    }                                                                           \
    free(array);                                                                \
    return NAME ## _pair_set_finalize(&map->pair_set);                          \
}                                                                               \
                                                                                \
NAME ## _t *                                                                    \
NAME ## _create()                                                               \
{                                                                               \
    NAME ## _t * map = malloc(sizeof(NAME ## _t));                              \
    if (!map)                                                                   \
        goto ERR_MALLOC;                                                        \
                                                                                \
    if (NAME ## _initialize(map) < 0)                                           \
        goto ERR_INITIALIZE;                                                    \
                                                                                \
    return map;                                                                 \
                                                                                \
ERR_INITIALIZE:                                                                 \
    free(map);                                                                  \
ERR_MALLOC:                                                                     \
    return NULL;                                                                \
}                                                                               \
                                                                                \
void                                                                            \
NAME ## _free(NAME ## _t * map)                                                 \
{                                                                               \
    NAME ## _finalize(map);                                                     \
    free(map);                                                                  \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _add(NAME ## _t * map, KEY_T key, VAL_T value)                          \
{                                                                               \
    int rc;                                                                     \
    NAME ## _pair_t * found = NULL;                                             \
                                                                                \
    NAME ## _pair_t * pair = NAME ## _pair_create(key, value);                  \
    if (!pair)                                                                  \
        return -1;                                                              \
                                                                                \
    rc = NAME ## _pair_set_get(&map->pair_set, pair, &found);                   \
    if (rc < 0)                                                                 \
        return -1;                                                              \
    if (found) {                                                                \
        NAME ## _pair_free(pair);                                               \
        return ERR_MAP_EXISTS;                                                  \
    }                                                                           \
                                                                                \
    rc = NAME ## _pair_set_add(&map->pair_set, pair);                           \
    if (rc < 0) {                                                               \
        NAME ## _pair_free(pair);                                               \
        return -1;                                                              \
    }                                                                           \
    return 0;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _remove(NAME ## _t * map, KEY_T key, VAL_T * value)                     \
{                                                                               \
    NAME ## _pair_t * found = NULL;                                             \
    NAME ## _pair_t search = { .key = key };                                    \
    int rc = NAME ## _pair_set_remove(&map->pair_set, &search, &found);         \
    if (rc < 0)                                                                 \
        return ERR_MAP_NOT_FOUND;                                               \
    if (value)                                                                  \
        *value = found->value;                                                  \
    NAME ## _pair_free(found);                                                  \
    return 0;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _get(NAME ## _t * map, KEY_T key, VAL_T * value)                        \
{                                                                               \
    NAME ## _pair_t * found = NULL, search = { .key = key };                    \
    int rc = NAME ## _pair_set_get(&map->pair_set, &search, &found);            \
    if (rc < 0)                                                                 \
        return -1;                                                              \
    if (found)                                                                  \
        *value = found->value;                                                  \
    return 0;                                                                   \
}                                                                               \
                                                                                \
void                                                                            \
NAME ## _dump(NAME ## _t * map) {                                               \
    NAME ## _pair_set_dump(&map->pair_set);                                     \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _get_key_array(NAME ## _t * map, KEY_T **array) {                       \
    NAME ## _pair_t ** pair_array;                                              \
    int n = NAME ## _pair_set_get_array(&map->pair_set, &pair_array);           \
    if (n < 0)                                                                  \
        return -1;                                                              \
    if (!array)                                                                 \
        goto END;                                                               \
    /* Allocate result array */                                                 \
    *array = malloc(n * sizeof(KEY_T));                                         \
    if (!array) {                                                               \
        free(pair_array);                                                       \
        return -1;                                                              \
    }                                                                           \
    /* Copy keys */                                                             \
    for (int i = 0; i < n; i++)                                                 \
        (*array)[i] = pair_array[i]->key;                                       \
    free(pair_array);                                                           \
END:                                                                            \
    return n;                                                                   \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _get_value_array(NAME ## _t * map, VAL_T **array) {                     \
    NAME ## _pair_t ** pair_array;                                              \
    int n = NAME ## _pair_set_get_array(&map->pair_set, &pair_array);           \
    if (n < 0)                                                                  \
        return -1;                                                              \
    if (!array)                                                                 \
        goto END;                                                               \
    /* Allocate result array */                                                 \
    *array = malloc(n * sizeof(VAL_T));                                         \
    if (!array) {                                                               \
        free(pair_array);                                                       \
        return -1;                                                              \
    }                                                                           \
    /* Copy values */                                                           \
    for (int i = 0; i < n; i++)                                                 \
        (*array)[i] = pair_array[i]->value;                                     \
    free(pair_array);                                                           \
END:                                                                            \
    return n;                                                                   \
}

#endif /* UTIL_MAP_H */
