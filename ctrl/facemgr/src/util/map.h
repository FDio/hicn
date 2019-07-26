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

#include "../common.h"
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
int NAME ## _add(NAME ## _t * map, KEY_T key, const VAL_T value);               \
                                                                                \
int NAME ## _remove(NAME ## _t * map, KEY_T key, VAL_T * value);                \
                                                                                \
int NAME ## _get(NAME ## _t * map, KEY_T key, VAL_T * value);                   \
                                                                                \
void NAME ## _dump(NAME ## _t * map);




#define TYPEDEF_MAP(NAME, KEY_T, VAL_T, CMP, KEY_SNPRINTF, VALUE_SNPRINTF)      \
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
    rc = VALUE_SNPRINTF(buf+rc, BUFSIZE/2, (VAL_T)pair->value);             \
    return rc;                                                                  \
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
    return NAME ## _pair_set_finalize(&map->pair_set);                          \
}                                                                               \
                                                                                \
AUTOGENERATE_CREATE_FREE(NAME)                                                  \
                                                                                \
int                                                                             \
NAME ## _add(NAME ## _t * map, KEY_T key, const VAL_T value)                    \
{                                                                               \
    int rc;                                                                     \
                                                                                \
    /* Create pair */                                                           \
    NAME ## _pair_t * pair = malloc(sizeof(NAME ## _pair_t));                   \
    if (!pair)                                                                  \
        return FACEMGR_FAILURE;                                                 \
                                                                                \
    pair->key = key;                                                            \
    pair->value = (VAL_T)value;                                                 \
                                                                                \
    rc = NAME ## _pair_set_get(&map->pair_set, pair, NULL);                     \
    if (!FACEMGR_IS_ERROR(rc)) {                                                \
        free(pair);                                                             \
        return ERR_MAP_EXISTS;                                                  \
    }                                                                           \
                                                                                \
    rc = NAME ## _pair_set_add(&map->pair_set, pair);                           \
    if (FACEMGR_IS_ERROR(rc)) {                                                 \
        free(pair);                                                             \
        return FACEMGR_FAILURE;                                                 \
    }                                                                           \
    return FACEMGR_SUCCESS;                                                     \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _remove(NAME ## _t * map, KEY_T key, VAL_T * value)                     \
{                                                                               \
    NAME ## _pair_t * found, search = { .key = key };                           \
    int rc = NAME ## _pair_set_remove(&map->pair_set, &search, &found);         \
    if (FACEMGR_IS_ERROR(rc))                                                   \
        return ERR_MAP_NOT_FOUND;                                               \
    *value = found->value;                                                      \
    return FACEMGR_SUCCESS;                                                     \
}                                                                               \
                                                                                \
int                                                                             \
NAME ## _get(NAME ## _t * map, KEY_T key, VAL_T * value)                        \
{                                                                               \
    NAME ## _pair_t * found, search = { .key = key };                           \
    int rc = NAME ## _pair_set_get(&map->pair_set, &search, &found);            \
    if (FACEMGR_IS_ERROR(rc))                                                   \
        return ERR_MAP_NOT_FOUND;                                               \
    *value = found->value;                                                      \
    return FACEMGR_SUCCESS;                                                     \
}                                                                               \
                                                                                \
void                                                                            \
NAME ## _dump(NAME ## _t * map) {                                               \
    NAME ## _pair_set_dump(&map->pair_set);                                     \
}

#endif /* UTIL_MAP_H */
