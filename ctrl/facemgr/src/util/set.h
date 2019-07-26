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

#ifndef UTIL_SET_H
#define UTIL_SET_H

#include <search.h>
#include <string.h>
#include "token.h"
#include "../common.h"

#define ERR_SET_EXISTS -2
#define ERR_SET_NOT_FOUND -3

#define BUFSIZE 80

static inline
int
string_snprintf(char * buf, size_t size, const char * s) {
    return snprintf(buf, size, "%s", s);
}

static inline
int
generic_snprintf(char * buf, size_t size, void * value) {
    return snprintf(buf, BUFSIZE, "%p", value);
}

#define TYPEDEF_SET_H(NAME, T)                                          \
                                                                        \
typedef struct {                                                        \
    size_t size;                                                        \
    void * root;                                                        \
} NAME ## _t;                                                           \
                                                                        \
int NAME ## _initialize(NAME ## _t * set);                              \
                                                                        \
int NAME ## _finalize(NAME ## _t * set);                                \
                                                                        \
NAME ## _t * NAME ## _create();                                         \
                                                                        \
void NAME ## _free(NAME ## _t * set);                                   \
                                                                        \
int NAME ## _add(NAME ## _t * set, const T element);                    \
                                                                        \
int NAME ## _remove(NAME ## _t * set, const T search, T * element);     \
                                                                        \
int NAME ## _get(NAME ## _t * set, const T search, T * element);        \
                                                                        \
void NAME ## _dump(NAME ## _t * set);




#define TYPEDEF_SET(NAME, T, CMP, SNPRINTF)                             \
int                                                                     \
NAME ## _initialize(NAME ## _t * set)                                   \
{                                                                       \
    set->root = NULL;                                                   \
    set->size = 0;                                                      \
    return FACEMGR_SUCCESS;                                             \
}                                                                       \
                                                                        \
NO_FINALIZE(NAME);                                                      \
AUTOGENERATE_CREATE_FREE(NAME);                                         \
                                                                        \
int                                                                     \
NAME ## _add(NAME ## _t * set, const T element)                         \
{                                                                       \
    return tsearch(element, &set->root, (cmp_t)CMP)              \
        ? FACEMGR_SUCCESS : FACEMGR_FAILURE;                            \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _remove(NAME ## _t * set, const T search, T * element)          \
{                                                                       \
    T * found = tdelete(search, &set->root, (cmp_t)CMP);         \
    if (found && element)                                               \
        *element = *found;                                              \
    return found ? FACEMGR_SUCCESS : ERR_SET_NOT_FOUND;                 \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _get(NAME ## _t * set, const T search, T * element)             \
{                                                                       \
    T * found = tfind(search, &set->root, (cmp_t)CMP);                  \
    if (found && element)                                               \
        *element = *found;                                              \
    return found ? FACEMGR_SUCCESS : ERR_SET_NOT_FOUND;                 \
}                                                                       \
                                                                        \
void                                                                    \
__ ## NAME ## _dump_node(const void *nodep, const VISIT which, const int depth) \
{                                                                       \
    char buf[BUFSIZE];                                                  \
    switch (which) {                                                    \
    case preorder:                                                      \
        break;                                                          \
    case postorder:                                                     \
        break;                                                          \
    case endorder:                                                      \
        break;                                                          \
    case leaf:                                                          \
        SNPRINTF(buf, BUFSIZE, *(T*)nodep);                             \
        printf("%s\n", buf);                                            \
        break;                                                          \
    }                                                                   \
}                                                                       \
                                                                        \
void                                                                    \
NAME ## _dump(NAME ## _t * set) {                                       \
    twalk(set->root, __ ## NAME ## _dump_node);                         \
}                                                                       \

#endif /* UTIL_SET_H */
