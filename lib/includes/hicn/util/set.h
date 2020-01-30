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

#include <hicn/util/log.h>
#include <search.h>
#include <string.h>
//#if !defined(__ANDROID__) && !defined(__APPLE__)
//#include <threads.h>
//#else
#define thread_local _Thread_local
//#endif /* ! __ANDROID__ */

#define ERR_SET_EXISTS -2
#define ERR_SET_NOT_FOUND -3

/* FIXME: buffer overflow when this is too small... investigate */
#define BUFSIZE 1024

static inline
int
int_cmp(const int x, const int y)
{
    return x - y;
}

static inline
int
int_snprintf(char * buf, size_t size, int value) {
    return snprintf(buf, size, "%d", value);
}

static inline
int
string_snprintf(char * buf, size_t size, const char * s) {
    return snprintf(buf, size, "%s", s);
}

static inline
int
generic_snprintf(char * buf, size_t size, const void * value) {
    return snprintf(buf, BUFSIZE, "%p", value);
}

typedef int(*cmp_t)(const void * x, const void * y);

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
int NAME ## _clear(NAME ## _t * set);                                   \
                                                                        \
int NAME ## _get(const NAME ## _t * set, const T search, T * element);  \
                                                                        \
int NAME ## _get_array(const NAME ## _t * set, T ** element);           \
                                                                        \
void NAME ## _dump(NAME ## _t * set);




#define TYPEDEF_SET(NAME, T, CMP, SNPRINTF)                             \
int                                                                     \
NAME ## _initialize(NAME ## _t * set)                                   \
{                                                                       \
    set->root = NULL;                                                   \
    set->size = 0;                                                      \
    return 0;                                                           \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _finalize(NAME ## _t * set)                                     \
{                                                                       \
    return NAME ## _clear(set);                                         \
}                                                                       \
                                                                        \
NAME ## _t *                                                            \
NAME ## _create()                                                       \
{                                                                       \
    NAME ## _t * set = malloc(sizeof(NAME ## _t));                      \
    if (!set)                                                           \
        goto ERR_MALLOC;                                                \
                                                                        \
    if (NAME ## _initialize(set) < 0)                                   \
        goto ERR_INITIALIZE;                                            \
                                                                        \
    return set;                                                         \
                                                                        \
ERR_INITIALIZE:                                                         \
    free(set);                                                          \
ERR_MALLOC:                                                             \
    return NULL;                                                        \
}                                                                       \
                                                                        \
void                                                                    \
NAME ## _free(NAME ## _t * set)                                         \
{                                                                       \
    NAME ## _finalize(set);                                             \
    free(set);                                                          \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _add(NAME ## _t * set, const T element)                         \
{                                                                       \
    T * found = tfind(element, &set->root, (cmp_t)CMP);                 \
    void * ptr = tsearch(element, &set->root, (cmp_t)CMP);              \
    if (!ptr)                                                           \
        return -1;                                                      \
    if (!found)                                                         \
        set->size++;                                                    \
    return 0;                                                           \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _remove(NAME ## _t * set, const T search, T * element)          \
{                                                                       \
    T * found = tfind(search, &set->root, (cmp_t)CMP);                  \
    if (!found)                                                         \
        return ERR_SET_NOT_FOUND;                                       \
    if (element)                                                        \
        *element = *found;                                              \
    tdelete(search, &set->root, (cmp_t)CMP);                            \
    set->size--;                                                        \
    return 0;                                                           \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _clear(NAME ## _t * set)                                        \
{                                                                       \
    T * array;                                                          \
    int n = NAME ## _get_array(set, &array);                            \
    if (n < 0)                                                          \
        return -1;                                                      \
    for (unsigned i = 0; i < n; i++) {                                  \
        T element = array[i];                                           \
        NAME ## _remove(set, element, NULL);                            \
    }                                                                   \
    free(array);                                                        \
    return 0;                                                           \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _get(const NAME ## _t * set, const T search, T * element)       \
{                                                                       \
    T * found = tfind(search, &set->root, (cmp_t)CMP);                  \
    if (element)                                                        \
        *element = found ? *found : NULL;                               \
    return 0;                                                           \
}                                                                       \
                                                                        \
static void                                                             \
NAME ## _dump_node(const void *nodep, const VISIT which,                \
        const int depth)                                                \
{                                                                       \
    char buf[BUFSIZE];                                                  \
    switch (which) {                                                    \
    case preorder:                                                      \
    case endorder:                                                      \
        break;                                                          \
    case postorder:                                                     \
    case leaf:                                                          \
        SNPRINTF(buf, BUFSIZE, *(T*)nodep);                             \
        INFO("%s", buf);                                                \
        break;                                                          \
    }                                                                   \
}                                                                       \
                                                                        \
void                                                                    \
NAME ## _dump(NAME ## _t * set) {                                       \
    twalk(set->root, NAME ## _dump_node);                               \
}                                                                       \
                                                                        \
thread_local                                                            \
T * NAME ## _array_pos = NULL;                                          \
                                                                        \
static void                                                             \
NAME ## _add_node_to_array(const void *nodep, const VISIT which,        \
        const int depth)                                                \
{                                                                       \
    if (!NAME ## _array_pos)                                            \
        return;                                                         \
    switch (which) {                                                    \
        case preorder:                                                  \
        case endorder:                                                  \
            break;                                                      \
        case postorder:                                                 \
        case leaf:                                                      \
            *NAME ## _array_pos = *(T*)nodep;                           \
            NAME ## _array_pos++;                                       \
            break;                                                      \
    }                                                                   \
}                                                                       \
                                                                        \
int                                                                     \
NAME ## _get_array(const NAME ## _t * set, T ** element)                \
{                                                                       \
    if (!element)                                                       \
        goto END;                                                       \
    *element = malloc(set->size * sizeof(T));                           \
    if (!*element)                                                      \
        return -1;                                                      \
    NAME ## _array_pos = *element;                                      \
    twalk(set->root, NAME ## _add_node_to_array);                       \
    NAME ## _array_pos = NULL;                                          \
END:                                                                    \
    return (int)(set->size);                                                   \
}

#endif /* UTIL_SET_H */
