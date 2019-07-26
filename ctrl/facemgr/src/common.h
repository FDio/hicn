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

/**
 * \file common.h
 * \file Common definitions used throughout the code
 */
#ifndef FACEMGR_COMMON_H
#define FACEMGR_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include "util/types.h"
#include "util/ip_address.h"
#include "util/token.h" // XXX debug

//#define DEBUG

/* Return value conventions */
#define FACEMGR_SUCCESS 0
#define FACEMGR_FAILURE -1
#define FACEMGR_IS_ERROR(rc) (rc < 0)

/* Useful types and macros for comparisons */
typedef int(*cmp_t)(const void * x, const void * y);

#define INT_CMP(x, y) x < y ? -1 : (x == y ? 0 : 1)

/* Dump with indent */
#define INDENT(n, fmt) "%*s" fmt, n, ""
#define printfi(n, fmt, ...) printf(INDENT(n*4, fmt), ##__VA_ARGS__)

/* Boilerplate code */

#define NO_INITIALIZE(NAME)                                             \
int                                                                     \
NAME ## _initialize(NAME ## _t * obj) {                                 \
    return FACEMGR_SUCCESS;                                             \
}

#define NO_FINALIZE(NAME)                                               \
int                                                                     \
NAME ## _finalize(NAME ## _t * obj) {                                   \
    return FACEMGR_SUCCESS;                                             \
}

#define AUTOGENERATE_CREATE_FREE(NAME)                                  \
                                                                        \
NAME ## _t *                                                            \
NAME ## _create()                                                       \
{                                                                       \
    NAME ## _t * obj  = malloc(sizeof(NAME ## _t));                     \
    if (!obj)                                                           \
        goto ERR_MALLOC;                                                \
                                                                        \
    if (FACEMGR_IS_ERROR(NAME ## _initialize(obj)))                     \
        goto ERR_INIT;                                                  \
                                                                        \
    return obj;                                                         \
                                                                        \
ERR_INIT:                                                               \
    free(obj);                                                          \
ERR_MALLOC:                                                             \
    return NULL;                                                        \
}                                                                       \
                                                                        \
void                                                                    \
NAME ## _free(NAME ## _t * obj)                                         \
{                                                                       \
    if (FACEMGR_IS_ERROR(NAME ## _finalize(obj)))                       \
        (void)0; /* XXX */                                              \
    free(obj);                                                          \
}                                                                       \

#define AUTOGENERATE_DEFS(NAME)                                         \
int NAME ## _initialize(NAME ## _t *);                                  \
int NAME ## _finalize(NAME ## _t *);                                    \
NAME ## _t * NAME ## _create();                                         \
void NAME ## _free(NAME ## _t *);                                       \

#endif /* FACEMGR_COMMON_H */
