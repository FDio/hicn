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

#ifndef UTIL_TYPES
#define UTIL_TYPES
#ifdef _WIN32
#include <hicn/util/windows/windows_Utils.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Helper for avoiding warnings about type-punning */
#define UNION_CAST(x, destType) \
   (((union {__typeof__(x) a; destType b;})x).b)

//typedef unsigned int hash_t;

typedef int (*cmp_t)(const void *, const void *);

/* Enums */

#define IS_VALID_ENUM_TYPE(NAME, x) ((x > NAME ## _UNDEFINED) && (x < NAME ## _N))

#endif /* UTIL_TYPES */
