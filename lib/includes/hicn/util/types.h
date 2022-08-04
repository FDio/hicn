/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

/* Standard types. */
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef double f64;
typedef float f32;

/* Architecture-dependent uword size */
#if INTPTR_MAX == INT64_MAX
#define hicn_log2_uword_bits 6
#elif INTPTR_MAX == INT32_MAX
#define hicn_log2_uword_bits 5
#else
#error "Impossible to detect architecture"
#endif

#define hicn_uword_bits (1 << hicn_log2_uword_bits)

/* Word types. */
#if hicn_uword_bits == 64
/* 64 bit word machines. */
typedef u64 hicn_uword;
#else
/* 32 bit word machines. */
typedef u32 hicn_uword;
#endif

typedef hicn_uword hicn_ip_csum_t;

#define hicn_uword_bits (1 << hicn_log2_uword_bits)

/* Helper for avoiding warnings about type-punning */
#define UNION_CAST(x, destType)                                               \
  (((union {                                                                  \
     __typeof__ (x) a;                                                        \
     destType b;                                                              \
   }) x)                                                                      \
     .b)

typedef int (*cmp_t) (const void *, const void *);

/* Enums */

#define IS_VALID_ENUM_TYPE(NAME, x) ((x > NAME##_UNDEFINED) && (x < NAME##_N))

/* Float */

uint32_t htonf (float f);
float ntohf (uint32_t i);

#endif /* UTIL_TYPES */
