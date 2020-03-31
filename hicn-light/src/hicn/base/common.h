/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file array.h
 * \brief Fixed-size pool allocator
 */

#ifndef UTIL_COMMON_H
#define UTIL_COMMON_H

#define round_pow2(x, pow2) ((x + pow2 - 1) & ~(pow2 - 1))

#define _SIZEOF_ALIGNED(x, size) round_pow2(sizeof(x), size)
#define SIZEOF_ALIGNED(x) _SIZEOF_ALIGNED(x, sizeof(void*))

/* Definitions for builtins unavailable on MSVC */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>

uint32_t __inline __builtin_ctz(uint32_t value) {
  uint32_t trailing_zero = 0;
  if (_BitScanForward(&trailing_zero, value))
    return trailing_zero;
  else
    return 32;
}

uint32_t __inline __builtin_clz(uint32_t value) {
  uint32_t leading_zero = 0;
  if (_BitScanReverse(&leading_zero, value))
    return 31 - leading_zero;
  else
    return 32;
}

uint32_t __inline __builtin_clzll(uint64_t value) {
  uint32_t leading_zero = 0;
  if (_BitScanReverse64(&leading_zero, value))
    return 63 - leading_zero;
  else
    return 64;
}

#define __builtin_clzl __builtin_clzll
#endif

#define next_pow2(x) (x == 1 ? 1 : 1<<(64-__builtin_clzl(x-1)))

#endif /* UTIL_COMMON_H */
