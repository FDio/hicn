/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <hicn/transport/portability/platform.h>

namespace transport {
namespace portability {
namespace cache {

/**
 * @Prefetch utilities
 */

/* Default cache line size of 64 bytes. */
#ifndef LOG2_CACHE_LINE_BYTES
static constexpr const std::size_t klog2_cache_line_bytes = 6;
#else
static constexpr const std::size_t klog2_cache_line_bytes =
    LOG2_CACHE_LINE_BYTES;
#endif

/* How much data prefetch instruction prefetches */
#ifndef LOG2_CACHE_PREFETCH_BYTES
static constexpr const std::size_t klog2_cache_prefetch_bytes =
    klog2_cache_line_bytes;
#else
static constexpr const std::size_t klog2_cache_prefetch_bytes =
    LOG2_CACHE_PREFETCH_BYTES;
#endif

/* Default cache line fill buffers. */
#ifndef N_PREFETCHES
static constexpr const std::size_t kn_prefetches = 16;
#else
static constexpr const std::size_t kn_prefetches = N_PREFETCHES;
#endif

static constexpr const std::size_t kcache_line_bytes =
    (1 << klog2_cache_line_bytes);
static constexpr const std::size_t kcache_prefetch_bytes =
    (1 << klog2_cache_prefetch_bytes);

static constexpr const int READ = 0;
static constexpr const int LOAD = 0; /* alias for read */
static constexpr const int WRITE = 1;
static constexpr const int STORE = 1; /* alias for write */

#if defined(__GNUC__) || defined(__clang__)
// Clang & GCC

template <int type>
static inline void _prefetch(uint8_t *addr, std::size_t n, std::size_t size) {
  if (size > n * kcache_prefetch_bytes) {
    __builtin_prefetch(addr + n * kcache_prefetch_bytes, type,
                       /* locality */ 3);
  }
}

template <typename T, int type>
static inline void prefetch(T *addr, std::size_t size) {
  uint8_t *_addr = reinterpret_cast<uint8_t *>(addr);

  _prefetch<type>(_addr, 0, size);
  _prefetch<type>(_addr, 1, size);
  _prefetch<type>(_addr, 2, size);
  _prefetch<type>(_addr, 3, size);
}
#endif

}  // namespace cache
}  // namespace portability
}  // namespace transport