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

/**
 * \file objects/cache.h
 * \brief Cache.
 */

#ifndef HICNCTRL_OBJECTS_CACHE_H
#define HICNCTRL_OBJECTS_CACHE_H

typedef struct {
  uint8_t serve;  // 1 = on, 0 = off
  uint8_t store;  // 1 = on, 0 = off
} hc_cache_t;

typedef struct {
  bool store;
  bool serve;
  size_t cs_size;
  size_t num_stale_entries;
} hc_cache_info_t;

int hc_cache_snprintf(char *s, size_t size, const hc_cache_info_t *cache_info);

#endif /* HICNCTRL_OBJECTS_CACHE_H */
