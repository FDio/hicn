/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef HICNLIGHT_CS_LRU_H
#define HICNLIGHT_CS_LRU_H

#define LRU_FAILURE 0
#define LRU_SUCCESS 1
#define LRU_EVICTION 2

typedef struct {
  off_t prev;
  off_t next;
} cs_entry_lru_state_t;

typedef struct {
  off_t head;
  off_t tail;
} cs_lru_state_t;

/**
 * @brief Count the number of:
 * - CS matches
 * - CS misses
 * - entries added to CS/LRU (upon receiving a data packet)
 * - entries updated in the LRU
 *   (because an already-existing CS entry has been updated)
 * - LRU evictions
 *
 * 'countExpiryEvictions' is not collected since an entry is never evicted
 * because of expiration. An expired CS entry is only detected when
 * a data packet with the same name is received, causing an update
 * (NOT an actual eviction).
 */
typedef struct {
  uint64_t countHits;
  uint64_t countMisses;
  uint64_t countAdds;
  uint64_t countUpdates;
  uint64_t countLruDeletions;
  uint64_t countLruEvictions;
} cs_lru_stats_t;

#endif /* HICNLIGHT_CS_LRU_H */
