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

/**
 * \file content_store.c
 * \brief Implementation of hICN content_store
 */

#include "content_store.h"
#include "packet_cache.h"

extern const cs_ops_t cs_lru;

const cs_ops_t *const cs_vft[] = {
    [CS_TYPE_LRU] = &cs_lru,
};

cs_t *_cs_create(cs_type_t type, size_t max_size) {
  if (!CS_TYPE_VALID(type)) {
    ERROR("[cs_create] Invalid content store type");
    return NULL;
  }

  if (max_size == 0) max_size = DEFAULT_CS_SIZE;

  cs_t *cs = malloc(sizeof(cs_t));
  if (!cs) return NULL;

  cs->type = type;
  cs->num_entries = 0;
  cs->max_size = max_size;
  cs_vft[type]->initialize(cs);
  cs->stats.lru = (cs_lru_stats_t){0};

  return cs;
}

void cs_free(cs_t *cs) {
  assert(cs);

  cs_vft[cs->type]->finalize(cs);
  free(cs);
}

void _cs_clear(cs_t **cs_ptr) {
  cs_type_t cs_type = (*cs_ptr)->type;
  size_t max_size = (*cs_ptr)->max_size;

  // Free and recreate the CS
  cs_free(*cs_ptr);
  *cs_ptr = _cs_create(cs_type, max_size);
}

void cs_hit(cs_t *cs) {
  cs->stats.lru.countHits++;
  TRACE("ContentStore hit (hits %u, misses %u)", cs->stats.lru.countHits,
        cs->stats.lru.countMisses);
}

void cs_miss(cs_t *cs) {
  cs->stats.lru.countMisses++;
  TRACE("ContentStore miss (hits %u, misses %u)", cs->stats.lru.countHits,
        cs->stats.lru.countMisses);
}

void cs_log(cs_t *cs) {
  DEBUG(
      "Content store: size = %u, capacity = %u, hits = %u, misses = %u, adds = "
      "%u, updates = %u, deletions = %u (with evictions = %u)",
      cs->num_entries, cs->max_size, cs->stats.lru.countHits,
      cs->stats.lru.countMisses, cs->stats.lru.countAdds,
      cs->stats.lru.countUpdates, cs->stats.lru.countLruDeletions,
      cs->stats.lru.countLruEvictions);
}
