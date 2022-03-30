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

#include "local_prefixes.h"
#include <hicn/core/forwarder.h>
#include <hicn/core/nexthops.h>
#include <hicn/core/name.h>
#include <hicn/core/mapme.h>

#define MAX_PREFIXES 10

struct local_prefixes_s {
  Name local_prefixes[MAX_PREFIXES];
  unsigned len;
};

local_prefixes_t *create_local_prefixes() {
  local_prefixes_t *lp = calloc(1, sizeof(local_prefixes_t));
  if (!lp) return NULL;
  return lp;
}

void free_local_prefixes(local_prefixes_t *lp) { free(lp); }

unsigned local_prefixes_get_len(local_prefixes_t *prefixes) {
  return prefixes->len;
}

bool contain_prefix(local_prefixes_t *prefixes, Name *name) {
  for (unsigned i = 0; i < prefixes->len; i++) {
    if (name_Equals(&(prefixes->local_prefixes[i]), name)) return true;
  }
  return false;
}

void local_prefixes_add_prefixes(local_prefixes_t *prefixes,
                                 local_prefixes_t *new_prefixes) {
  // if there is not enough space for the new prefixes they are not added
  unsigned i = 0;
  while ((i < new_prefixes->len) && (prefixes->len < MAX_PREFIXES)) {
    if (!contain_prefix(prefixes, &(new_prefixes->local_prefixes[i]))) {
      name_Copy(&new_prefixes->local_prefixes[i],
                &prefixes->local_prefixes[prefixes->len]);
      prefixes->len++;
    }
    i++;
  }
}

void local_prefixes_add_prefix(local_prefixes_t *prefixes, const void *prefix) {
  if (prefixes->len >= MAX_PREFIXES) return;
  Name *n = (Name *)prefix;
  if (!contain_prefix(prefixes, n)) {
    name_Copy(n, &(prefixes->local_prefixes[prefixes->len]));
    prefixes->len++;
  }
}

void update_remote_node_paths(const void *nexthops, const void *forwarder,
                              local_prefixes_t *prefixes) {
  if (!prefixes) return;
  struct mapme_s *mapme = forwarder_get_mapme((forwarder_t *)forwarder);
  fib_t *fib = forwarder_get_fib((forwarder_t *)forwarder);
  for (unsigned i = 0; i < prefixes->len; i++) {
    fib_entry_t *entry = fib_match_name(fib, &prefixes->local_prefixes[i]);
    if (!entry) continue;
    mapme_set_adjacencies(mapme, entry, (nexthops_t *)nexthops, false);
  }
}
