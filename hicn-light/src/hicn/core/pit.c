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
 * The pending interest table.
 *
 * Interest aggregation strategy:
 * - The first Interest for a name is forwarded
 * - A second Interest for a name from a different reverse path may be
 * aggregated
 * - A second Interest for a name from an existing Interest is forwarded
 * - The Interest Lifetime is like a subscription time.  A reverse path entry is
 * removed once the lifetime is exceeded.
 * - Whan an Interest arrives or is aggregated, the Lifetime for that reverse
 * hop is extended.  As a simplification, we only keep a single lifetime not per
 * reverse hop.
 *
 */

#include "pit.h"

Ticks pit_calculate_lifetime(pit_t* pit, const msgbuf_t* msgbuf) {
  uint64_t lifetime = msgbuf_get_lifetime(msgbuf);
  if (lifetime == 0) lifetime = NSEC_TO_TICKS(DEFAULT_INTEREST_LIFETIME);

  return ticks_now() + lifetime;
}

/* This is only used as a hint for first allocation, as the table is resizeable
 */
#define DEFAULT_PIT_SIZE 65535

pit_t* _pit_create(size_t init_size, size_t max_size) {
  pit_t* pit = malloc(sizeof(pit_t));
  if (!pit) return NULL;

  if (init_size == 0) init_size = DEFAULT_PIT_SIZE;

  pit->max_size = max_size;
  return pit;
}

void pit_free(pit_t* pit) {
  assert(pit);
  free(pit);
}

// void pit_print(const pit_t *pit) {
//   const Name *k;
//   unsigned v;
//   pit_entry_t * entry;
//   Ticks expire_ts;

//   printf("*** PIT ***\n");
//   kh_foreach(pit->index_by_name, k, v, {
//     char *name_str = name_ToString(k);
//     entry = pit_at(pit, v);
//     expire_ts = pit_entry_get_expire_ts(entry);
//     printf("%s\t\t\texpire=%lu\n", name_str, expire_ts);
//     free(name_str);
//   })
// }
