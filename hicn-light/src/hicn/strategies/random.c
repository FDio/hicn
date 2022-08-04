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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hicn/hicn-light/config.h>

#include <hicn/core/nexthops.h>
#include <hicn/core/strategy.h>
#include <hicn/core/strategy_vft.h>

#include "random.h"

static int strategy_random_initialize(strategy_entry_t *entry,
                                      const void *forwarder) {
  srand((unsigned int)time(NULL));
  entry->forwarder = forwarder;
  return 0;
}

static int strategy_random_finalize(strategy_entry_t *entry) {
  /* Nothing to do */
  return 0;
}

static int strategy_random_add_nexthop(strategy_entry_t *entry,
                                       nexthops_t *nexthops, off_t offset) {
  /* Nothing to do */
  return 0;
}

static int strategy_random_remove_nexthop(strategy_entry_t *entry,
                                          nexthops_t *nexthops, off_t offset) {
  /* Nothing to do */
  return 0;
}

static nexthops_t *strategy_random_lookup_nexthops(strategy_entry_t *entry,
                                                   nexthops_t *nexthops,
                                                   const msgbuf_t *msgbuf) {
  if (nexthops_get_curlen(nexthops) == 0) return nexthops;
  nexthops_select(nexthops, rand() % nexthops_get_len(nexthops));
  return nexthops;
}

static int strategy_random_on_data(strategy_entry_t *entry,
                                   nexthops_t *nexthops,
                                   const nexthops_t *data_nexthops,
                                   const msgbuf_t *msgbuf,
                                   Ticks pitEntryCreation, Ticks objReception) {
  /* Nothing to do */
  return 0;
}

static int strategy_random_on_timeout(strategy_entry_t *entry,
                                      nexthops_t *nexthops,
                                      const nexthops_t *timeout_nexthops) {
  /* Nothing to do */
  return 0;
}

DECLARE_STRATEGY(random);
