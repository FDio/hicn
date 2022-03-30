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

#include "replication.h"

/* Shorthand */
#define strategy_state_t strategy_replication_state_t

static int strategy_replication_initialize(strategy_entry_t *entry,
                                           const void *forwarder) {
  entry->forwarder = forwarder;
  strategy_state_t *state = &entry->state.replication;
  state->prev_nexthops = malloc(sizeof(nexthops_t));
  *((nexthops_t *)state->prev_nexthops) = NEXTHOPS_EMPTY;
  return 0;
}

static int strategy_replication_finalize(strategy_entry_t *entry) {
  /* Nothing to do */
  strategy_state_t *state = &entry->state.replication;
  free(state->prev_nexthops);
  return 0;
}

static int strategy_replication_add_nexthop(strategy_entry_t *entry,
                                            nexthops_t *nexthops,
                                            off_t offset) {
  /* Nothing to do */
  return 0;
}

static int strategy_replication_remove_nexthop(strategy_entry_t *entry,
                                               nexthops_t *nexthops,
                                               off_t offset) {
  /* Nothing to do */
  return 0;
}

static nexthops_t *strategy_replication_lookup_nexthops(
    strategy_entry_t *entry, nexthops_t *nexthops, const msgbuf_t *msgbuf) {
  // if nexthops is different from prev_nexthops send updates
  strategy_state_t *state = &entry->state.replication;

  if (!nexthops_equal((nexthops_t *)state->prev_nexthops, nexthops)) {
    // send updates
    strategy_replication_options_t *options = &entry->options.replication;
    update_remote_node_paths(nexthops, entry->forwarder,
                             options->local_prefixes);

    // update next hops
    nexthops_copy(nexthops, (nexthops_t *)state->prev_nexthops);
  }

  // Return all next hops
  return nexthops;
}

static int strategy_replication_on_data(strategy_entry_t *entry,
                                        nexthops_t *nexthops,
                                        const nexthops_t *data_nexthops,
                                        const msgbuf_t *msgbuf,
                                        Ticks pitEntryCreation,
                                        Ticks objReception) {
  /* Nothing to do */
  return 0;
}

static int strategy_replication_on_timeout(strategy_entry_t *entry,
                                           nexthops_t *nexthops,
                                           const nexthops_t *timeout_nexthops) {
  /* Nothing to do */
  return 0;
}

DECLARE_STRATEGY(replication);
