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

#include <hicn/core/nexthops.h>
#include <hicn/core/forwarder.h>

#include "local_remote.h"

static int strategy_local_remote_initialize(strategy_entry_t *entry,
                                            const void *forwarder) {
  printf("INIT FWD STRATEGY REMOTE LOCAL\n");
  srand((unsigned int)time(NULL));
  entry->forwarder = forwarder;
  return 0;
}

static int strategy_local_remote_finalize(strategy_entry_t *entry) {
  /* Nothing to do */
  return 0;
}

static int strategy_local_remote_add_nexthop(strategy_entry_t *entry,
                                             nexthops_t *nexthops,
                                             off_t offset) {
  /* Nothing to do */
  return 0;
}

static int strategy_local_remote_remove_nexthop(strategy_entry_t *entry,
                                                nexthops_t *nexthops,
                                                off_t offset) {
  /* Nothing to do */
  return 0;
}

static nexthops_t *strategy_local_remote_lookup_nexthops(
    strategy_entry_t *entry, nexthops_t *nexthops, const msgbuf_t *msgbuf) {
  if (!entry->forwarder) {
    // the forwarder does not exists, drop packet
    nexthops_disable_all(nexthops);
    return nexthops;
  }

  unsigned cid = msgbuf_get_connection_id(msgbuf);
  connection_table_t *table = forwarder_get_connection_table(entry->forwarder);
  if (!table) {
    // the connection table does not exists, drop packet.
    nexthops_disable_all(nexthops);
    return nexthops;
  }

  connection_t *in = connection_table_get_by_id(table, cid);
  if (!in) {
    // the ingress connection does not exists, drop packet.
    nexthops_disable_all(nexthops);
    return nexthops;
  }

  bool in_is_local = connection_is_local(in);
  nexthops_enumerate(nexthops, i, nexthop, {
    connection_t *out = connection_table_get_by_id(table, nexthop);
    if (out) {
      if (connection_is_local(out) != in_is_local) {
        // this connection satisfies the requirements, send the intetest here.
        nexthops_select(nexthops, i);
        return nexthops;
      }
    }
  });

  // no out connection satisfies the requirements, drop packet.
  nexthops_disable_all(nexthops);
  return nexthops;
}

static int strategy_local_remote_on_data(strategy_entry_t *entry,
                                         nexthops_t *nexthops,
                                         const nexthops_t *data_nexthops,
                                         const msgbuf_t *msgbuf,
                                         Ticks pitEntryCreation,
                                         Ticks objReception) {
  /* Nothing to do */
  return 0;
}

static int strategy_local_remote_on_timeout(
    strategy_entry_t *entry, nexthops_t *nexthops,
    const nexthops_t *timeout_nexthops) {
  /* Nothing to do */
  return 0;
}

DECLARE_STRATEGY(local_remote);
