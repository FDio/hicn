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
 * @file fib_entry.h
 * @brief A forwarding entry in the FIB table
 *
 * A Forwarding Information Base (FIB) entry (fib_entry_t) is a
 * set of nexthops for a name.  It also indicates the forwarding strategy.
 *
 * Each nexthop contains the ConnectionId assocaited with it.  This could be
 * something specific like a MAC address or point-to-point tunnel.  Or, it
 * could be something general like a MAC group address or ip multicast overlay.
 *
 * See strategy.h for a description of forwarding strategies.
 * In short, a strategy is the algorithm used to select one or more nexthops
 * from the set of available nexthops.
 *
 * Each nexthop also contains a void* to a forwarding strategy data container.
 * This allows a strategy to keep proprietary information about each nexthop.
 *
 *
 */

#ifndef fib_entry_h
#define fib_entry_h

#include <hicn/name.h>
#include "strategy.h"
#include "msgbuf.h"
#include "nexthops.h"
#include "policy_stats.h"

typedef struct {
  hicn_prefix_t prefix;
  unsigned refcount;
  nexthops_t nexthops;

  /* This is used for producer prefixes only */
  uint32_t nexthops_hash;

  strategy_entry_t strategy;

  const void *forwarder;

#ifdef WITH_POLICY
  hicn_policy_t policy;
#endif /* WITH_POLICY */

  policy_counters_t policy_counters;
  policy_stats_t policy_stats;

#ifdef WITH_MAPME
#if 0
  /* In case of no multipath, this stores the previous decision taken by policy.
   * As the list of nexthops is not expected to change, we can simply store the
   * flags */
  uint_fast32_t prev_nexthops_flags;
#endif
  void *user_data;
  void (*user_data_release)(void **user_data);
#endif /* WITH_MAPME */
} fib_entry_t;

#define _fib_entry_var(x) _fib_entry_##x

#define fib_entry_strategy_type(fib_entry) ((fib_entry)->strategy.type)

#define fib_entry_get_nexthops(fib_entry) (&(fib_entry)->nexthops)

#define fib_entry_nexthops_len(fib_entry) \
  (nexthops_get_len(&(fib_entry)->nexthops))
#define fib_entry_nexthops_curlen(fib_entry) \
  (nexthops_curlen(&(fib_entry)->nexthops))
#define fib_entry_get_nexthop(fib_entry, i) ((fib_entry)->nexthops.elts[i])
#define fib_entry_foreach_nexthop(fib_entry, nexthop, BODY) \
  nexthops_foreach(fib_entry->nexthops, BODY)

#define fib_entry_get_nexthops_hash(E) ((E)->nexthops_hash)
#define fib_entry_set_nexthops_hash(E, H) (E)->nexthops_hash = (H)

static inline void fib_entry_set_nexthops(fib_entry_t *entry,
                                          nexthops_t *nexthops) {
  entry->nexthops = *nexthops;
}

static inline void fib_entry_initialize_nexthops(fib_entry_t *entry) {
  entry->nexthops = NEXTHOPS_EMPTY;
}

static inline bool fib_entry_nexthops_changed(fib_entry_t *entry,
                                              nexthops_t *nexthops) {
  uint32_t old_hash = fib_entry_get_nexthops_hash(entry);
  uint32_t hash = nexthops_get_hash(nexthops);
  if (hash != old_hash) {
    fib_entry_set_nexthops_hash(entry, hash);
    return true;
  }
  return false;
};

struct forwarder_s;

/*
 * This does a copy of the name passed as parameter
 */
fib_entry_t *fib_entry_create(const hicn_prefix_t *prefix,
                              strategy_type_t strategy_type,
                              strategy_options_t *strategy_options,
                              const struct forwarder_s *table);

void fib_entry_free(fib_entry_t *entry);

void fib_entry_add_strategy_options(fib_entry_t *entry,
                                    strategy_type_t strategy_type,
                                    strategy_options_t *strategy_options);

void fib_entry_set_strategy(fib_entry_t *fib_entry,
                            strategy_type_t strategy_type,
                            strategy_options_t *strategy_options);

void fib_entry_nexthops_add(fib_entry_t *fib_entry, unsigned nexthop);

void fib_entry_nexthops_remove(fib_entry_t *fib_entry, unsigned nexthop);

/**
 * @function fib_entry_nexthops_get
 * @abstract Returns the nexthop set of the FIB entry.  You must Acquire if it
 * will be saved.
 * @discussion
 *   Returns the next hop set for the FIB entry.
 */
const nexthops_t *fib_entry_nexthops_get(const fib_entry_t *fib_entry);

const nexthops_t *fib_entry_nexthops_getFromForwardingStrategy(
    fib_entry_t *fib_entry, const msgbuf_t *interest_msgbuf,
    bool is_retransmission);

void fib_entry_on_data(fib_entry_t *fib_entry, nexthops_t *nexthops,
                       const msgbuf_t *object_msgbuf, Ticks pit_entry_creation,
                       Ticks data_reception);

#ifdef WITH_POLICY
hicn_policy_t fib_entry_get_policy(const fib_entry_t *fib_entry);
void fib_entry_reconsider_policy(fib_entry_t *fib_entry);
void fib_entry_set_policy(fib_entry_t *fib_entry, hicn_policy_t policy);
void fib_entry_update_stats(fib_entry_t *fib_entry, uint64_t now);
#endif /* WITH_POLICY */

nexthops_t *fib_entry_filter_nexthops(fib_entry_t *entry, nexthops_t *nexthops,
                                      unsigned ingress_id, bool prefer_local);

nexthops_t *fib_entry_get_mapme_nexthops(fib_entry_t *entry,
                                         nexthops_t *new_nexthops);

nexthops_t *fib_entry_get_available_nexthops(fib_entry_t *fib_entry,
                                             unsigned in_connection,
                                             nexthops_t *new_nexthops);
void fib_entry_on_timeout(fib_entry_t *fib_entry, const nexthops_t *egressId);
nexthops_t *fib_entry_get_nexthops_from_strategy(
    fib_entry_t *fib_entry, const msgbuf_t *interest_msgbuf,
    bool is_retransmission);

/**
 * @function fib_entry_get_prefix
 * @return The FIB entry prefix
 */
const hicn_prefix_t *fib_entry_get_prefix(const fib_entry_t *fib_entry);

bool fib_entry_has_local_nexthop(const fib_entry_t *entry);
bool fib_entry_has_all_local_nexthops(const fib_entry_t *entry);

#ifdef WITH_MAPME

/**
 * @function fib_entry_get_user_data
 * @abstract Returns user data associated to the FIB entry.
 * @param [in] fib_entry - Pointer to the FIB entry.
 * @return User data as a void pointer
 */
void *fib_entry_get_user_data(const fib_entry_t *fib_entry);

/**
 * @function fib_entry_get_user_data
 * @abstract Associates user data and release callback to a FIB entry.
 * @param [in] fib_entry - Pointer to the FIB entry.
 * @param [in] user_data - Generic pointer to user data
 * @param [in@ user_data_release - Callback used to release user data upon
 * change of FIB entry removal.
 */
void fib_entry_set_user_data(fib_entry_t *fib_entry, const void *user_data,
                             void (*user_data_release)(void **));

#endif /* WITH_MAPME */

#endif  // fib_entry_h
