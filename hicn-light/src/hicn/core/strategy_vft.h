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
 * \file strategy_vft.h
 * \brief hICN forwarding strategy VFT
 */
#ifndef HICNLIGHT_STRATEGY_VFT_H
#define HICNLIGHT_STRATEGY_VFT_H

#include "msgbuf.h"

#include "../strategies/best_path.h"
#include "../strategies/load_balancer.h"
#include "../strategies/random.h"
#include "../strategies/replication.h"

typedef union {
  strategy_load_balancer_options_t load_balancer;
  strategy_random_options_t random;
  strategy_replication_options_t replication;
  strategy_bestpath_options_t bestpath;
} strategy_options_t;

typedef struct {
#ifdef WITH_POLICY
  int priority;
#endif /* WITH_POLICY */
  union {
    strategy_load_balancer_nexthop_state_t load_balancer;
    strategy_random_nexthop_state_t random;
    strategy_replication_nexthop_state_t replication;
    strategy_bestpath_nexthop_state_t bestpath;
  };
} strategy_nexthop_state_t;

#define STRATEGY_NEXTHOP_STATE_EMPTY \
  {                                  \
    0, {                             \
      { 0 }                          \
    }                                \
  }

typedef union {
  strategy_load_balancer_state_t load_balancer;
  strategy_random_state_t random;
  strategy_replication_state_t replication;
  strategy_bestpath_state_t bestpath;
} strategy_state_t;
// XXX This has to be merged with nexthops
// XXX How to avoid errors due to pool id reuse (eg on_data) ?

/**
 * @typedef strategy_ops_t
 * @abstract Forwarding strategy implementation
 * @constant receiveObject is called when we receive an object and have a
 * measured round trip time.  This allows a strategy to update its performance
 * data.
 * @constant lookupNexthop Find the set of nexthops to use for the Interest.
 *           May be empty, should not be NULL.  Must be destroyed.
 * @constant addNexthop Add a nexthop to the list of available nexthops with a
 * routing protocol-specific cost.
 * @constant destroy cleans up the strategy, freeing all memory and state.  A
 * strategy is reference counted, so the final destruction only happens after
 * the last reference is released.
 * @discussion <#Discussion#>
 */

struct strategy_entry_s;
struct nexthops_s;

typedef struct {
  const char *name;

  int (*initialize)(struct strategy_entry_s *entry, const void *forwarder);

  int (*finalize)(struct strategy_entry_s *entry);

  struct nexthops_s *(*lookup_nexthops)(struct strategy_entry_s *entry,
                                        struct nexthops_s *nexthops,
                                        const msgbuf_t *msgbuf);

  int (*add_nexthop)(struct strategy_entry_s *strategy,
                     struct nexthops_s *nexthops, off_t offset);

  int (*remove_nexthop)(struct strategy_entry_s *entry,
                        struct nexthops_s *nexthops, off_t offset);

  int (*on_data)(struct strategy_entry_s *entry, struct nexthops_s *nexthops,
                 const struct nexthops_s *data_nexthops, const msgbuf_t *msgbuf,
                 Ticks pitEntryCreation, Ticks objReception);

  int (*on_timeout)(struct strategy_entry_s *entry, struct nexthops_s *nexthops,
                    const struct nexthops_s *timeout_nexthops);

} strategy_ops_t;

extern const strategy_ops_t *const strategy_vft[];

#define DECLARE_STRATEGY(NAME)                              \
  const strategy_ops_t strategy_##NAME = {                  \
      .name = #NAME,                                        \
      .initialize = strategy_##NAME##_initialize,           \
      .finalize = strategy_##NAME##_finalize,               \
      .add_nexthop = strategy_##NAME##_add_nexthop,         \
      .remove_nexthop = strategy_##NAME##_remove_nexthop,   \
      .lookup_nexthops = strategy_##NAME##_lookup_nexthops, \
      .on_data = strategy_##NAME##_on_data,                 \
      .on_timeout = strategy_##NAME##_on_timeout,           \
  }

#endif /* HICNLIGHT_STRATEGY_VFT_H */
