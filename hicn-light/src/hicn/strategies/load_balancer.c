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

#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hicn/core/strategy.h>
#include <hicn/core/strategy_vft.h>
#include <hicn/core/nexthops.h>
#include <hicn/core/fib_entry.h>

#include "load_balancer.h"

#define AVG_PI_THRESHOLD 1e-3
#define AVG_PI_MIN 0.1

#define ALPHA 0.9

/* Shorthand */
#define nexthop_state_t strategy_load_balancer_nexthop_state_t
#define nexthop_state(nexthops, i) (&nexthops->state[i].load_balancer)

static const nexthop_state_t NEXTHOP_STATE_INIT = {
    .pi = 0,
    .avg_pi = 0.0,
    .weight = 1,
};

static inline void update_state(nexthop_state_t *state) {
  state->avg_pi = (state->avg_pi * ALPHA) + (state->pi * 1 - ALPHA);
  if (state->avg_pi < AVG_PI_THRESHOLD) state->avg_pi = AVG_PI_MIN;
  state->weight = 1 / state->avg_pi;
}

static inline void update_state_inc(nexthop_state_t *state) {
  state->pi++;
  update_state(state);
}

static inline void update_state_dec(nexthop_state_t *state) {
  if (state->pi > 0) state->pi--;
  update_state(state);
}

static inline void reset_all(nexthops_t *nexthops) {
  nexthops_enumerate(nexthops, i, nexthop, {
    (void)nexthop;
    nexthops->state[i].load_balancer = NEXTHOP_STATE_INIT;
  });
}

static int strategy_load_balancer_initialize(strategy_entry_t *entry,
                                             const void *forwarder) {
  /* No reset, this will be done when a nexthop is added */
  entry->forwarder = forwarder;
  return 0;
}

static int strategy_load_balancer_finalize(strategy_entry_t *entry) {
  /* Nothing to do */
  return 0;
}

static int strategy_load_balancer_add_nexthop(strategy_entry_t *entry,
                                              nexthops_t *nexthops,
                                              off_t offset) {
  /* We reset the state of all nexthops */
  reset_all(nexthops);
  return 0;
}

static int strategy_load_balancer_remove_nexthop(strategy_entry_t *entry,
                                                 nexthops_t *nexthops,
                                                 off_t offset) {
  reset_all(nexthops);
  return 0;
}

static nexthops_t *strategy_load_balancer_lookup_nexthops(
    strategy_entry_t *entry, nexthops_t *nexthops, const msgbuf_t *msgbuf) {
  if (nexthops_get_curlen(nexthops) == 0) return nexthops;
  /* Compute the sum of weights of potential next hops */
  double sum = 0;
  nexthops_enumerate(nexthops, i, nexthop, {
    (void)nexthop;
    sum += nexthops_state(nexthops, i).load_balancer.weight;
  });

  /* Perform weighted random selection */
  double distance = (double)rand() * sum / ((double)RAND_MAX + 1);

  nexthops_enumerate(nexthops, i, nexthop, {
    distance -= nexthop_state(nexthops, i)->weight;
    if (distance < 0) {
      nexthops_select(nexthops, i);
      update_state_inc(nexthop_state(nexthops, i));
      break;
    }
  });
  return nexthops;
}

static int strategy_load_balancer_on_timeout(
    strategy_entry_t *entry, nexthops_t *nexthops,
    const nexthops_t *timeout_nexthops) {
  /*
   * As we have few nexthops in FIB entry, and even fewer selected ones in
   * nexthops, we can allow for linear search that will be very efficient
   * CPU-wise.
   */
  nexthops_foreach(timeout_nexthops, timeout_nexthop, {
    nexthops_enumerate(nexthops, i, nexthop, {
      if (nexthop == timeout_nexthop)
        update_state_dec(nexthop_state(nexthops, i));
    });
  });
  return 0;
}

static int strategy_load_balancer_on_data(strategy_entry_t *entry,
                                          nexthops_t *nexthops,
                                          const nexthops_t *data_nexthops,
                                          const msgbuf_t *msgbuf,
                                          Ticks pitEntryCreation,
                                          Ticks objReception) {
  return strategy_load_balancer_on_timeout(entry, nexthops, data_nexthops);
}

#undef nexthop_state_t

DECLARE_STRATEGY(load_balancer);

#undef nexthop_state_t
