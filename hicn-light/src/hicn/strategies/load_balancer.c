/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#define NEXTHOP_STATE_INIT {    \
    .pi = 0,                    \
    .avg_pi = 0.0,              \
    .weight = 1,                \
}

/* Shorthand */
#define nexthop_state_t strategy_load_balancer_nexthop_state_t

#define update_state(state)                             \
do {                                                    \
    state->avg_pi = (state->avg_pi * ALPHA) +           \
            (state->pi * 1 - ALPHA);                    \
    if (state->avg_pi < AVG_PI_THRESHOLD)               \
        state->avg_pi = AVG_PI_MIN;                     \
    state->weight = 1 / state->avg_pi;                  \
} while(0)

#define update_state_inc(state)                         \
do {                                                    \
    state->pi++;                                        \
    update_state(state);                                \
} while(0)

#define update_state_dec(state)                         \
do {                                                    \
    if (state->pi > 0)                                  \
        state->pi--;                                    \
    update_state(state);                                \
} while(0)

#if 0
#define reset_all(nexthops, nexthops_state)             \
do {                                                    \
    unsigned _lb_var(nexthop);                          \
    nexthops_foreach((state), _lb_var(nexthop), {       \
      (nexthop) = NEXTHOP_STATE_INIT;                   \
    });                                                 \
} while(0)
#else
#define reset_all(state)
#endif

static
void
strategy_load_balancer_initialize(strategy_entry_t * entry)
{
    // XXXreset_all(entry->state);
    // XXX TODO initialize nexthops
    // XXX maybe merge with nexthop data structure
}

static
void
strategy_load_balancer_finalize(strategy_entry_t * entry)
{
    /* Nothing to do */
}

static
void
strategy_load_balancer_add_nexthop(strategy_entry_t * entry, unsigned nexthop,
        strategy_nexthop_state_t * state)
{
  // Create and reset associated state
  // if this is really a new nexthop
  // XXX assume nexthop is inserted before
  reset_all(state);
}

static
void
strategy_load_balancer_remove_nexthop(strategy_entry_t * entry, unsigned
        nexthop, strategy_nexthop_state_t * state)
{
  reset_all(state);
}

static
nexthops_t *
strategy_load_balancer_lookup_nexthops(strategy_entry_t * entry,
        nexthops_t * nexthops, const msgbuf_t * msgbuf)
{
// TEMP
    nexthop_state_t * state = NULL;

  /* Compute the sum of weights of potential next hops */
  double sum = 0;
  unsigned i, nexthop;
  nexthops_enumerate(nexthops, i, nexthop, {
    (void)nexthop;
    sum += nexthops_state(nexthops, i).load_balancer.weight;
  });

  /* Perform weighted random selection */
  double distance = (double)rand() * sum / ((double)RAND_MAX + 1);

  nexthops_enumerate(nexthops, i, nexthop, {
    // XXX distance -= nexthop_state(nexthops, i).weight;
    if (distance < 0) {
      nexthops_select(nexthops, i);
      update_state_inc(state); // XXX 
      break;
    }
  });
  return nexthops;
}

static
void
strategy_load_balancer_on_timeout(strategy_entry_t * entry,
        const nexthops_t * nexthops)
{
  /*
   * As we have few nexthops in FIB entry, and even fewer selected ones in
   * nexthops, we can allow for linear search that will be very efficient
   * CPU-wise.
   */
// XXX TODO
#if 0
  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
    // XXX TODO leverage coexistence between nexthop and state
    if (correct_nexthop_id(nexthop))
      update_state_dec(&entry.state.nexthop_state);
  });
#endif
}

static
void
strategy_load_balancer_on_data(strategy_entry_t * entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
  strategy_load_balancer_on_timeout(entry, nexthops);
}

DECLARE_STRATEGY(load_balancer);

#undef nexthop_state_t
