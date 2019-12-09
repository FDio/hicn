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

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Unsigned.h>

#include <hicn/strategies/loadBalancer.h>
#include <hicn/strategies/nexthopState.h>

#define AVG_PI_THRESHOLD 1e-3
#define AVG_PI_MIN 0.1

#define ALPHA 0.9

#define NEXTHOP_STATE_INIT {    \
    .pi = 0,                    \
    .avg_pi = 0.0,              \
    .weight = 1,                \
}

/* Shorthand */
#define nexthop_state_t strategy_random_nexthop_state_t

#define update_state(state, update)                     \
do {                                                    \
    state->svg_pi = (state->avg_pi * ALPHA) +           \
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

#define reset_all(state)                                \
do {                                                    \
    unsigned nexthop;                                   \
    nexthops_foreach(state, nexthop, {                  \
      state = NEXTHOP_STATE_INIT;                       \
    });                                                 \
} while(0)

static
void
strategy_load_balancer_initialize(strategy_entry_t * entry)
{
    reset_all(entry->state);
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
strategy_load_balancer_add_nexthop(strategy_entry_t * entry, unsigned nexthop)
{
  // Create and reset associated state
  // if this is really a new nexthop
  // XXX assume nexthop is inserted before
  if (nexthops_has(nexthops, nexthop))
    return;
  reset_all(state);
}

static
void
strategy_load_balancer_remove_nexthop(strategy_entry_t * entry, unsigned nexthop)
{
  if (!nexthops_has(nexthops, nexthop))
    return;
  reset_all(state);
}

static
nexthops_t *
strategy_load_balancer_lookup_nexthops(strategy_entry_t * entry,
        nexthops_t * nexthops, const msgbuf_t * msgbuf)
{
  /* Compute the sum of weights of potential next hops */
  double sum = 0;
  unsigned nexthop;
  nexthops_enumerate(nexthops, i, nexthop, {
    sum += nexthop_state(nexthops, i).weight;
  });

  /* Perform weighted random selection */
  double distance = (double)rand() * sum / ((double)RAND_MAX + 1);

  nexthops_enumerate(nexthops, i, nexthop, {
    distance -= nexthop_state(nexthops, i).weight;
    if (distance < 0) {
      nexthops_select(nexthops, i);
      update_state_inc(0); // XXX 
      break;
    }
  }
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
  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
    // XXX TODO leverage coexistence between nexthop and state
    if (correct_nexthop_id(nexthop))
      update_state_dec(&entry.state.nexthop_state);
  });
}

static
void
strategy_load_balancer_on_data(strategy_entry_t * entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
  strategy_load_balancer_on_timeout(strategy, nexthops);
}

DECLARE_STRATEGY(load_balancer);

#undef nexthop_state_t
