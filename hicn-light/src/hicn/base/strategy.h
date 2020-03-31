/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file strategy.h
 * \brief hICN forwarding strategy
 */
#ifndef HICN_STRATEGY_H
#define HICN_STRATEGY_H

#include <hicn/core/name.h>
#include <hicn/base/msgbuf.h>

#include <hicn/strategies/load_balancer.h>
#include <hicn/strategies/low_latency.h>
#include <hicn/strategies/random.h>

typedef enum {
  STRATEGY_TYPE_UNDEFINED,
  STRATEGY_TYPE_LOADBALANCER,
  STRATEGY_TYPE_LOW_LATENCY,
  STRATEGY_TYPE_RANDOM,
  STRATEGY_TYPE_N
} strategy_type_t;

#define STRATEGY_TYPE_VALID(type) \
    ((type != STRATEGY_TYPE_UNDEFINED) && (type != STRATEGY_TYPE_N))

typedef union {
    strategy_load_balancer_options_t load_balancer;
    strategy_low_latency_options_t low_latency;
    strategy_random_options_t random;
} strategy_options_t;

typedef union {
    strategy_load_balancer_nexthop_state_t load_balancer;
    strategy_low_latency_nexthop_state_t low_latency;
    strategy_random_nexthop_state_t random;
} strategy_nexthop_state_t;

#define STRATEGY_NEXTHOP_STATE_EMPTY {{ 0 }}

typedef union {
    strategy_load_balancer_state_t load_balancer;
    strategy_low_latency_state_t low_latency;
    strategy_random_state_t random;
} strategy_state_t;
// XXX This has to be merged with nexthops
// XXX How to avoid errors due to pool id reuse (eg on_data) ?

typedef struct {
    strategy_type_t type;
    strategy_options_t options;
    strategy_state_t state;
} strategy_entry_t;


#endif /* HICN_STRATEGY_H */
