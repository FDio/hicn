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
 * Forward on a single path. Every time the strategy is reset with a command the
 * forwarder starts to probe the available paths matching the probes on the
 * original flow. if after the probing phase a better path exists (lower
 * latency, less losses) the forwarder switch path, otherwise does nothing
 */

#ifndef HICNLIGHT_STRATEGY_BESTPATH_H
#define HICNLIGHT_STRATEGY_BESTPATH_H

#include "probe_generator.h"
#include "local_prefixes.h"

typedef enum {
  PROBING_OFF,
  PROBING_ON,
  SENT_MAX_PROBES,
  PROBING_ENDING,  // waiting for probes to come back
  UNKWNOWN,
} probing_state_t;

typedef struct {
  // number or probes sent during a probing phase
  unsigned int sent_probes;
  // number or probes received during a probing phase
  unsigned int recv_probes;
  // sum of all rtt collected
  Ticks rtt_sum;
} strategy_bestpath_nexthop_state_t;

typedef struct {
  unsigned best_nexthop;
  Ticks probing_time;
  probing_state_t probing_state;
  probe_generator_t *pg;
} strategy_bestpath_state_t;

typedef struct {
  local_prefixes_t *local_prefixes;
} strategy_bestpath_options_t;

#endif /* HICNLIGHT_STRATEGY_BESTPATH_H */
