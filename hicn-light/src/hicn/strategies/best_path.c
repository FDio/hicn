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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <hicn/hicn-light/config.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/nexthops.h>
#include <hicn/core/strategy.h>
#include <hicn/core/strategy_vft.h>

#include "best_path.h"

#define MAX_NEXTHOP_COST 100
#define MAX_RTT_ALLOWED 300.0   // ms
#define MAX_LOSSES_ALLOWED 0.4  // 40%

#define MAX_PROBING_DURATION 5000  // ticks (= ms)
#define PROBES_WAINTING_TIME 500   // ticks (= ms)
#define MAX_PROBES 50

/* Shorthand */
#define nexthop_state_t strategy_bestpath_nexthop_state_t
#define strategy_state_t strategy_bestpath_state_t
#define nexthop_state(nexthops, i) (&nexthops->state[i].bestpath)

// nexthop state functions

static const nexthop_state_t NEXTHOP_STATE_INIT = {
    .sent_probes = 0,
    .recv_probes = 0,
    .rtt_sum = 0,
};

static inline unsigned int get_sent_probes(nexthop_state_t *state) {
  return state->sent_probes;
}

static inline unsigned int inc_sent_probes(nexthop_state_t *state) {
  state->sent_probes++;
  return state->sent_probes;
}

static inline void add_rtt_sample(nexthop_state_t *state, Ticks rtt) {
  state->recv_probes++;
  state->rtt_sum += rtt;
}

static inline unsigned int get_nexthop_cost(nexthop_state_t *state) {
  if (state->recv_probes == 0)
    return 100;  // we have no info for this nexthop, return max cost

  assert(state->recv_probes <= state->sent_probes);

  double rtt = (double)state->rtt_sum / (double)state->recv_probes;
  double delay_cost = rtt / MAX_RTT_ALLOWED;
  if (delay_cost > 1) delay_cost = 1;

  double loss_rate = (double)(state->sent_probes - state->recv_probes) /
                     (double)state->sent_probes;
  double loss_cost = loss_rate / MAX_LOSSES_ALLOWED;
  if (loss_cost > 1) loss_cost = 1;

  double total_cost = delay_cost * 0.5 + loss_cost * 0.5;
  return round(total_cost * 100);
}

// options functions
static void bestpath_update_remote_node(strategy_entry_t *entry,
                                        nexthops_t *nexthops) {
  strategy_state_t *state = &entry->state.bestpath;
  strategy_bestpath_options_t *options = &entry->options.bestpath;
  off_t offset = nexthops_find(nexthops, state->best_nexthop);

  /* Backup flags and cur_len: because our code is called from
   * strategy_on_data / check_stop_probing / stop_probing
   * which does not expect the nexthop flags to be modified.
   */
  uint_fast32_t flags = nexthops->flags;
  size_t cur_len = nexthops_get_curlen(nexthops);

  nexthops_select(nexthops, offset);
  update_remote_node_paths(nexthops, entry->forwarder, options->local_prefixes);

  /* Restore flags & curlen */
  nexthops->flags = flags;
  nexthops->cur_elts = cur_len;
}

// probing functions

static void start_probing(strategy_entry_t *entry) {
  strategy_state_t *state = &entry->state.bestpath;
  if (state->probing_state == PROBING_OFF) {
    state->probing_state = PROBING_ON;
    state->probing_time = ticks_now();
  }
}

static void stop_probing(strategy_entry_t *entry, nexthops_t *nexthops) {
  strategy_state_t *state = &entry->state.bestpath;
  nexthop_t best_nexthop;
  best_nexthop = state->best_nexthop;
  unsigned int min_cost = ~0;
  unsigned current_nexthop_cost = ~0;

  nexthops_enumerate(nexthops, i, nexthop, {
    unsigned int cost = get_nexthop_cost(nexthop_state(nexthops, i));
    if (cost < min_cost) {
      min_cost = cost;
      best_nexthop = nexthop;
    }
    if (nexthop == state->best_nexthop) current_nexthop_cost = cost;

    nexthops->state[i].bestpath = NEXTHOP_STATE_INIT;
  });

  if (best_nexthop != state->best_nexthop) {
    if (current_nexthop_cost > min_cost) {
      // update best face
      state->best_nexthop = best_nexthop;
    }
  }

  // always update remote node
  bestpath_update_remote_node(entry, nexthops);

  state->probing_state = PROBING_OFF;
  delete_all_probes(state->pg);
}

static void check_stop_probing(strategy_entry_t *entry, nexthops_t *nexthops) {
  strategy_state_t *state = &entry->state.bestpath;
  if (state->probing_state == PROBING_OFF) return;

  if (state->probing_state == PROBING_ON) {
    Ticks probing_duration = ticks_now() - state->probing_time;
    if (probing_duration >= MAX_PROBING_DURATION) {
      state->probing_state = PROBING_ENDING;
      state->probing_time = ticks_now();
    }
    return;
  }

  if (state->probing_state == SENT_MAX_PROBES) {
    state->probing_state = PROBING_ENDING;
    state->probing_time = ticks_now();
    return;
  }

  if (state->probing_state == PROBING_ENDING) {
    Ticks ending_duration = ticks_now() - state->probing_time;
    if (ending_duration >= PROBES_WAINTING_TIME) stop_probing(entry, nexthops);
  }
}

static void send_probes(strategy_entry_t *entry, nexthops_t *nexthops,
                        const msgbuf_t *msgbuf) {
  strategy_state_t *state = &entry->state.bestpath;

  bool sent_max_probes = false;
  nexthops_enumerate(nexthops, i, nexthop, {
    if (get_sent_probes(nexthop_state(nexthops, i)) < MAX_PROBES) {
      int res = generate_probe(state->pg, msgbuf, entry->forwarder, nexthop);
      if (res >= 0) inc_sent_probes(nexthop_state(nexthops, i));
    } else {
      sent_max_probes = true;
    }
  });

  if (sent_max_probes) {
    state->probing_state = SENT_MAX_PROBES;
    check_stop_probing(entry, nexthops);
  }
}

static void init_strategy_state(strategy_state_t *state) {
  state->best_nexthop = ~0;
  state->probing_state = PROBING_OFF;
  state->pg = create_probe_generator();
}

// strategy functions
static int strategy_bestpath_initialize(strategy_entry_t *entry,
                                        const void *forwarder) {
  if (entry->forwarder == NULL) {
    srand((unsigned int)time(NULL));
    entry->forwarder = forwarder;
    init_strategy_state(&entry->state.bestpath);
  } else {
    strategy_state_t *state = &entry->state.bestpath;
    if (!state->pg) {
      // the previous strategy was a different one
      init_strategy_state(state);
    } else {
      // all set, start probing
      start_probing(entry);
    }
  }
  return 0;
}

static int strategy_bestpath_finalize(strategy_entry_t *entry) {
  strategy_state_t *state = &entry->state.bestpath;
  free_local_prefixes(entry->options.bestpath.local_prefixes);
  destroy_probe_generator(state->pg);
  return 0;
}

static int strategy_bestpath_add_nexthop(strategy_entry_t *entry,
                                         nexthops_t *nexthops, off_t offset) {
  // reset the strategy state
  nexthops->state[offset].bestpath = NEXTHOP_STATE_INIT;
  return 0;
}

static int strategy_bestpath_remove_nexthop(strategy_entry_t *entry,
                                            nexthops_t *nexthops,
                                            off_t offset) {
  /* Nothing to do */
  return 0;
}

static nexthops_t *strategy_bestpath_lookup_nexthops(strategy_entry_t *entry,
                                                     nexthops_t *nexthops,
                                                     const msgbuf_t *msgbuf) {
  size_t nexthops_len = nexthops_get_curlen(nexthops);
  if (nexthops_len == 0) {
    // nexthops is empty, return
    return nexthops;
  }

  strategy_state_t *state = &entry->state.bestpath;
  off_t best_nexthop_offset = nexthops_find(nexthops, state->best_nexthop);

  // TODO explain the purpose of this test
  if (nexthops_len == 1) {
    nexthop_t nh = nexthops_get_one(nexthops);
    if (state->best_nexthop != nh) {
      state->best_nexthop = nh;
      bestpath_update_remote_node(entry, nexthops);
    }
    return nexthops;
  }

  if (state->best_nexthop == ~0 || best_nexthop_offset == INVALID_NEXTHOP) {
    state->best_nexthop = nexthops_get_one(nexthops);
    best_nexthop_offset = nexthops_find(nexthops, state->best_nexthop);
    bestpath_update_remote_node(entry, nexthops);
    // we have probe only in case the number of face is > 1
    start_probing(entry);
    // bestpath_update_remote_node sets the nexthops. in case of probing we want
    // to send the packets on all faces, so we reset the nexthops here
    nexthops_reset(nexthops);
  }

  if (state->probing_state == PROBING_ON) {
    // send a probe for each interest received
    send_probes(entry, nexthops, msgbuf);

    uint32_t suffix = hicn_name_get_suffix(msgbuf_get_name(msgbuf));
    if (suffix >= MIN_PROBE_SUFFIX && suffix <= MAX_PROBE_SUFFIX) {
      // this packet is a probe from the transport, so register it
      Ticks time = get_probe_send_time(state->pg, suffix);
      if (time == 0) {
        // a probe with the same seq number is not pending, send the packet
        // the stats for this probe will be collected by the transport
        register_probe(state->pg, suffix);
      } else {
        // this probe is already pending. avoid duplicates and drop it
        nexthops->flags = ~0;
        nexthops->cur_elts = 0;
      }
    }
  } else {
    // we are not probing anymore. if in probing ending state (wait for probes
    // to come back) keep replicating traffic, otherwise and on best path
    if (state->probing_state != PROBING_ENDING)
      nexthops_select(nexthops, best_nexthop_offset);
  }

  // in case we are still probing send all interest on all paths
  // so do not select any next hop.
  // XXX in this transition phase should we replicate also at the
  // server side?
  return nexthops;
}

static int strategy_bestpath_on_data(strategy_entry_t *entry,
                                     nexthops_t *nexthops,
                                     const nexthops_t *data_nexthops,
                                     const msgbuf_t *msgbuf,
                                     Ticks pitEntryCreation,
                                     Ticks objReception) {
  strategy_state_t *state = &entry->state.bestpath;
  if (state->probing_state == PROBING_OFF) return 0;

  uint32_t seq = hicn_name_get_suffix(msgbuf_get_name(msgbuf));
  if (seq >= MIN_PROBE_SUFFIX && seq <= MAX_PROBE_SUFFIX) {
    if (pitEntryCreation != 0) {
      // this is not a probe sent by the forwader. do not use it in the probing
      // statisitcs but remove it from the map if it exists
      delete_probe(state->pg, seq);
      return 0;
    }

    Ticks send_time = get_probe_send_time(state->pg, seq);
    if (send_time != 0) {
      Ticks rtt = ticks_now() - send_time;
      delete_probe(state->pg, seq);
      nexthops_enumerate(data_nexthops, i, nexthop, {
        off_t pos = nexthops_find(nexthops, nexthop);
        add_rtt_sample(nexthop_state(nexthops, pos), rtt);
      });
    }
  }

  check_stop_probing(entry, nexthops);

  return 0;
}

static int strategy_bestpath_on_timeout(strategy_entry_t *entry,
                                        nexthops_t *nexthops,
                                        const nexthops_t *timeout_nexthops) {
  /* Nothing to do */
  return 0;
}

#undef nexthop_state_t
#undef strategy_state_t

DECLARE_STRATEGY(bestpath);

#undef nexthop_state_t
#undef strategy_state_t
