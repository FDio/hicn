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
 * \file strategy.h
 * \brief hICN forwarding strategy
 */
#ifndef HICNLIGHT_STRATEGY_H
#define HICNLIGHT_STRATEGY_H

/*
 * Forwarding strategy
 *
 * The forwarding strategy decides to elect one or several next hops among those
 * available in the FIB entry, after an eventual application of the policy. This
 * means it should be aware of the different flags set in the nexthops_t data
 * structure by previous forwarding steps, that might have excluded certain
 * nexthops.
 *
 * A strategy is defined by its type and comes with :
 *  - options, initialized at setup and that might eventually be updated (this
 *  is allowed on a per-strategy basis.
 *  - a state (eventually) empty, that is used to inform its decisions, and
 *  might be updated for each interest sent (lookup_nexthops), data received
 *  (on_data) or timeout event (on_timeout).
 *
 * All this information (type, options, state) is made available through a
 * strategy_entry_t which is stored together with nexthops in the FIB entry.
 *
 * Per-nexthop strategy informaton is stored in the nexthops table itself. As it
 * would be difficult and suboptimal to provide a correct strategy-dependent
 * initialization in the FIB nad nexthops data structures, it is thus the
 * responsibility of the forwarding strategy to initialize its state and nexthop
 * related state when appropriate (eg. at initialization, or when a nexthop is
 * added).
 */

#include "nexthops.h"
#include "strategy_vft.h"

typedef struct strategy_entry_s {
  const void *forwarder;
  strategy_type_t type;
  strategy_options_t options;
  strategy_state_t state;
} strategy_entry_t;

int strategy_initialize(strategy_entry_t *entry, const void *forwarder);

nexthops_t *strategy_lookup_nexthops(strategy_entry_t *entry,
                                     nexthops_t *nexthops,
                                     const msgbuf_t *msgbuf);

int strategy_add_nexthop(strategy_entry_t *entry, nexthops_t *nexthops,
                         off_t offset);

int strategy_remove_nexthop(strategy_entry_t *entry, nexthops_t *nexthops,
                            off_t offset);

int strategy_on_data(strategy_entry_t *entry, nexthops_t *nexthops,
                     const nexthops_t *data_nexthops, const msgbuf_t *msgbuf,
                     Ticks pitEntryCreation, Ticks objReception);

int strategy_on_timeout(strategy_entry_t *entry, nexthops_t *nexthops,
                        const nexthops_t *timeout_nexthops);

#endif /* HICNLIGHT_STRATEGY_H */
