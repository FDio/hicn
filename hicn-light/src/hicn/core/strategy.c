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
 * \file strategy.c
 * \brief Implementation of hICN forwarding strategy
 */

#include "nexthops.h"
#include "strategy.h"
#include "strategy_vft.h"

int strategy_initialize(strategy_entry_t *entry, const void *forwarder) {
  return strategy_vft[entry->type]->initialize(entry, forwarder);
}

nexthops_t *strategy_lookup_nexthops(strategy_entry_t *entry,
                                     nexthops_t *nexthops,
                                     const msgbuf_t *msgbuf) {
  return strategy_vft[entry->type]->lookup_nexthops(entry, nexthops, msgbuf);
}

int strategy_add_nexthop(strategy_entry_t *entry, nexthops_t *nexthops,
                         off_t offset) {
  return strategy_vft[entry->type]->add_nexthop(entry, nexthops, offset);
}

int strategy_remove_nexthop(strategy_entry_t *entry, nexthops_t *nexthops,
                            off_t offset) {
  return strategy_vft[entry->type]->remove_nexthop(entry, nexthops, offset);
}

int strategy_on_data(strategy_entry_t *entry, nexthops_t *nexthops,
                     const nexthops_t *data_nexthops, const msgbuf_t *msgbuf,
                     Ticks pitEntryCreation, Ticks objReception) {
  return strategy_vft[entry->type]->on_data(
      entry, nexthops, data_nexthops, msgbuf, pitEntryCreation, objReception);
}

int strategy_on_timeout(strategy_entry_t *entry, nexthops_t *nexthops,
                        const nexthops_t *timeout_nexthops) {
  return strategy_vft[entry->type]->on_timeout(entry, nexthops,
                                               timeout_nexthops);
}
