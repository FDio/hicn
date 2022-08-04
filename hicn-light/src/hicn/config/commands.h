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
 * @file commands.h
 * @brief hicn-light configuration, such as in-band commands or CLI
 *
 * Manages all user configuration of the system, such as from the CLI or web
 * interface It remembers the user commands and will be able to write out a
 * config file.
 *
 */

#ifndef HICNLIGHT_COMMANDS_H
#define HICNLIGHT_COMMANDS_H

#include "../core/msgbuf.h"
#include "../core/strategy.h"
#include <hicn/ctrl/api.h>
#include <hicn/ctrl/hicn-light.h>

uint8_t *command_process(forwarder_t *forwarder, uint8_t *packet,
                         unsigned ingress_id, size_t *reply_size);

ssize_t command_process_msgbuf(forwarder_t *forwarder, msgbuf_t *msgbuf);

uint8_t *configuration_on_listener_add(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_listener_remove(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size);

uint8_t *configuration_on_listener_list(forwarder_t *forwarder, uint8_t *packet,
                                        unsigned ingress_id,
                                        size_t *reply_size);

uint8_t *configuration_on_connection_add(forwarder_t *forwarder,
                                         uint8_t *packet, unsigned ingress_id,
                                         size_t *reply_size);

uint8_t *configuration_on_connection_remove(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size);

uint8_t *configuration_on_connection_list(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size);

uint8_t *configuration_on_connection_set_admin_state(forwarder_t *forwarder,
                                                     uint8_t *packet,
                                                     unsigned ingress_id,
                                                     size_t *reply_size);

uint8_t *configuration_on_connection_update(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size);

uint8_t *configuration_on_connection_set_priority(forwarder_t *forwarder,
                                                  uint8_t *packet,
                                                  unsigned ingress_id,
                                                  size_t *reply_size);

uint8_t *configuration_on_connection_set_tags(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size);

uint8_t *configuration_on_route_add(forwarder_t *forwarder, uint8_t *packet,
                                    unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_route_remove(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_route_list(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_cache_set_store(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size);

uint8_t *configuration_on_cache_set_serve(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size);

uint8_t *configuration_on_cache_clear(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_strategy_set(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_strategy_add_local_prefix(forwarder_t *forwarder,
                                                    uint8_t *packet,
                                                    unsigned ingress_id,
                                                    size_t *reply_size);

uint8_t *configuration_on_wldr_set(forwarder_t *forwarder, uint8_t *packet,
                                   unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_punting_add(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size);

#ifdef WITH_MAPME
uint8_t *configuration_on_mapme_enable(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_mapme_set_discovery(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size);

uint8_t *configuration_on_mapme_set_timescale(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size);

uint8_t *configuration_on_mapme_set_retx(forwarder_t *forwarder,
                                         uint8_t *packet, unsigned ingress_id,
                                         size_t *reply_size);

uint8_t *configuration_on_mapme_send_update(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size);
#endif /* WITH_MAPME */

uint8_t *configuration_on_policy_add(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_policy_remove(forwarder_t *forwarder, uint8_t *packet,
                                        unsigned ingress_id,
                                        size_t *reply_size);

uint8_t *configuration_on_policy_list(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size);

uint8_t *configuration_on_stats_list(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size);

void commands_notify_connection(const forwarder_t *forwarder,
                                connection_event_t event,
                                const connection_t *connection);

void commands_notify_route(const forwarder_t *forwarder,
                           const fib_entry_t *entry);

void commands_notify_active_interface_update(const forwarder_t *forwarder,
                                             hicn_ip_prefix_t *prefix,
                                             netdevice_flags_t flags);

#endif  // HICNLIGHT_COMMANDS_H
