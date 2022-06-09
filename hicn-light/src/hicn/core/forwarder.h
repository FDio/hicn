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

/*
 * The methods in this header are for the non-threaded forwarder.  They should
 * only be called within the forwarders thread of execution.
 */

#ifndef HICNLIGHT_FORWARDER_H
#define HICNLIGHT_FORWARDER_H

//#ifndef _WIN32
//#include <sys/time.h>
//#endif
//

#include <stdlib.h>
#include <sys/socket.h>  // struct mmsghdr

#include "connection.h"
#include "connection_table.h"
#include "packet_cache.h"
#include "listener_table.h"
#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "../config/configuration.h"
#include "subscription.h"

#ifdef WITH_MAPME
#include "fib.h"
#endif /* WITH_MAPME */

#define PORT_NUMBER 9695
#define PORT_NUMBER_AS_STRING "9695"

//#include <hicn/utils/commands.h>

// ==============================================

typedef struct forwarder_s forwarder_t;

/**
 * @brief Create the forwarder and use the provided logger for diagnostic
 * output
 * @discussion
 *   If the logger is null, hicn-light will create a STDOUT logger.
 *
 * @param logger may be NULL
 */
forwarder_t *forwarder_create(configuration_t *configuration);

/**
 * @brief Destroys the forwarder, stopping all traffic and freeing all memory
 */
void forwarder_free(forwarder_t *forwarder);

/**
 * @brief Setup one tcp and one udp listener on address 127.0.0.1 and the
 * given port
 */
void forwarder_setup_local_listeners(forwarder_t *forwarder, uint16_t port);

configuration_t *forwarder_get_configuration(forwarder_t *forwarder);

subscription_table_t *forwarder_get_subscriptions(forwarder_t *forwarder);

/**
 * Returns the set of currently active listeners
 *
 * @param[in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The set of active listeners
 * @retval null An error
 */
listener_table_t *forwarder_get_listener_table(forwarder_t *forwarder);

/**
 * Returns the forwrder's connection table
 *
 * @param[in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The connection tabler
 * @retval null An error
 *
 */
connection_table_t *forwarder_get_connection_table(
    const forwarder_t *forwarder);

pkt_cache_t *forwarder_get_pkt_cache(const forwarder_t *forwarder);

void forwarder_cs_set_store(forwarder_t *forwarder, bool val);

bool forwarder_cs_get_store(forwarder_t *forwarder);

void forwarder_cs_set_serve(forwarder_t *forwarder, bool val);

bool forwarder_cs_get_serve(forwarder_t *forwarder);

/**
 * Sets the maximum number of content objects in the content store
 *
 * Implementation dependent - may wipe the cache.
 */
void forwarder_cs_set_size(forwarder_t *forwarder, size_t size);

size_t forwarder_cs_get_size(forwarder_t *forwarder);
size_t forwarder_cs_get_num_stale_entries(forwarder_t *forwarder);
void forwarder_cs_clear(forwarder_t *forwarder);

/**
 * @brief Adds or updates a route on all the message processors
 */
bool forwarder_add_or_update_route(forwarder_t *forwarder, ip_prefix_t *prefix,
                                   unsigned ingress_id);

/**
 * @brief Removes a route from all the message processors
 */
bool forwarder_remove_route(forwarder_t *forwarder, ip_prefix_t *prefix,
                            unsigned ingress_id);

#ifdef WITH_POLICY
/**
 * @brief Adds or updates a policy on the message processor
 */
bool forwarder_add_or_update_policy(forwarder_t *forwarder, ip_prefix_t *prefix,
                                    hicn_policy_t *policy);

/**
 * @brief Removes a policy from the message processor
 */
bool forwarder_remove_policy(forwarder_t *forwarder, ip_prefix_t *prefix);

#endif /* WITH_POLICY */

/**
 * Removes a connection id from all routes
 */
void forwarder_remove_connection_id_from_routes(forwarder_t *forwarder,
                                                unsigned connection_id);

void forwarder_add_strategy_options(forwarder_t *forwarder, Name *name_prefix,
                                    strategy_type_t strategy_type,
                                    strategy_options_t *strategy_options);

void forwarder_set_strategy(forwarder_t *forwarder, Name *name_prefix,
                            strategy_type_t strategy_type,
                            strategy_options_t *strategy_options);

cs_t *forwarder_get_cs(const forwarder_t *forwarder);

off_t *forwarder_get_acquired_msgbuf_ids(const forwarder_t *forwarder);

/**
 * @note Acquire msgbuf ids vector ONLY for read-only operations.
 */
off_t *forwarder_get_acquired_msgbuf_ids(const forwarder_t *forwarder);

void forwarder_acquired_msgbuf_ids_reset(const forwarder_t *forwarder);

void forwarder_acquired_msgbuf_ids_push(const forwarder_t *forwarder,
                                        off_t msgbuf_id);

/**
 * @brief Returns the forwarder's FIB.
 * @param[in] forwarder - Pointer to the forwarder.
 * @returns Pointer to the hICN FIB.
 */
fib_t *forwarder_get_fib(forwarder_t *forwarder);

/**
 * @brief Return the forwarder packet pool.
 * @param[in] forwarder The forwarder from which to retrieve the packet
 * pool.
 * @return msgbuf_pool_t * The forwarder packet pool.
 */
msgbuf_pool_t *forwarder_get_msgbuf_pool(const forwarder_t *forwarder);

#ifdef WITH_MAPME

/**
 * @brief Callback fired upon addition of a new connection through the
 *   control protocol.
 * @param[in] forwarder - Pointer to the forwarder.
 * @param[in] conn - Pointer to the newly added connection.
 * @param[in] event - Connection event
 */
void forwarder_on_connection_event(const forwarder_t *forwarder,
                                   const connection_t *connection,
                                   connection_event_t event);

/**
 * @brief Callback fired by an hICN listener upon reception of a MAP-Me
 *      message.
 * @param[in] forwarder - Pointer to the forwarder.
 * @param[in] msgBuffer - MAP-Me buffer
 * @param[in] conn_id - Ingress connection id
 */
void forwarder_process_mapme(const forwarder_t *forwarder,
                             const uint8_t *packet, unsigned conn_id);

struct mapme_s *forwarder_get_mapme(const forwarder_t *forwarder);

#endif /* WITH_MAPME */

#ifdef WITH_POLICY_STATS
const policy_stats_mgr_t *forwarder_get_policy_stats_mgr(
    const forwarder_t *forwarder);
#endif /* WITH_POLICY_STATS */

void forwarder_flush_connections(forwarder_t *forwarder);

/**
 * @brief Handles a newly received packet from a listener.
 *
 * NOTE: the received msgbuf is incomplete and only holds the packet content and
 * size/
 */
ssize_t forwarder_receive(forwarder_t *forwarder, listener_t *listener,
                          off_t msgbuf_id, address_pair_t *pair, Ticks now);

/**
 * @brief Log forwarder statistics, e.g. info about packets processed, packets
 * dropped, packets forwarded, errors while forwarding, interest and data
 * processing results.
 *
 * @param forwarder Pointer to the forwarder data structure to use
 */
void forwarder_log(forwarder_t *forwarder);

forwarder_stats_t forwarder_get_stats(forwarder_t *forwarder);

#endif  // HICNLIGHT_FORWARDER_H
