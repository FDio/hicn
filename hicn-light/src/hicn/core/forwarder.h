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

/*
 * The methods in this header are for the non-threaded forwarder.  They should
 * only be called within the forwarders thread of execution.
 */

#ifndef HICNLIGHT_FORWARDER_H
#define HICN_LIGHT_FORWARDER_H

//#ifndef _WIN32
//#include <sys/time.h>
//#endif
//

#include <stdlib.h>
#include <sys/socket.h> // struct mmsghdr

#include "connection.h"
#include "connection_table.h"
#include "content_store.h"
#include "listener_table.h"
#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "../config/configuration.h"

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
forwarder_t * forwarder_create();

/**
 * @brief Destroys the forwarder, stopping all traffic and freeing all memory
 */
void forwarder_free(forwarder_t * forwarder);

/**
 * @brief Setup all listeners (tcp, udp, local, ether, ip multicast) on all
 * interfaces
 * @discussion
 *   Sets up all listeners on all running interfaces.  This provides a quick and
 * easy startup, rather than providing a configuration file or programmatic
 * commands.
 *
 * @param port is used by TCP and UDP listeners, in host byte order
 * @param localPath is the AF_UNIX path to use, if NULL no AF_UNIX listener is
 * setup
 */
void forwarder_setup_all_listeners(forwarder_t * forwarder, uint16_t port, const
        char *local_path);
/**
 * @brief Setup one tcp and one udp listener on address 127.0.0.1 and the
 * given port
 */
void forwarder_setup_local_listeners(forwarder_t * forwarder, uint16_t port);

/**
 * Configure hicn-light via a configuration file
 *
 * The configuration file is a set of lines, just like used in hicnLightControl.
 * You need to have "add listener" lines in the file to receive connections.  No
 * default listeners are configured.
 *
 * @param[in] forwarder An alloated forwarder_t
 * @param[in] filename The path to the configuration file
 */
void forwarder_read_config(forwarder_t * forwarder, const char * filename);

/**
 * @brief The configuration object
 * @discussion
 *   The configuration contains all user-issued commands.  It does not include
 * dynamic state.
 */
configuration_t * forwarder_get_configuration(forwarder_t * forwarder);

/**
 * Returns the set of currently active listeners
 *
 * @param[in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The set of active listeners
 * @retval null An error
 */
listener_table_t * forwarder_get_listener_table(forwarder_t *forwarder);

/**
 * Returns the forwrder's connection table
 *
 * @param[in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The connection tabler
 * @retval null An error
 *
 */
connection_table_t * forwarder_get_connection_table(const forwarder_t *forwarder);

void forwarder_cs_set_store(forwarder_t * forwarder, bool val);

bool forwarder_cs_get_store(forwarder_t * forwarder);

void forwarder_cs_set_serve(forwarder_t * forwarder, bool val);

bool forwarder_cs_get_serve(forwarder_t * forwarder);

/**
 * Sets the maximum number of content objects in the content store
 *
 * Implementation dependent - may wipe the cache.
 */
void forwarder_cs_set_size(forwarder_t * forwarder, size_t size);

void forwarder_cs_clear(forwarder_t *forwarder);

ssize_t forwarder_receive_command(forwarder_t * forwarder, msgbuf_t * msgbuf);

/**
 * @brief Adds or updates a route on all the message processors
 */
bool forwarder_add_or_update_route(forwarder_t * forwarder,
        ip_prefix_t * prefix, unsigned ingress_id);

/**
 * @brief Removes a route from all the message processors
 */
bool forwarder_remove_route(forwarder_t * forwarder, ip_prefix_t * prefix,
        unsigned ingress_id);

#ifdef WITH_POLICY
/**
 * @brief Adds or updates a policy on the message processor
 */
bool forwarder_add_or_update_policy(forwarder_t * forwarder,
        ip_prefix_t * prefix, policy_t * policy);

/**
 * @brief Removes a policy from the message processor
 */
bool forwarder_remove_policy(forwarder_t * forwarder, ip_prefix_t * prefix);

#endif /* WITH_POLICY */

/**
 * Removes a connection id from all routes
 */
void forwarder_remove_connection_id_from_routes(forwarder_t * forwarder,
        unsigned connection_id);

void forwarder_set_strategy(forwarder_t * forwarder, Name * name_prefix,
        strategy_type_t strategy_type, strategy_options_t * strategy_options);

cs_t * forwarder_get_cs(const forwarder_t * forwarder);


/**
 * @brief Returns the forwarder's FIB.
 * @param[in] forwarder - Pointer to the forwarder.
 * @returns Pointer to the hICN FIB.
 */
fib_t * forwarder_get_fib(forwarder_t * forwarder);

/**
 * @brief Return the forwarder packet pool.
 * @param[in] forwarder The forwarder from which to retrieve the packet
 * pool.
 * @return msgbuf_pool_t * The forwarder packet pool.
 */
msgbuf_pool_t * forwarder_get_msgbuf_pool(const forwarder_t * forwarder);

#ifdef WITH_MAPME

/**
 * @brief Callback fired upon addition of a new connection through the
 *   control protocol.
 * @param[in] forwarder - Pointer to the forwarder.
 * @param[in] conn - Pointer to the newly added connection.
 * @param[in] event - Connection event
 */
void forwarder_on_connection_event(const forwarder_t * forwarder,
        const connection_t * connection, connection_event_t event);

/**
 * @brief Callback fired by an hICN listener upon reception of a MAP-Me
 *      message.
 * @param[in] forwarder - Pointer to the forwarder.
 * @param[in] msgBuffer - MAP-Me buffer
 * @param[in] conn_id - Ingress connection id
 */
void forwarder_process_mapme(const forwarder_t * forwarder, const uint8_t * packet,
        unsigned conn_id);

struct mapme_s * forwarder_get_mapme(const forwarder_t * forwarder);

#endif /* WITH_MAPME */

#ifdef WITH_PREFIX_STATS
const prefix_stats_mgr_t * forwarder_get_prefix_stats_mgr(const forwarder_t * forwarder);
#endif /* WITH_PREFIX_STATS */

void forwarder_flush_connections(forwarder_t * forwarder);

/**
 * @brief Handles a newly received packet from a listener.
 *
 * NOTE: the received msgbuf is incomplete and only holds the packet content and
 * size/
 */
ssize_t forwarder_receive(forwarder_t * forwarder, listener_t * listener,
        off_t msgbuf_id, address_pair_t * pair, Ticks now);

#endif // HICN_LIGHT_FORWARDER_H
