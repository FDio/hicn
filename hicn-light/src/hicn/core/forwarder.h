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

#ifndef forwarder_h
#define forwarder_h

//#ifndef _WIN32
//#include <sys/time.h>
//#endif

#include <stdlib.h>

#include <hicn/base/msgbuf.h>
#include <hicn/base/content_store.h>
#include <hicn/base/connection.h>
#include <hicn/base/connection_table.h>
#include <hicn/base/listener_table.h>

#include <hicn/config/configuration.h>

#ifdef WITH_MAPME
#include <hicn/core/fib.h>
#endif /* WITH_MAPME */

#include <hicn/core/fib_entry_list.h>

#define PORT_NUMBER 9695
#define PORT_NUMBER_AS_STRING "9695"

#include <hicn/utils/commands.h>

// ==============================================

typedef struct forwarder_s forwarder_t;

/**
 * @function forwarder_Create
 * @abstract Create the forwarder and use the provided logger for diagnostic
 * output
 * @discussion
 *   If the logger is null, hicn-light will create a STDOUT logger.
 *
 * @param logger may be NULL
 */
forwarder_t * forwarder_create();

/**
 * @function forwarder_Destroy
 * @abstract Destroys the forwarder, stopping all traffic and freeing all memory
 */
void forwarder_free(forwarder_t * forwarder);

/**
 * @function forwarder_SetupAllListeners
 * @abstract Setup all listeners (tcp, udp, local, ether, ip multicast) on all
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
 * @function forwarder_SetupAllListeners
 * @abstract Setup one tcp and one udp listener on address 127.0.0.1 and the
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
 * @param [in] forwarder An alloated forwarder_t
 * @param [in] filename The path to the configuration file
 */
void forwarder_read_config(forwarder_t * forwarder, const char * filename);

/**
 * @function forwarder_GetConfiguration
 * @abstract The configuration object
 * @discussion
 *   The configuration contains all user-issued commands.  It does not include
 * dynamic state.
 */
Configuration * forwarder_get_configuration(forwarder_t * forwarder);

/**
 * Returns the set of currently active listeners
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The set of active listeners
 * @retval null An error
 */
listener_table_t * forwarder_get_listener_table(forwarder_t *forwarder);

/**
 * Returns the forwrder's connection table
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The connection tabler
 * @retval null An error
 *
 */
connection_table_t * forwarder_get_connection_table(const forwarder_t *forwarder);

void forwarder_content_store_set_store(forwarder_t * forwarder, bool val);

bool forwarder_content_store_get_store(forwarder_t * forwarder);

void forwarder_content_store_set_serve(forwarder_t * forwarder, bool val);

bool forwarder_content_store_get_serve(forwarder_t * forwarder);

/**
 * Sets the maximum number of content objects in the content store
 *
 * Implementation dependent - may wipe the cache.
 */
void forwarder_content_store_set_size(forwarder_t * forwarder, size_t size);

void forwarder_content_store_clear(forwarder_t *forwarder);

void forwarder_receive_command(forwarder_t * forwarder, command_type_t command_type,
        uint8_t * packet, unsigned connection_id);

void forwarder_receive(forwarder_t * forwarder, msgbuf_t * message, unsigned new_batch);

/**
 * @function forwarder_add_or_update_route
 * @abstract Adds or updates a route on all the message processors
 */
bool forwarder_add_or_update_route(forwarder_t * forwarder,
        ip_prefix_t * prefix, unsigned ingress_id);

/**
 * @function forwarder_remove_route
 * @abstract Removes a route from all the message processors
 */
bool forwarder_remove_route(forwarder_t * forwarder, ip_prefix_t * prefix,
        unsigned ingress_id);

#ifdef WITH_POLICY
/**
 * @function forwarder_add_or_update_policy
 * @abstract Adds or updates a policy on the message processor
 */
bool forwarder_add_or_update_policy(forwarder_t * forwarder,
        ip_prefix_t * prefix, policy_t * policy);


/**
 * @function forwarder_RemovePolicy
 * @abstract Removes a policy from the message processor
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

fib_entry_list_t * forwarder_get_fib_entries(forwarder_t * forwarder);

content_store_t * forwarder_get_content_store(const forwarder_t * forwarder);

#ifdef WITH_MAPME

/**
 * @function forwarder_getFib
 * @abstract Returns the hICN forwarder's FIB.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @returns Pointer to the hICN FIB.
 */
fib_t * forwarder_get_fib(forwarder_t * forwarder);

/**
 * @function forwarder_onConnectionEvent
 * @abstract Callback fired upon addition of a new connection through the
 *   control protocol.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] conn - Pointer to the newly added connection.
 * @param [in] event - Connection event
 */
void forwarder_on_connection_event(forwarder_t * forwarder,
        const connection_t * connection, connection_event_t event);

/**
 * @function forwarder_ProcessMapMe
 * @abstract Callback fired by an hICN listener upon reception of a MAP-Me
 *      message.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] msgBuffer - MAP-Me buffer
 * @param [in] conn_id - Ingress connection id
 */
void forwarder_process_mapme(const forwarder_t * forwarder, const uint8_t * packet,
        unsigned conn_id);

struct mapme_s * forwarder_get_mapme(const forwarder_t * forwarder);

#endif /* WITH_MAPME */

#ifdef WITH_PREFIX_STATS
const prefix_stats_mgr_t * forwarder_get_prefix_stats_mgr(const forwarder_t * forwarder);
#endif /* WITH_PREFIX_STATS */

bool forwarder_handle_hooks(const forwarder_t * forwarder, const uint8_t * packet,
        listener_t * listener, int fd, unsigned conn_id, address_pair_t * pair);

#endif  // forwarder_h
