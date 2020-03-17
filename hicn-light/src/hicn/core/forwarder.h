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

#ifndef _WIN32
#include <sys/time.h>
#endif
#include <stdlib.h>

#include <hicn/core/connectionTable.h>
#include <hicn/core/dispatcher.h>
#include <hicn/messenger/messenger.h>

#include <hicn/core/message.h>

#include <hicn/config/configuration.h>

#ifdef WITH_MAPME
#include <hicn/processor/fib.h>
#endif /* WITH_MAPME */

#include <hicn/core/logger.h>
#include <hicn/core/ticks.h>
#include <hicn/io/listenerSet.h>

#include <hicn/processor/fibEntryList.h>

#include <parc/algol/parc_Clock.h>

//#include <hicn/socket/api.h>

#define PORT_NUMBER 9695
#define PORT_NUMBER_AS_STRING "9695"

#include <hicn/utils/commands.h>

// ==============================================

struct forwarder;
typedef struct forwarder Forwarder;

/**
 * @function forwarder_Create
 * @abstract Create the forwarder and use the provided logger for diagnostic
 * output
 * @discussion
 *   If the logger is null, hicn-light will create a STDOUT logger.
 *
 * @param logger may be NULL
 */
Forwarder *forwarder_Create(Logger *logger);

/**
 * @function forwarder_Destroy
 * @abstract Destroys the forwarder, stopping all traffic and freeing all memory
 */
void forwarder_Destroy(Forwarder **ptr);

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
void forwarder_SetupAllListeners(Forwarder *forwarder, uint16_t port,
                                 const char *localPath);
/**
 * @function forwarder_SetupAllListeners
 * @abstract Setup one tcp and one udp listener on address 127.0.0.1 and the
 * given port
 */
void forwarder_SetupLocalListeners(Forwarder *forwarder, uint16_t port);

/**
 * Configure hicn-light via a configuration file
 *
 * The configuration file is a set of lines, just like used in hicnLightControl.
 * You need to have "add listener" lines in the file to receive connections.  No
 * default listeners are configured.
 *
 * @param [in] forwarder An alloated Forwarder
 * @param [in] filename The path to the configuration file
 */
void forwarder_SetupFromConfigFile(Forwarder *forwarder, const char *filename);

/**
 * Returns the logger used by this forwarder
 *
 * If you will store the logger, you should acquire a reference to it.
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The logger used by hicn-light
 * @retval null An error
 */
Logger *forwarder_GetLogger(const Forwarder *forwarder);

/**
 * @function forwarder_SetLogLevel
 * @abstract Sets the minimum level to log
 */
void forwarder_SetLogLevel(Forwarder *forwarder, PARCLogLevel level);

/**
 * @function forwarder_GetNextConnectionId
 * @abstract Get the next identifier for a new connection
 */
unsigned forwarder_GetNextConnectionId(Forwarder *forwarder);

Messenger *forwarder_GetMessenger(Forwarder *forwarder);

Dispatcher *forwarder_GetDispatcher(Forwarder *forwarder);

/**
 * Returns the set of currently active listeners
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The set of active listeners
 * @retval null An error
 */
ListenerSet *forwarder_GetListenerSet(Forwarder *forwarder);

/**
 * Returns the forwrder's connection table
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null The connection tabler
 * @retval null An error
 *
 */
#ifdef WITH_POLICY
ConnectionTable *forwarder_GetConnectionTable(const Forwarder *forwarder);
#else
ConnectionTable *forwarder_GetConnectionTable(Forwarder *forwarder);
#endif /* WITH_POLICY */

/**
 * Returns a Tick-based clock
 *
 * Runs at approximately 1 msec per tick (see HZ in forwarder.c).
 * Do not Release this clock.  If you save a copy of it, create your own
 * reference to it with parcClock_Acquire().
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 *
 * @retval non-null An allocated hicn-light Clock based on the Tick counter
 * @retval null An error
 */
PARCClock *forwarder_GetClock(const Forwarder *forwarder);

/**
 * Direct call to get the Tick clock
 *
 * Runs at approximately 1 msec per tick (see HZ in forwarder.c)
 *
 * @param [in] forwarder An allocated hicn-light forwarder
 */
Ticks forwarder_GetTicks(const Forwarder *forwarder);

/**
 * Convert nano seconds to Ticks
 *
 * Converts nano seconds to Ticks, based on HZ (in forwarder.c)
 */
Ticks forwarder_NanosToTicks(uint64_t nanos);

uint64_t forwarder_TicksToNanos(Ticks ticks);

void forwarder_ReceiveCommand(Forwarder *forwarder, command_id command,
                              struct iovec *message, unsigned ingressId);

void forwarder_Receive(Forwarder *forwarder, Message *mesage);

/**
 * @function forwarder_AddOrUpdateRoute
 * @abstract Adds or updates a route on all the message processors
 */
bool forwarder_AddOrUpdateRoute(Forwarder *forwarder,
                                add_route_command *control, unsigned ifidx);

/**
 * @function forwarder_RemoveRoute
 * @abstract Removes a route from all the message processors
 */
bool forwarder_RemoveRoute(Forwarder *forwarder, remove_route_command *control,
                           unsigned ifidx);

#ifdef WITH_POLICY
/**
 * @function forwarder_AddOrUpdatePolicy
 * @abstract Adds or updates a policy on the message processor
 */
bool forwarder_AddOrUpdatePolicy(Forwarder *forwarder, add_policy_command *control);

/**
 * @function forwarder_RemovePolicy
 * @abstract Removes a policy from the message processor
 */
bool forwarder_RemovePolicy(Forwarder *forwarder, remove_policy_command *control);
#endif /* WITH_POLICY */

/**
 * Removes a connection id from all routes
 */
void forwarder_RemoveConnectionIdFromRoutes(Forwarder *forwarder,
                                            unsigned connectionId);

/**
 * @function forwarder_GetConfiguration
 * @abstract The configuration object
 * @discussion
 *   The configuration contains all user-issued commands.  It does not include
 * dynamic state.
 */
Configuration *forwarder_GetConfiguration(Forwarder *forwarder);

FibEntryList *forwarder_GetFibEntries(Forwarder *forwarder);

/**
 * Sets the maximum number of content objects in the content store
 *
 * Implementation dependent - may wipe the cache.
 */
void forwarder_SetContentObjectStoreSize(Forwarder *forwarder,
                                         size_t maximumContentStoreSize);

void forwarder_SetChacheStoreFlag(Forwarder *forwarder, bool val);

bool forwarder_GetChacheStoreFlag(Forwarder *forwarder);

void forwarder_SetChacheServeFlag(Forwarder *forwarder, bool val);

bool forwarder_GetChacheServeFlag(Forwarder *forwarder);

void forwarder_ClearCache(Forwarder *forwarder);

void forwarder_SetStrategy(Forwarder *forwarder, Name *prefix,
                           strategy_type strategy, unsigned related_prefixes_len,
                           Name **related_prefixes);
#if !defined(__APPLE__)
hicn_socket_helper_t *forwarder_GetHicnSocketHelper(Forwarder *forwarder);
#endif
#ifdef WITH_MAPME

/**
 * @function forwarder_getFib
 * @abstract Returns the hICN forwarder's FIB.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @returns Pointer to the hICN FIB.
 */
FIB *forwarder_getFib(Forwarder *forwarder);

/**
 * @function forwarder_onConnectionEvent
 * @abstract Callback fired upon addition of a new connection through the
 *   control protocol.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] conn - Pointer to the newly added connection.
 * @param [in] event - Connection event
 */
void forwarder_onConnectionEvent(Forwarder *forwarder, const Connection *conn, connection_event_t event);

/**
 * @function forwarder_ProcessMapMe
 * @abstract Callback fired by an hICN listener upon reception of a MAP-Me
 *      message.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] msgBuffer - MAP-Me buffer
 * @param [in] conn_id - Ingress connection id
 */
void forwarder_ProcessMapMe(Forwarder *forwarder, const uint8_t *msgBuffer,
                            unsigned conn_id);

struct mapme;
struct mapme * forwarder_getMapmeInstance(const Forwarder *forwarder);

#endif /* WITH_MAPME */

#endif  // forwarder_h
