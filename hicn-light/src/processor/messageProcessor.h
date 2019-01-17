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

/**
 * @file messageProcessor.h
 * @brief Executes the set of rules dictated by the PacketType
 *
 * This is a "run-to-completion" handling of a message based on the PacketType.
 *
 * The MessageProcessor also owns the PIT and FIB tables.
 *
 */

#ifndef messageProcessor_h
#define messageProcessor_h

#include <src/content_store/contentStoreInterface.h>
#include <src/core/forwarder.h>
#include <src/core/message.h>

#include <src/utils/commands.h>

struct message_processor;
typedef struct message_processor MessageProcessor;

/**
 * Allocates a MessageProcessor along with PIT, FIB and ContentStore tables
 *
 * The hicn-light pointer is primarily used for logging (forwarder_Log), getting
 * the configuration, and accessing the connection table.
 *
 * @param [in] Pointer to owning hicn-light process
 *
 * @retval non-null An allocated message processor
 * @retval null An error
 *
 */
MessageProcessor *messageProcessor_Create(Forwarder *forwarder);

/**
 * Deallocates a message processor an all internal tables
 *
 * @param [in,out] processorPtr Pointer to message processor to de-allocate,
 * will be NULL'd.
 */
void messageProcessor_Destroy(MessageProcessor **processorPtr);

/**
 * @function messageProcessor_Receive
 * @abstract Process the message, takes ownership of the memory.
 * @discussion
 *   Will call destroy on the memory when done with it, so if the caller wants
 * to keep it, make a reference counted copy.
 *
 *   Receive may modify some fields in the message, such as the HopLimit field.
 */
void messageProcessor_Receive(MessageProcessor *procesor, Message *message);

/**
 * Adds or updates a route in the FIB
 *
 * If the route already exists, it is replaced
 *
 * @param [in] procesor An allocated message processor
 * @param [in] route The route to update
 *
 * @retval true added or updated
 * @retval false An error
 */
bool messageProcessor_AddOrUpdateRoute(MessageProcessor *processor,
                                       add_route_command *control,
                                       unsigned ifidx);

/**
 * Removes a route from the FIB
 *
 * Removes a specific nexthop for a route.  If there are no nexthops left after
 * the removal, the entire route is deleted from the FIB.
 *
 * @param [in] procesor An allocated message processor
 * @param [in] route The route to remove
 *
 * @retval true Route completely removed
 * @retval false There is still a nexthop for the route
 */

bool messageProcessor_RemoveRoute(MessageProcessor *processor,
                                  remove_route_command *control,
                                  unsigned ifidx);

/**
 * Removes a given connection id from all FIB entries
 *
 * Iterates the FIB and removes the given connection ID from every route.
 */
void messageProcessor_RemoveConnectionIdFromRoutes(MessageProcessor *processor,
                                                   unsigned connectionId);

/**
 * Returns a list of all FIB entries
 *
 * You must destroy the list.
 *
 * @retval non-null The list of FIB entries
 * @retval null An error
 */
FibEntryList *messageProcessor_GetFibEntries(MessageProcessor *processor);

/**
 * Adjusts the ContentStore to the given size.
 *
 * This will destroy and re-create the content store, so any cached objects will
 * be lost.
 *
 */
void messageProcessor_SetContentObjectStoreSize(MessageProcessor *processor,
                                                size_t maximumContentStoreSize);

/**
 * Return the interface to the currently instantiated ContentStore, if any.
 *
 * @param [in] processor the `MessageProcessor` from which to return the
 * ContentStoreInterface.
 *
 */
ContentStoreInterface *messageProcessor_GetContentObjectStore(
    const MessageProcessor *processor);

void messageProcessor_SetCacheStoreFlag(MessageProcessor *processor, bool val);

bool messageProcessor_GetCacheStoreFlag(MessageProcessor *processor);

void messageProcessor_SetCacheServeFlag(MessageProcessor *processor, bool val);

bool messageProcessor_GetCacheServeFlag(MessageProcessor *processor);

void messageProcessor_ClearCache(MessageProcessor *processor);

void processor_SetStrategy(MessageProcessor *processor, Name *prefix,
                           strategy_type strategy);

#ifdef WITH_MAPME

/**
 * @function messageProcessor_getFib
 * @abstract Returns the hICN processor's FIB.
 * @param [in] forwarder - Pointer to the hICN processor.
 * @returns Pointer to the hICN FIB.
 */
FIB *messageProcessor_getFib(MessageProcessor *processor);

#endif /* WITH_MAPME */

#endif  // messageProcessor_h
