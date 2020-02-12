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
 * @file mapme.h
 * @brief MAP-Me : AnchorLess Producer Mobility Management
 */

#ifndef mapme_h
#define mapme_h

#ifdef WITH_MAPME

#include <stdbool.h>
#include <stdint.h>

#include <hicn/hicn.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/connection.h>
#include <hicn/utils/commands.h>

struct mapme;
typedef struct mapme MapMe;

/**
 * @function mapme_create
 * @abstract Initializes MAP-Me state in the forwarder.
 * @return bool - Boolean informing about the success of MAP-Me initialization.
 */
bool mapme_create(MapMe **mapme, Forwarder *Forwarder);

/**
 * @function mapme_free
 * @abstract Free MAP-Me state in the forwarder.
 */
void mapme_free(MapMe *mapme);

/**
 * @function messageHandler_isMapMe
 * @abstract Identifies MAP-Me messages
 * @discussion This function can be used by the forwarder to dispatch MAP-Me
 * 	message to the appropriate processing function. Ideally this would be
 *      done through hooks defined in the Init function.
 * @param [in] msgBuffer - The buffer to match
 * @return A boolean indicating whether message is a MAP-Me control message.
 */
bool mapme_isMapMe(const uint8_t *msgBuffer);

/**
 * @function mapme_handleMapMeMessage
 * @abstract Process a MAP-Me message.
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] message - MAP-Me buffer
 * @param [in] conn_id - Ingress connection id
 */
void mapme_Process(const MapMe *mapme, const uint8_t *msgBuffer,
                   unsigned conn_id);

/**
 * @function mapme_send_updates
 * @abstract Trigger the update for specified FIB entry and nexthops
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] fibEntry - The FIB entry to consider
 * @param [in] nexthops - NumberSet holding the next hops on which to send the
 * update.
 */
void mapme_send_updates(const MapMe * mapme, FibEntry * fibEntry, const NumberSet * nexthops);

/**
 * @function mapme_reconsiderFibEntry
 * @abstract Process a fib entry for changes that might trigger new updates
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] fibEntry - The FIB entry to consider
 */
void mapme_reconsiderFibEntry(const MapMe *mapme, FibEntry * fibEntry);

/**
 * @function mapme_onFaceEvent
 * @abstract Callback fired upon change associated to a face.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] conn_id - ID of the connection to which the event is related
 * @param [in] event - Face event
 */
void mapme_onFaceEvent(const MapMe *mapme, unsigned conn_id, face_event_t event);

/**
 * @function mapme_onRouteEvent
 * @abstract Callback fired upon change associated to a route.
 * @param [in] forwarder - Pointer to the hICN forwarder.
 * @param [in] name - Name of the route to which the event is related
 * @param [in] conn_id - ID of the connection to which the event is related
 * @param [in] event - Face event
 */
void mapme_onRouteEvent(const MapMe *mapme, Name * name, unsigned conn_id,
        route_event_t event);

/**
 * @function mapme_getNextHops
 * @abstract return the nexthops to forward interests defined by mapme, it
 *   covers also the case where local discovery mechanisms are trriggered.
 */
NumberSet *mapme_getNextHops(const MapMe *mapme, FibEntry *fibEntry,
                             const Message *interest);

hicn_mapme_type_t mapme_PktType_To_LibHicnPktType(MessagePacketType type);

MessagePacketType mapme_LibHicnPktType_To_PktType(hicn_mapme_type_t type);

#endif /* WITH_MAPME */

#endif  // mapme_h
