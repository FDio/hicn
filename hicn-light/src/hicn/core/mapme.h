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
 * @file mapme.h
 * @brief MAP-Me : AnchorLess Producer Mobility Management
 */

#ifndef mapme_h
#define mapme_h

#ifdef WITH_MAPME

#include <stdbool.h>
#include <stdint.h>

#include <hicn/ctrl/hicn-light-ng.h>
#include <hicn/hicn.h>

#include "connection.h"
#include "fib_entry.h"
#include "msgbuf.h"

typedef struct mapme_s mapme_t;

/**
 * @function mapme_create
 * @abstract Initializes MAP-Me state in the forwarder.
 * @return bool - Boolean informing about the success of MAP-Me initialization.
 */
mapme_t *mapme_create(void *Forwarder);

/**
 * @function mapme_free
 * @abstract Free MAP-Me state in the forwarder.
 */
void mapme_free(mapme_t *mapme);

/**
 * @function messageHandler_is_mapme
 * @abstract Identifies MAP-Me messages
 * @discussion This function can be used by the forwarder to dispatch MAP-Me
 * 	message to the appropriate processing function. Ideally this would be
 *      done through hooks defined in the Init function.
 * @param [in] msgBuffer - The buffer to match
 * @return A boolean indicating whether message is a MAP-Me control message.
 */
bool mapme_match_packet(const uint8_t *msgBuffer);

/**
 * @function mapme_handlemapme_tMessage
 * @abstract Process a MAP-Me message.
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] message - MAP-Me buffer
 * @param [in] conn_id - Ingress connection id
 */
void mapme_process(mapme_t *mapme, msgbuf_t *msgbuf);

/* mapme API */
/**
 * @function mapme_send_updates
 * @abstract sends an update to all adjacencies. Used for face
 * add/delete/changes (priority.tag) and policy
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] fib_entry - The FIB entry to consider
 */
int mapme_set_all_adjacencies(const mapme_t *mapme, fib_entry_t *entry);

/**
 * @function mapme_set_adjacencies
 * @abstract sends an update to the specified adjacencies. Used by forwarding
 * strategies
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] fib_entry - The FIB entry to consider
 * @param [in] nexthops - next hops on which to send the update.
 */
int mapme_set_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
                          nexthops_t *nexthops, bool force);

/**
 * @function mapme_update_adjacencies
 * @abstract sends an update on previuos adjacencies. Used for IU forwarding,
 * NAT and timeouts
 * strategies
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] fib_entry - The FIB entry to consider
 * @param [in] inc_iu_seq - if true, the seq number of the tfib/mapme iu will be
 * increased by one
 */
int mapme_update_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
                             bool inc_iu_seq);

/**
 * @function mapme_on_connection_event
 * @abstract Callback following the addition of the face though the control
 * protocol.
 * @discussion This callback triggers the sending of control packets by MAP-Me.
 * @param [in] mapme - Pointer to the MAP-Me data structure.
 * @param [in] conn - The newly added connection.
 * @param [in] event - Connection event
 */
void mapme_on_connection_event(const mapme_t *mapme, const connection_t *conn,
                               connection_event_t event);

/**
 * @function mapme_get_nexthops
 * @abstract return the nexthops to forward interests defined by mapme, it
 *   covers also the case where local discovery mechanisms are trriggered.
 */
// nexthops_t * mapme_get_nexthops(const mapme_t *mapme, fib_entry_t *fib_entry,
//                              const msgbuf_t *interest);

void mapme_set_enable(mapme_t *mapme, bool enable);
void mapme_set_discovery(mapme_t *mapme, bool enable);
void mapme_set_timescale(mapme_t *mapme, uint32_t time);
void mapme_set_retransmision(mapme_t *mapme, uint32_t time);

#endif /* WITH_MAPME */

#endif  // mapme_h
