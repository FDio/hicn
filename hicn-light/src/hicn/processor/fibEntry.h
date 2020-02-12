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
 * @file fibEntry.h
 * @brief A forwarding entry in the FIB table
 *
 * A Forwarding Information Base (FIB) entry (FibEntry) is a
 * set of nexthops for a name.  It also indicates the forwarding strategy.
 *
 * Each nexthop contains the ConnectionId assocaited with it.  This could be
 * something specific like a MAC address or point-to-point tunnel.  Or, it
 * could be something general like a MAC group address or ip multicast overlay.
 *
 * See strategy.h for a description of forwarding strategies.
 * In short, a strategy is the algorithm used to select one or more nexthops
 * from the set of available nexthops.
 *
 * Each nexthop also contains a void* to a forwarding strategy data container.
 * This allows a strategy to keep proprietary information about each nexthop.
 *
 *
 */

#ifndef fibEntry_h
#define fibEntry_h

#include <hicn/core/name.h>
#include <hicn/strategies/strategyImpl.h>

#ifdef WITH_POLICY
#include <hicn/core/connectionTable.h>
#endif /* WITH_POLICY */

#ifdef WITH_MAPME
#include <parc/algol/parc_EventTimer.h>
#include <parc/algol/parc_Iterator.h>
#endif /* WITH_MAPME */

struct fib_entry;
typedef struct fib_entry FibEntry;

#ifdef WITH_POLICY
struct forwarder;
FibEntry *fibEntry_Create(Name *name, hicn_strategy_t fwdStrategy, const struct forwarder * table);
#else
FibEntry *fibEntry_Create(Name *name, hicn_strategy_t fwdStrategy);
#endif

/**
 * Decrements the reference count by one, and destroys the memory after last
 * release
 *
 */
void fibEntry_Release(FibEntry **fibEntryPtr);

/**
 * Returns a reference counted copy of the fib entry
 *
 * The reference count is increased by one.  The returned value must be
 * released via fibEnty_Release().
 *
 * @param [in] fibEntry An allocated FibEntry
 *
 * @return non-null A reference counted copy of the fibEntry
 *
 */
FibEntry *fibEntry_Acquire(const FibEntry *fibEntry);

void fibEntry_SetStrategy(FibEntry *fibEntry, hicn_strategy_t strategy,
                           unsigned related_prefixes_len,
                           Name **related_prefixes);

void fibEntry_AddNexthop(FibEntry *fibEntry, unsigned connectionId);

void fibEntry_RemoveNexthopByConnectionId(FibEntry *fibEntry,
                                          unsigned connectionId);

size_t fibEntry_NexthopCount(const FibEntry *fibEntry);

/**
 * @function fibEntry_GetNexthops
 * @abstract Returns the nexthop set of the FIB entry.  You must Acquire if it
 * will be saved.
 * @discussion
 *   Returns the next hop set for the FIB entry.
 */
const NumberSet *fibEntry_GetNexthops(const FibEntry *fibEntry);

const NumberSet *fibEntry_GetNexthopsFromForwardingStrategy(
#ifdef WITH_POLICY
    FibEntry *fibEntry, const Message *interestMessage, bool is_retransmission);
#else
    const FibEntry *fibEntry, const Message *interestMessage);
#endif /* WITH_POLICY */

#ifdef WITH_POLICY
void fibEntry_ReceiveObjectMessage(FibEntry *fibEntry,
#else
void fibEntry_ReceiveObjectMessage(const FibEntry *fibEntry,
#endif /* WITH_POLICY */
                                   const NumberSet *egressId,
                                   const Message *objectMessage,
                                   Ticks pitEntryCreation,
                                   Ticks objReception);

#ifdef WITH_POLICY
policy_t fibEntry_GetPolicy(const FibEntry *fibEntry);
void fibEntry_ReconsiderPolicy(FibEntry *fibEntry);
void fibEntry_SetPolicy(FibEntry *fibEntry, policy_t policy);
void fibEntry_UpdateStats(FibEntry *fibEntry, uint64_t now);
NumberSet * fibEntry_GetAvailableNextHops(const FibEntry *fibEntry, unsigned in_connection);
NumberSet * fibEntry_GetPreviousNextHops(const FibEntry *fibEntry);
void fibEntry_SetPreviousNextHops(FibEntry *fibEntry, const NumberSet * nexthops);

void fibEntry_OnTimeout(FibEntry *fibEntry, const NumberSet *egressId);
const NumberSet *fibEntry_GetNexthopsFromForwardingStrategy(
    FibEntry *fibEntry, const Message *interestMessage, bool is_retransmission);

#else
void fibEntry_OnTimeout(const FibEntry *fibEntry, const NumberSet *egressId);
const NumberSet *fibEntry_GetNexthopsFromForwardingStrategy(
    const FibEntry *fibEntry, const Message *interestMessage);
#endif /* WITH_POLICY */


hicn_strategy_t fibEntry_GetFwdStrategyType(const FibEntry *fibEntry);

StrategyImpl *fibEntry_GetFwdStrategy(const FibEntry *fibEntry);

/**
 * @function fibEntry_GetPrefix
 * @abstract Returns a copy of the prefix.
 * @return A reference counted copy that you must destroy
 */
Name *fibEntry_GetPrefix(const FibEntry *fibEntry);

#ifdef WITH_MAPME

/**
 * @function fibEntry_getUserData
 * @abstract Returns user data associated to the FIB entry.
 * @param [in] fibEntry - Pointer to the FIB entry.
 * @return User data as a void pointer
 */
void *fibEntry_getUserData(const FibEntry *fibEntry);

/**
 * @function fibEntry_getUserData
 * @abstract Associates user data and release callback to a FIB entry.
 * @param [in] fibEntry - Pointer to the FIB entry.
 * @param [in] userData - Generic pointer to user data
 * @param [in@ userDataRelease - Callback used to release user data upon change
 *       of FIB entry removal.
 */
void fibEntry_setUserData(FibEntry *fibEntry, const void *userData,
                          void (*userDataRelease)(void **));

#endif /* WITH_MAPME */

#endif  // fibEntry_h
