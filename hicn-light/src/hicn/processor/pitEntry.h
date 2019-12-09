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
 * @file pitEntry.h
 * @brief The embodiment of a PIT entry
 *
 * Embodies a PIT entry
 *
 */

#ifndef pitEntry_h
#define pitEntry_h

#include <hicn/core/message.h>
#include <hicn/core/ticks.h>
#include <hicn/processor/fib_entry.h>

struct pit_entry;
typedef struct pit_entry PitEntry;

/**
 * @function pitEntry_Create
 * @abstract Takes ownership of the message inside the PitEntry
 * @discussion
 *   When the PIT entry is destroyed, will call <code>message_Release()</code>
 * on the message.
 *
 */
PitEntry *pitEntry_Create(msgbuf_t *message, Ticks expiryTime,
                          Ticks CreationTime);

/**
 * Release a previously acquired reference to the specified instance,
 * decrementing the reference count for the instance.
 *
 * The pointer to the instance is set to NULL as a side-effect of this function.
 *
 * If the invocation causes the last reference to the instance to be released,
 * the instance is deallocated and the instance's implementation will perform
 * additional cleanup and release other privately held references.
 *
 * @param [in,out] pitEntryPtr A pointer to a PitEntry instance pointer, which
 * will be set to zero on return.
 *
 */
void pitEntry_Release(PitEntry **pitEntryPtr);

/**
 * @function pitEntry_Acquire
 * @abstract Returns a reference counted copy
 * @discussion
 *   A reference counted copy that shares the same state as the original.
 *   Caller must use <code>pitEntry_Release()</code> on it when done.
 *
 * @return A reference counted copy, use Destroy on it.
 */
PitEntry *pitEntry_Acquire(PitEntry *original);

/**
 * @function pitEntry_AddIngressId
 * @abstract Add an ingress connection id to the list of reverse paths
 * @discussion
 *   A PitEntry has two NumberSets.  The first is the set of ingress ports,
 * which make up the reverse path.  The second is the set of egress ports, which
 * make up its forward path.
 *
 *   This function tracks which reverse paths have sent us the interest.
 *
 * @param ingressId the reverse path
 */
void pitEntry_AddIngressId(PitEntry *pitEntry, unsigned ingressId);

/**
 * @function pitEntry_AddEgressId
 * @abstract Add an egress connection id to the list of attempted paths
 * @discussion
 *   A PitEntry has two NumberSets.  The first is the set of ingress ports,
 * which make up the reverse path.  The second is the set of egress ports, which
 * make up its forward path.
 *
 *   This function tracks which forward paths we've tried for the interest.
 *
 * @param egressId the forwarded path
 */
void pitEntry_AddEgressId(PitEntry *pitEntry, unsigned egressId);

void pitEntry_AddFibEntry(PitEntry *pitEntry, fib_entry_t *fibEntry);

fib_entry_t *pitEntry_GetFibEntry(PitEntry *pitEntry);

/**
 * @function pitEntry_GetIngressSet
 * @abstract The Ingress connection id set
 * @discussion
 *   You must acquire a copy of the number set if you will store the result.
 * This is the internal reference.
 *
 * @return May be empty, will not be null.  Must be destroyed.
 */
const nexthops_t * pitEntry_GetIngressSet(const PitEntry *pitEntry);

/**
 * @function pitEntry_GetEgressSet
 * @abstract The Egress connection id set
 * @discussion
 *   You must acquire a copy of the number set if you will store the result.
 * This is the internal reference.
 *
 * @param <#param1#>
 * @return May be empty, will not be null.  Must be destroyed.
 */
const nexthops_t * pitEntry_GetEgressSet(const PitEntry *pitEntry);

/**
 * @function pitEntry_GetMessage
 * @abstract Gets the interest underpinning the PIT entry
 * @discussion
 *   A reference counted copy, call <code>Message_Release()</code> on it.
 *
 * @return A reference counted copy, call <code>Message_Release()</code> on it.
 */
msgbuf_t *pitEntry_GetMessage(const PitEntry *pitEntry);

/**
 * Returns the time (in ticks) at which the PIT entry is no longer valid
 *
 * The ExpiryTime is computed when the PIT entry is added (or via
 * pitEntry_SetExpiryTime). It is the aboslute time (in Ticks) at which the Pit
 * entry is no longer valid.
 *
 * @param [in] PitEntry An allocated PIT entry
 *
 * @retval number The abosolute time (in Ticks) of the Expiry
 */
Ticks pitEntry_GetExpiryTime(const PitEntry *pitEntry);

Ticks pitEntry_GetCreationTime(const PitEntry *pitEntry);
/**
 * Sets the ExpriyTime of the PIT entry to the given value
 *
 * It is probalby an error to set the expiryTime to a smaller value than
 * currently set to, but this is not enforced.  PIT entries use lazy delete.
 *
 * @param [in] pitEntry The allocated PIT entry to modify
 * @param [in] expiryTime The new expiryTime (UTC in forwarder Ticks)
 *
 */
void pitEntry_SetExpiryTime(PitEntry *pitEntry, Ticks expiryTime);

#endif  // pitEntry_h
