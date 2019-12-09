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
 * @file pit.h
 * @brief The Pending Interest Table interface
 *
 * Interface for implementing a PIT table
 *
 */

#ifndef pit_h
#define pit_h

#include <hicn/base/nexthops.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/message.h>
#include <hicn/processor/pitEntry.h>
#include <hicn/processor/pitVerdict.h>

struct pit;
typedef struct pit PIT;

struct pit {
  void (*release)(PIT **pitPtr);
  PITVerdict (*receiveInterest)(PIT *pit, msgbuf_t *interestMessage);
  nexthops_t * (*satisfyInterest)(PIT *pit, const msgbuf_t *objectMessage);
  void (*removeInterest)(PIT *pit, const msgbuf_t *interestMessage);
  PitEntry *(*getPitEntry)(const PIT *pit, const msgbuf_t *interestMessage);
  void *closure;
};

void *pit_Closure(const PIT *pit);

/**
 * Destroys the PIT table and all entries contained in it.
 *
 * PIT entries are reference counted, so if the user has stored one outside the
 * PIT table it will still be valid.
 *
 * @param [in,out] pitPtr Double pointer to PIT table, will be NULLed
 */
void pit_Release(PIT **pitPtr);

/**
 * @function pit_ReceiveInterest
 * @abstract Receives an interest and adds to PIT table
 * @discussion
 *   If not present, adds entry to the PIT table and returns
 * PIT_VERDICT_NEW_ENTRY. If present and aggregated, returns
 * PIT_VERDICT_EXISTING_ENTRY.
 *
 *   Some aggregated interests may return PIT_VERDICT_NEW_ENTRY if the interest
 * needs to be forwarded again (e.g. the lifetime is extended).
 *
 *   If the PIT stores the message in its table, it will store a reference
 * counted copy.
 *
 * @return Verdict of receiving the interest
 */
PITVerdict pit_ReceiveInterest(PIT *pit, msgbuf_t *interestMessage);

/**
 * @function pit_SatisfyInterest
 * @abstract Tries to satisfy PIT entries based on the message, returning where
 * to send message
 * @discussion
 *     If matching interests are in the PIT, will return the set of reverse
 * paths to use to forward the content object.
 *
 *     The return value is allocated and must be destroyed.
 *
 * @return Set of ConnectionTable id's to forward the message, may be empty or
 * NULL.  Must be destroyed.
 */
nexthops_t * pit_SatisfyInterest(PIT *pit, const msgbuf_t *objectMessage);

/**
 * @function pit_RemoveInterest
 * @abstract Unconditionally remove the interest from the PIT
 * @discussion
 *   The PIT may store a specific name in several tables.  This function will
 *   remove the interest from the specific table it lives it.  It will not
 *   remove PIT entries in different tables with the same name.
 *
 *   The different tables index interests based on their matching criteria,
 *   such as by name, by name and keyid, etc.
 *
 */
void pit_RemoveInterest(PIT *pit, const msgbuf_t *interestMessage);

/**
 * @function pit_GetPitEntry
 * @abstract Retrieve the best matching PIT entry for the message.
 * @discussion
 *   Returns a reference counted copy of the entry, must call
 * <code>pitEntry_Destory()</code> on it.
 *
 * @return NULL if not in table, otherwise a reference counted copy of the entry
 */
PitEntry *pit_GetPitEntry(const PIT *pit, const msgbuf_t *interestMessage);
#endif  // pit_h
