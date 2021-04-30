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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <parc/algol/parc_Memory.h>
#include <hicn/core/numberSet.h>
#include <hicn/processor/pitEntry.h>

#include <parc/assert/parc_Assert.h>

struct pit_entry {
  Message *message;
  NumberSet *ingressIdSet;
  NumberSet *egressIdSet;

  FibEntry *fibEntry;

  Ticks creationTime;
  Ticks expiryTime;

  unsigned refcount;
};

PitEntry *pitEntry_Create(Message *message, Ticks expiryTime,
                          Ticks creationTime) {
  PitEntry *pitEntry = parcMemory_AllocateAndClear(sizeof(PitEntry));
  parcAssertNotNull(pitEntry, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(PitEntry));
  pitEntry->message = message;
  pitEntry->ingressIdSet = numberSet_Create();
  pitEntry->egressIdSet = numberSet_Create();
  pitEntry->refcount = 1;

  // add the message to the reverse path set
  numberSet_Add(pitEntry->ingressIdSet,
                message_GetIngressConnectionId(message));

  // hack in a 4-second timeout
  pitEntry->expiryTime = expiryTime;
  pitEntry->fibEntry = NULL;

  pitEntry->creationTime = creationTime;
  return pitEntry;
}

void pitEntry_Release(PitEntry **pitEntryPtr) {
  parcAssertNotNull(pitEntryPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*pitEntryPtr,
                    "Parameter must dereference to non-null pointer");

  PitEntry *pitEntry = *pitEntryPtr;
  parcTrapIllegalValueIf(pitEntry->refcount == 0,
                         "Illegal state: has refcount of 0");

  pitEntry->refcount--;
  if (pitEntry->refcount == 0) {
    if (pitEntry->fibEntry != NULL) {
      fibEntry_Release(&pitEntry->fibEntry);
    }
    numberSet_Release(&pitEntry->ingressIdSet);
    numberSet_Release(&pitEntry->egressIdSet);
    message_Release(&pitEntry->message);
    parcMemory_Deallocate((void **)&pitEntry);
  }
  *pitEntryPtr = NULL;
}

PitEntry *pitEntry_Acquire(PitEntry *original) {
  parcAssertNotNull(original, "Parameter original must be non-null");
  original->refcount++;
  return original;
}

void pitEntry_AddIngressId(PitEntry *pitEntry, unsigned ingressId) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  numberSet_Add(pitEntry->ingressIdSet, ingressId);
}

void pitEntry_AddEgressId(PitEntry *pitEntry, unsigned egressId) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  numberSet_Add(pitEntry->egressIdSet, egressId);
}

void pitEntry_AddFibEntry(PitEntry *pitEntry, FibEntry *fibEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
  // the fibEntry should be always the same for all the interests in the same
  // pitEntry
  if (pitEntry->fibEntry == NULL) {
    fibEntry_Acquire(fibEntry);
    pitEntry->fibEntry = fibEntry;
  }
}

FibEntry *pitEntry_GetFibEntry(PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return pitEntry->fibEntry;
}

Ticks pitEntry_GetExpiryTime(const PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return pitEntry->expiryTime;
}

Ticks pitEntry_GetCreationTime(const PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return pitEntry->creationTime;
}

void pitEntry_SetExpiryTime(PitEntry *pitEntry, Ticks expiryTime) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  pitEntry->expiryTime = expiryTime;
}

const NumberSet *pitEntry_GetIngressSet(const PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return pitEntry->ingressIdSet;
}

const NumberSet *pitEntry_GetEgressSet(const PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return pitEntry->egressIdSet;
}

Message *pitEntry_GetMessage(const PitEntry *pitEntry) {
  parcAssertNotNull(pitEntry, "Parameter pitEntry must be non-null");
  return message_Acquire(pitEntry->message);
}
