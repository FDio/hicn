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
 * The pending interest table.
 *
 * Interest aggregation strategy:
 * - The first Interest for a name is forwarded
 * - A second Interest for a name from a different reverse path may be
 * aggregated
 * - A second Interest for a name from an existing Interest is forwarded
 * - The Interest Lifetime is like a subscription time.  A reverse path entry is
 * removed once the lifetime is exceeded.
 * - Whan an Interest arrives or is aggregated, the Lifetime for that reverse
 * hop is extended.  As a simplification, we only keep a single lifetime not per
 * reverse hop.
 *
 */

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <hicn/processor/hashTableFunction.h>
#include <hicn/processor/pit.h>

#include <hicn/core/ticks.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_HashCodeTable.h>
#include <parc/algol/parc_Memory.h>

#include <hicn/core/forwarder.h>

#include <parc/assert/parc_Assert.h>

struct standard_pit;
typedef struct standard_pit StandardPIT;

struct standard_pit {
  Forwarder *forwarder;
  Logger *logger;
  PARCHashCodeTable *table;  // PIT indexed by name
};

static void _pit_StoreInTable(StandardPIT *pit, Message *interestMessage);

static void _pit_PitEntryDestroyer(void **dataPtr) {
  pitEntry_Release((PitEntry **)dataPtr);
}

static bool _pit_IngressSetContains(PitEntry *pitEntry, unsigned connectionId) {
  const NumberSet *set = pitEntry_GetIngressSet(pitEntry);
  bool numberInSet = numberSet_Contains(set, connectionId);
  return numberInSet;
}

static Ticks _pit_CalculateLifetime(StandardPIT *pit,
                                    Message *interestMessage) {
  uint64_t interestLifetimeTicks =
      message_GetInterestLifetimeTicks(interestMessage);
  if (interestLifetimeTicks == 0) {
    interestLifetimeTicks = forwarder_NanosToTicks(4000000000ULL);
  }

  Ticks expiryTime = forwarder_GetTicks(pit->forwarder) + interestLifetimeTicks;
  return expiryTime;
}

static void _pit_StoreInTable(StandardPIT *pit, Message *interestMessage) {
  Message *key = message_Acquire(interestMessage);

  Ticks expiryTime = _pit_CalculateLifetime(pit, interestMessage);

  PitEntry *pitEntry =
      pitEntry_Create(key, expiryTime, forwarder_GetTicks(pit->forwarder));

  parcHashCodeTable_Add(pit->table, key, pitEntry);

  if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__,
               "Message %p added to PIT (expiry %" PRIu64 ") ingress %u",
               (void *)interestMessage, pitEntry_GetExpiryTime(pitEntry),
               message_GetIngressConnectionId(interestMessage));
  }
}

static void _pit_ExtendLifetime(StandardPIT *pit, PitEntry *pitEntry,
                                Message *interestMessage) {
  Ticks expiryTime = _pit_CalculateLifetime(pit, interestMessage);

  if (expiryTime > pitEntry_GetExpiryTime(pitEntry))
    pitEntry_SetExpiryTime(pitEntry, expiryTime);
}

// ======================================================================
// Interface API

static void _pitStandard_Destroy(PIT **pitPtr) {
  parcAssertNotNull(pitPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*pitPtr, "Parameter must dereference to non-null pointer");

  StandardPIT *pit = pit_Closure(*pitPtr);

  if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__, "PIT %p destroyed", (void *)pit);
  }

  parcHashCodeTable_Destroy(&pit->table);
  logger_Release(&pit->logger);
  parcMemory_Deallocate(pitPtr);
}

static PITVerdict _pitStandard_ReceiveInterest(PIT *generic,
                                               Message *interestMessage) {
  parcAssertNotNull(generic, "Parameter pit must be non-null");
  parcAssertNotNull(interestMessage,
                    "Parameter interestMessage must be non-null");

  StandardPIT *pit = pit_Closure(generic);

  PitEntry *pitEntry = parcHashCodeTable_Get(pit->table, interestMessage);

  if (pitEntry) {
    // has it expired?
    Ticks now = forwarder_GetTicks(pit->forwarder);
    if (now < pitEntry_GetExpiryTime(pitEntry)) {
      _pit_ExtendLifetime(pit, pitEntry, interestMessage);

      // Is the reverse path already in the PIT entry?
      if (_pit_IngressSetContains(
              pitEntry, message_GetIngressConnectionId(interestMessage))) {
        // It is already in the PIT entry, so this is a retransmission, so
        // forward it.

        if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                              PARCLogLevel_Debug)) {
          logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                     __func__,
                     "Message %p existing entry (expiry %" PRIu64
                     ") and reverse path, forwarding",
                     (void *)interestMessage, pitEntry_GetExpiryTime(pitEntry));
        }
#ifdef WITH_POLICY
        return PITVerdict_Retransmit;
#else
        return PITVerdict_Forward;
#endif /* WITH_POLICY */
      }

      // It is in the PIT but this is the first interest for the reverse path
      pitEntry_AddIngressId(pitEntry,
                            message_GetIngressConnectionId(interestMessage));

      if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                            PARCLogLevel_Debug)) {
        logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                   __func__,
                   "Message %p existing entry (expiry %" PRIu64
                   ") and reverse path is new, aggregate",
                   (void *)interestMessage, pitEntry_GetExpiryTime(pitEntry));
      }

      return PITVerdict_Aggregate;
    }
    // this is a timeout....
    FibEntry *fibEntry = pitEntry_GetFibEntry(pitEntry);
    if (fibEntry != NULL) {
      fibEntry_OnTimeout(fibEntry, pitEntry_GetEgressSet(pitEntry));
    }

    // it's an old entry, remove it
    parcHashCodeTable_Del(pit->table, interestMessage);
  }

  _pit_StoreInTable(pit, interestMessage);

  return PITVerdict_Forward;
}

static NumberSet *_pitStandard_SatisfyInterest(PIT *generic,
                                               const Message *objectMessage) {
  parcAssertNotNull(generic, "Parameter pit must be non-null");
  parcAssertNotNull(objectMessage, "Parameter objectMessage must be non-null");

  StandardPIT *pit = pit_Closure(generic);

  NumberSet *ingressSet = numberSet_Create();

  PitEntry *pitEntry = parcHashCodeTable_Get(pit->table, objectMessage);
  if (pitEntry) {
    // here we need to check if the PIT entry is expired
    // if so, remove the PIT entry.
    Ticks now = forwarder_GetTicks(pit->forwarder);
    if (now < pitEntry_GetExpiryTime(pitEntry)) {
      // PIT entry is not expired, use it
      FibEntry *fibEntry = pitEntry_GetFibEntry(pitEntry);
      if (fibEntry != NULL) {
        fibEntry_ReceiveObjectMessage(fibEntry, pitEntry_GetEgressSet(pitEntry),
                                      objectMessage,
                                      pitEntry_GetCreationTime(pitEntry),
                                      forwarder_GetTicks(pit->forwarder));
      }
      const NumberSet *is = pitEntry_GetIngressSet(pitEntry);
      numberSet_AddSet(ingressSet, is);  // with this we do a copy so we can
                                         // remove the entry from the PIT
    }
    // remove the entry from the PIT.  Key is a reference counted copy of the
    // pit entry message
    Message *key = pitEntry_GetMessage(pitEntry);
    parcHashCodeTable_Del(pit->table, key);
    message_Release(&key);
  }

  return ingressSet;
}

static void _pitStandard_RemoveInterest(PIT *generic,
                                        const Message *interestMessage) {
  parcAssertNotNull(generic, "Parameter pit must be non-null");
  parcAssertNotNull(interestMessage,
                    "Parameter interestMessage must be non-null");

  StandardPIT *pit = pit_Closure(generic);

  if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__, "Message %p removed from PIT",
               (void *)interestMessage);
  }

  parcHashCodeTable_Del(pit->table, interestMessage);
}

static PitEntry *_pitStandard_GetPitEntry(const PIT *generic,
                                          const Message *interestMessage) {
  parcAssertNotNull(generic, "Parameter pit must be non-null");
  parcAssertNotNull(interestMessage,
                    "Parameter interestMessage must be non-null");

  StandardPIT *pit = pit_Closure(generic);

  PitEntry *entry = parcHashCodeTable_Get(pit->table, interestMessage);
  if (entry) {
    return pitEntry_Acquire(entry);
  }
  return NULL;
}

// ======================================================================
// Public API

PIT *pitStandard_Create(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");

  size_t allocation = sizeof(PIT) + sizeof(StandardPIT);

  PIT *generic = parcMemory_AllocateAndClear(allocation);
  parcAssertNotNull(generic, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    allocation);
  generic->closure = (uint8_t *)generic + sizeof(PIT);

  StandardPIT *pit = pit_Closure(generic);
  pit->forwarder = forwarder;
  pit->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  size_t initialSize = 65535;
  pit->table =
      parcHashCodeTable_Create_Size(hashTableFunction_MessageNameEquals,
                                    hashTableFunction_MessageNameHashCode, NULL,
                                    _pit_PitEntryDestroyer, initialSize);

  if (logger_IsLoggable(pit->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(pit->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__, "PIT %p created", (void *)pit);
  }

  generic->getPitEntry = _pitStandard_GetPitEntry;
  generic->receiveInterest = _pitStandard_ReceiveInterest;
  generic->release = _pitStandard_Destroy;
  generic->removeInterest = _pitStandard_RemoveInterest;
  generic->satisfyInterest = _pitStandard_SatisfyInterest;

  return generic;
}
