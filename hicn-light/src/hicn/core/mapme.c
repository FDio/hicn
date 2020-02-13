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
 * @file mapme.c
 * @brief MAP-Me : AnchorLess Producer Mobility Management.
 */

#ifdef WITH_MAPME

#include <hicn/hicn.h>
#include <hicn/core/mapme.h>
#include <stdio.h>  // printf

#include <hicn/core/connection.h>
#include <hicn/core/connectionList.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/logger.h>
#include <hicn/core/message.h>
#include <hicn/core/messagePacketType.h>  // packet types
#include <hicn/core/ticks.h>
#include <hicn/processor/fibEntry.h>
#include <hicn/processor/pitEntry.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Iterator.h>
#include <parc/algol/parc_Unsigned.h>
#include <parc/assert/parc_Assert.h>

#define MS2NS(x) x * 1000000
#define T2NS(x) forwarder_TicksToNanos(x)

#define MAPME_DEFAULT_TU 5000  /* ms */
#define MAPME_DEFAULT_RETX 500 /* ms */
#define MAX_RETX 3

#define NOT_A_NOTIFICATION false
#define NO_INGRESS 0
#define TIMER_NO_REPEAT false

#define DO_DISCOVERY 1
#define MAPME_INVALID_DICOVERY_SEQ -1

#define LOG_FACILITY LoggerFacility_Core

#define LOG(mapme, log_level, fmt, ...)                          \
  do {                                                           \
    Logger *logger = forwarder_GetLogger(mapme->forwarder);      \
    if (logger_IsLoggable(logger, LOG_FACILITY, log_level)) {    \
      logger_Log(logger, LOG_FACILITY, log_level, __func__, fmt, \
                 ##__VA_ARGS__);                                 \
    }                                                            \
  } while (0)

#define WARN(mapme, fmt, ...) \
  LOG(mapme, PARCLogLevel_Warning, fmt, ##__VA_ARGS__)
#define ERR(mapme, fmt, ...) LOG(mapme, PARCLogLevel_Error, fmt, ##__VA_ARGS__)
#define INFO(mapme, fmt, ...) LOG(mapme, PARCLogLevel_Info, fmt, ##__VA_ARGS__)
#define DEBUG(mapme, fmt, ...) \
  LOG(mapme, PARCLogLevel_Debug, fmt, ##__VA_ARGS__)

/**
 * MAP-Me state data structure
 */
struct mapme {
  uint32_t retx; /* ms */
  uint32_t Tu;   /* ms */
  bool removeFibEntries;

  Forwarder *forwarder;
};

static MapMe MapMeDefault = {.retx = MAPME_DEFAULT_RETX,
                             .Tu = MAPME_DEFAULT_TU,
                             .removeFibEntries = false};

/******************************************************************************/

bool mapme_create(MapMe **mapme, Forwarder *forwarder) {
  *mapme = malloc(sizeof(MapMe));
  if (!mapme) goto ERR_MALLOC;

  /* Internal state : set default values */
  memcpy(*mapme, &MapMeDefault, sizeof(MapMe));

  (*mapme)->forwarder = forwarder;

  /* As there is no face table and no related events, we need to install hooks
   * in various places in the forwarder, where both control commands and
   * signalization are processed.
   */

  return true;

ERR_MALLOC:
  return false;
}

void mapme_free(MapMe *mapme)
{
    free(mapme);
}

/******************************************************************************
 * TFIB
 ******************************************************************************/

#define INVALID_SEQ 0
#define INIT_SEQ 0

typedef struct {
  uint32_t seq;
  PARCHashMap *nexthops;
  /* Update/Notification heuristic */
  Ticks lastAckedUpdate;
} MapMeTFIB;

static MapMeTFIB *mapmeTFIB_Create() {
  MapMeTFIB *tfib;
  tfib = malloc(sizeof(MapMeTFIB));
  if (!tfib) goto ERR_MALLOC;
  tfib->seq = INIT_SEQ;
  tfib->lastAckedUpdate = 0;
  tfib->nexthops = parcHashMap_Create();
  if (!tfib->nexthops) goto ERR_HASHMAP;

  return tfib;

ERR_HASHMAP:
  free(tfib);
ERR_MALLOC:
  return NULL;
}

void mapmeTFIB_Release(MapMeTFIB **tfibPtr) {
  MapMeTFIB *tfib = *tfibPtr;
  /* TODO; Release all timers */
  parcHashMap_Release(&tfib->nexthops);
  free(tfib);
  *tfibPtr = NULL;
}

/**
 * @function mapme_CreateTFIB
 * @abstract Associate a new TFIB entry to a FIB entry.
 * @param [in] - Pointer to the FIB entry.
 * @return Boolean indicating the success of the operation.
 */
static void mapme_CreateTFIB(FibEntry *fibEntry) {
  MapMeTFIB *tfib;

  /* Make sure we don't already have an associated TFIB entry */
  tfib = fibEntry_getUserData(fibEntry);
  // assertNull(tfib);

  tfib = mapmeTFIB_Create();
  fibEntry_setUserData(fibEntry, tfib, (void (*)(void **))mapmeTFIB_Release);
}

#define TFIB(fibEntry) ((MapMeTFIB *)fibEntry_getUserData(fibEntry))

static const PARCEventTimer *mapmeTFIB_Get(const MapMeTFIB *tfib,
                                           unsigned conn_id) {
  const PARCEventTimer *timer;
  const PARCBuffer *buffer;
  PARCUnsigned *cid = parcUnsigned_Create(conn_id);
  buffer = parcHashMap_Get(tfib->nexthops, cid);
  if (!buffer) return NULL;
  PARCByteArray *array = parcBuffer_Array(buffer);
  timer = *((PARCEventTimer **)parcByteArray_Array(array));
  parcUnsigned_Release(&cid);
  return timer;
}

static void mapmeTFIB_Put(MapMeTFIB *tfib, unsigned conn_id,
                          const PARCEventTimer *timer) {
  /* NOTE: Timers are not objects (the only class not being an object in
   * fact), and as such, we cannot use them as values for the HashMap.
   * Just like for unsigned we needed the PARC wrapper.
   * There is no wrapper for pointers, so we use Arrays, which has an ubly
   * syntax...
   */
  PARCUnsigned *cid = parcUnsigned_Create(conn_id);
  PARCBuffer *buffer =
      parcBuffer_CreateFromArray(&timer, sizeof(PARCEventTimer *));
  parcHashMap_Put(tfib->nexthops, cid, buffer);
  parcUnsigned_Release(&cid);
  parcBuffer_Release(&buffer);
}

static void mapmeTFIB_Remove(MapMeTFIB *tfib, unsigned conn_id) {
  // Who releases the timer ?
  PARCUnsigned *cid = parcUnsigned_Create(conn_id);
  parcHashMap_Remove(tfib->nexthops, cid);
  parcUnsigned_Release(&cid);
}

static PARCIterator *mapmeTFIB_CreateKeyIterator(const MapMeTFIB *tfib) {
  return parcHashMap_CreateKeyIterator(tfib->nexthops);
}

int hicn_prefix_from_name(const Name *name, hicn_prefix_t *prefix) {
  NameBitvector *bv = name_GetContentName(name);
  ip_prefix_t ip_prefix;
  nameBitvector_ToIPAddress(bv, &ip_prefix);

  /* The name length will be equal to ip address' prefix length */
  return hicn_prefix_create_from_ip_prefix(&ip_prefix, prefix);
}

static Message *mapme_createMessage(const MapMe *mapme, const Name *name,
                                    mapme_params_t *params) {
  Ticks now = forwarder_GetTicks(mapme->forwarder);
  Logger *logger = logger_Acquire(forwarder_GetLogger(mapme->forwarder));

  INFO(mapme, "[MAP-Me] CreateMessage type=%d seq=%d", params->type,
       params->seq);

  size_t size = (params->protocol == IPPROTO_IPV6) ? HICN_MAPME_V6_HDRLEN
                                                   : HICN_MAPME_V4_HDRLEN;
  uint8_t *icmp_pkt = parcMemory_AllocateAndClear(size);

  hicn_prefix_t prefix;
  int rc = hicn_prefix_from_name(name, &prefix);
  if (rc < 0) {
    ERR(mapme, "[MAP-Me] Failed to create lib's name");
    goto ERR_NAME;
  }

  INFO(mapme, "[MAP-Me] Creating MAP-Me packet");
  size_t len = hicn_mapme_create_packet(icmp_pkt, &prefix, params);
  if (len == 0) {
    ERR(mapme, "[MAP-Me] Failed to create mapme packet through lib");
    goto ERR_CREATE;
  }

  // hicn_packet_dump(icmp_pkt, MAPME_HDRLEN);

  return message_CreateFromByteArray(NO_INGRESS, icmp_pkt,
                                     MessagePacketType_Interest, now, logger);

ERR_CREATE:
ERR_NAME:
  return NULL;
}

static Message *mapme_createAckMessage(const MapMe *mapme,
                                       const uint8_t *msgBuffer,
                                       const mapme_params_t *params) {
  Ticks now = forwarder_GetTicks(mapme->forwarder);
  Logger *logger = logger_Acquire(forwarder_GetLogger(mapme->forwarder));

  size_t size = (params->protocol == IPPROTO_IPV6) ? HICN_MAPME_V6_HDRLEN
                                                   : HICN_MAPME_V4_HDRLEN;
  uint8_t *icmp_pkt = parcMemory_AllocateAndClear(size);
  memcpy(icmp_pkt, msgBuffer, size);

  size_t len = hicn_mapme_create_ack(icmp_pkt, params);
  if (len != size) {
    ERR(mapme, "[MAP-Me] Failed to create mapme ack packet through lib");
    return NULL;
  }

  return message_CreateFromByteArray(
      NO_INGRESS, icmp_pkt, MessagePacketType_ContentObject, now, logger);
}

struct setFacePendingArgs {
  const MapMe *mapme;
  const Name *name;
  FibEntry *fibEntry;
  unsigned conn_id;
  bool send;
  bool is_producer;
  uint32_t num_retx;
};

static bool mapme_setFacePending(const MapMe *mapme, const Name *name,
                                 FibEntry *fibEntry, unsigned conn_id,
                                 bool send, bool is_producer, bool clear_tfib, uint32_t num_retx);

static void mapme_setFacePendingCallback(int fd, PARCEventType which_event,
                                         void *data) {
  struct setFacePendingArgs *args = (struct setFacePendingArgs *)data;

  parcAssertTrue(which_event & PARCEventType_Timeout,
                 "Event incorrect, expecting %X set, got %X",
                 PARCEventType_Timeout, which_event);

  INFO(args->mapme, "Timeout during retransmission. Re-sending");
  mapme_setFacePending(args->mapme, args->name, args->fibEntry, args->conn_id,
                       args->send, args->is_producer, false, args->num_retx);
}

/**
 * @brief Update/Notification heuristic:
 *
 * NOTE: IN are currently disabled until the proper placeholder is agreed in the
 * interest header.
 */
static hicn_mapme_type_t mapme_getTypeFromHeuristic(const MapMe *mapme,
                                                    FibEntry *fibEntry) {
#if 0 /* interplay of IU/IN */
    if (TFIB(fibEntry)->lastAckedUpdate == 0) {
        return UPDATE;
    } else {
        Ticks interval = now - TFIB(fibEntry)->lastAckedUpdate;
        return (T2NS(interval) > MS2NS(mapme->Tu)) ? UPDATE : NOTIFICATION;
    }
#else /* Always send IU */
  return UPDATE;
#endif
}

static bool mapme_setFacePending(const MapMe *mapme, const Name *name,
                                 FibEntry *fibEntry, unsigned conn_id,
                                 bool send, bool is_producer, bool clear_tfib, uint32_t num_retx) {
  int rc;

  INFO(mapme, "[MAP-Me] SetFacePending connection=%d prefix=XX retx=%d",
       conn_id, num_retx);

  /* NOTE: if the face is pending an we receive an IN, maybe we should not
   * cancel the timer
   */
  Dispatcher *dispatcher = forwarder_GetDispatcher(mapme->forwarder);
  PARCEventTimer *timer;

  /* Safeguard during retransmissions */
  if (!TFIB(fibEntry))
      return true;

  /*
   * On the producer side, we have to clear the TFIB everytime we change the list
   * of adjacencies, otherwise retransmissions will occur to preserve them.
   */
  if (clear_tfib) {
    /*
     * It is likely we cannot iterator and remove elements from the hashmap at
     * the same time, so we proceed in two steps
     */
    if (parcHashMap_Size(TFIB(fibEntry)->nexthops) > 0) {

      NumberSet * conns = numberSet_Create();

      PARCIterator *it = parcHashMap_CreateKeyIterator(TFIB(fibEntry)->nexthops);
      while (parcIterator_HasNext(it)) {
        PARCUnsigned *cid = parcIterator_Next(it);
        unsigned conn_id = parcUnsigned_GetUnsigned(cid);
        numberSet_Add(conns, conn_id);
      }
      parcIterator_Release(&it);

      for (size_t i = 0; i < numberSet_Length(conns); i++) {
        unsigned conn_id = numberSet_GetItem(conns, i);
        PARCEventTimer *oldTimer = (PARCEventTimer *)mapmeTFIB_Get(TFIB(fibEntry), conn_id);
        if (oldTimer)
          parcEventTimer_Stop(oldTimer);
        mapmeTFIB_Remove(TFIB(fibEntry), conn_id);
      }

      numberSet_Release(&conns);
    }
  }

  // NOTE
  // - at producer, send always true, we always send something reliably so we
  // set the timer.
  // - in the network, we always forward an IU, and never an IN
  //if (is_producer || send) {
  if (send) {
    mapme_params_t params = {
        .protocol = IPPROTO_IPV6,
        .type = is_producer ? mapme_getTypeFromHeuristic(mapme, fibEntry) : UPDATE,
        .seq = TFIB(fibEntry)->seq};
    Message *special_interest = mapme_createMessage(mapme, name, &params);
    if (!special_interest) {
      INFO(mapme, "[MAP-Me] Could not create special interest");
      return false;
    }

    const ConnectionTable *table =
        forwarder_GetConnectionTable(mapme->forwarder);
    const Connection *conn =
        connectionTable_FindById((ConnectionTable *)table, conn_id);
    if (conn) {
      const Name * name = message_GetName(special_interest);
      char * name_str = name_ToString(name);
      INFO(mapme, "[MAP-Me] Sending MAP-Me packet name=%s seq=%d conn=%d",
              name_str, params.seq, conn_id);
      free(name_str);
      connection_ReSend(conn, special_interest, NOT_A_NOTIFICATION);
    } else {
      INFO(mapme, "[MAP-Me] Stopped retransmissions as face went down");
    }

    if (num_retx < MAX_RETX) {
      INFO(mapme, "[MAP-Me]   - Scheduling retransmission\n");
      /* Schedule retransmission */
      struct setFacePendingArgs *args =
          malloc(sizeof(struct setFacePendingArgs));
      if (!args) goto ERR_MALLOC;
      args->mapme = mapme;
      args->name = name;
      args->fibEntry = fibEntry;
      args->conn_id = conn_id;
      args->send = send;
      args->is_producer = is_producer;
      args->num_retx = num_retx + 1;

      timer = dispatcher_CreateTimer(dispatcher, TIMER_NO_REPEAT,
                                     mapme_setFacePendingCallback, args);
      struct timeval timeout = {mapme->retx / 1000,
                                (mapme->retx % 1000) * 1000};
      rc = parcEventTimer_Start(timer, &timeout);
      if (rc < 0) goto ERR_TIMER;
    } else {
      INFO(mapme, "[MAP-Me] Last retransmission.");
      timer = NULL;
    }
  } else {
    INFO(mapme, "[MAP-Me]  - not forwarding as send is False");
    timer = NULL;
  }

  PARCEventTimer *oldTimer =
      (PARCEventTimer *)mapmeTFIB_Get(TFIB(fibEntry), conn_id);
  if (oldTimer) {
    INFO(mapme, "[MAP-Me]   - Found old timer, would need to cancel !");
    // parcEventTimer_Stop(oldTimer);
  }
  INFO(mapme, "[MAP-Me]   - Putting new timer in TFIB");
  if (timer) mapmeTFIB_Put(TFIB(fibEntry), conn_id, timer);

  return true;

ERR_MALLOC:
ERR_TIMER:
  return false;
}

/*------------------------------------------------------------------------------
 * Event handling
 *----------------------------------------------------------------------------*/

/*
 * Return true if we have at least one local connection as next hop
 */
static bool mapme_hasLocalNextHops(const MapMe *mapme,
                                   const FibEntry *fibEntry) {
  const NumberSet *nexthops = fibEntry_GetNexthops(fibEntry);
  const ConnectionTable *table = forwarder_GetConnectionTable(mapme->forwarder);

  for (size_t j = 0; j < fibEntry_NexthopCount(fibEntry); j++) {
    /* Retrieve Nexthop #j */
    unsigned conn_id = numberSet_GetItem(nexthops, j);
    const Connection *conn =
        connectionTable_FindById((ConnectionTable *)table, conn_id);

    /* Ignore non-local connections */
    if (!connection_IsLocal(conn)) continue;
    /* We don't need to test against conn_added since we don't
     * expect it to have any entry in the FIB */

    return true;
  }
  return false;
}

void
mapme_send_updates(const MapMe * mapme, FibEntry * fibEntry, const NumberSet * nexthops)
{
  if (!TFIB(fibEntry)) /* Create TFIB associated to FIB entry */
    mapme_CreateTFIB(fibEntry);
  TFIB(fibEntry)->seq++;

  const Name *name = fibEntry_GetPrefix(fibEntry);
  char *name_str = name_ToString(name);
  bool clear_tfib = true;
  for (size_t j = 0; j < numberSet_Length(nexthops); j++) {
      unsigned nexthop_id = numberSet_GetItem(nexthops, j);
      INFO(mapme, "[MAP-Me] sending IU/IN for name %s on connection %d", name_str,
           nexthop_id);
      mapme_setFacePending(mapme, name, fibEntry, nexthop_id, true, true, clear_tfib, 0);
      clear_tfib = false;
  }
  free(name_str);
}


void
mapme_maybe_send_updates(const MapMe * mapme, FibEntry * fibEntry, const NumberSet * nexthops)
{
  /* Detect change */
  NumberSet * previous_nexthops = fibEntry_GetPreviousNextHops(fibEntry);
  if (numberSet_Equals(nexthops, previous_nexthops)) {
      INFO(mapme, "[MAP-Me] No change in nexthops");
      return;
  }
  fibEntry_SetPreviousNextHops(fibEntry, nexthops);

  mapme_send_updates(mapme, fibEntry, nexthops);
}

void
mapme_reconsiderFibEntry(const MapMe *mapme, FibEntry * fibEntry)
{
  /*
   * Skip entries that do not correspond to a producer ( / have a locally
   * served prefix / have no local connection as next hop)
   */
  if (!mapme_hasLocalNextHops(mapme, fibEntry))
      return;

  /* Apply the policy of the fibEntry over all neighbours */
  NumberSet * available_nexthops = fibEntry_GetAvailableNextHops(fibEntry, ~0);

  /* Advertise prefix on all available next hops (if needed) */
  mapme_send_updates(mapme, fibEntry, available_nexthops);

  numberSet_Release(&available_nexthops);
}

/*
 * Callback called everytime a new connection is created by the control protocol
 */
void
mapme_onConnectionEvent(const MapMe *mapme, const Connection *conn_added, connection_event_t event) {
  /* Does the priority change impacts the default route selection; if so,
   * advertise the prefix on this default route. If there are many default
   * routes, either v4 v6, or many connections as next hops on this default
   * route, then send to all.
   */
  if (conn_added) {
    if (connection_IsLocal(conn_added))
        return;

    unsigned conn_added_id = connection_GetConnectionId(conn_added);
    switch(event) {
      case CONNECTION_EVENT_CREATE:
          INFO(mapme, "[MAP-Me] Connection %d got created", conn_added_id);
          break;
      case CONNECTION_EVENT_DELETE:
          INFO(mapme, "[MAP-Me] Connection %d got deleted", conn_added_id);
          break;
      case CONNECTION_EVENT_UPDATE:
          INFO(mapme, "[MAP-Me] Connection %d got updated", conn_added_id);
          break;
      case CONNECTION_EVENT_SET_UP:
          INFO(mapme, "[MAP-Me] Connection %d went up", conn_added_id);
          break;
      case CONNECTION_EVENT_SET_DOWN:
          INFO(mapme, "[MAP-Me] Connection %d went down", conn_added_id);
          break;
      case CONNECTION_EVENT_TAGS_CHANGED:
          INFO(mapme, "[MAP-Me] Connection %d changed tags", conn_added_id);
          break;
      case CONNECTION_EVENT_PRIORITY_CHANGED:
          INFO(mapme, "[MAP-Me] Connection %d changed priority to %d",
                  conn_added_id, connection_GetPriority(conn_added));
          break;
    }
  }

  /* We need to send a MapMe update on the newly selected connections for
   * each concerned fibEntry : connection is involved, or no more involved */
  FibEntryList *fiblist = forwarder_GetFibEntries(mapme->forwarder);

  /* Iterate a first time on the FIB to get the locally served prefixes */
  for (size_t i = 0; i < fibEntryList_Length(fiblist); i++) {
    FibEntry *fibEntry = (FibEntry *)fibEntryList_Get(fiblist, i);
    mapme_reconsiderFibEntry(mapme, fibEntry);
  }

  fibEntryList_Destroy(&fiblist);

  INFO(mapme, "[MAP-Me] Done");
}

#if 0
#ifdef WITH_POLICY
void mapme_onPolicyUpdate(const MapMe *mapme, const Connection *conn_selected, FibEntry * fibEntry)
{
  /* Ignore local connections corresponding to applications for now */
  if (connection_IsLocal(conn_selected))
      return;

  unsigned conn_selected_id = connection_GetConnectionId(conn_selected);
  INFO(mapme, "[MAP-Me] New connection %d", conn_selected_id);

  const Name *name = fibEntry_GetPrefix(fibEntry);

  /* Skip entries that have no local connection as next hop */
  if (!mapme_hasLocalNextHops(mapme, fibEntry))
      return;

  /* This entry corresponds to a locally served prefix, set
   * Special Interest */
  if (!TFIB(fibEntry)) /* Create TFIB associated to FIB entry */
    mapme_CreateTFIB(fibEntry);
  TFIB(fibEntry)->seq++;

  char *name_str = name_ToString(name);
  INFO(mapme, "[MAP-Me] sending IU/IN for name %s on connection %d", name_str,
       conn_selected_id);
  free(name_str);

  mapme_setFacePending(mapme, name, fibEntry, conn_selected_id, true, true, true, 0);
}
#endif /* WITH_POLICY */
#endif

/*------------------------------------------------------------------------------
 * Special Interest handling
 *----------------------------------------------------------------------------*/

/**
 * @discussion This function is way too long and should be cut out
 */
static bool mapme_onSpecialInterest(const MapMe *mapme,
                                    const uint8_t *msgBuffer,
                                    unsigned conn_in_id, hicn_prefix_t *prefix,
                                    mapme_params_t *params) {
  const ConnectionTable *table = forwarder_GetConnectionTable(mapme->forwarder);
  /* The cast is needed since connectionTable_FindById miss the
   * const qualifier for the first parameter */
  const Connection *conn_in =
      connectionTable_FindById((ConnectionTable *)table, conn_in_id);
  seq_t fibSeq, seq = params->seq;
  bool send = (params->type == UPDATE);
  bool rv;

  Name *name = name_CreateFromPacket(msgBuffer, MessagePacketType_Interest);
  name_setLen(name, prefix->len);
  char *name_str = name_ToString(name);
  INFO(mapme,
       "[MAP-Me] Ack'ed Special Interest on connection %d - prefix=%s type=XX "
       "seq=%d",
       conn_in_id, name_str, seq);
  free(name_str);

  /*
   * Immediately send an acknowledgement back on the ingress connection
   * We always ack, even duplicates.
   */
  Message *ack = mapme_createAckMessage(mapme, msgBuffer, params);
  if (!ack) goto ERR_ACK_CREATE;
  rv = connection_ReSend(conn_in, ack, NOT_A_NOTIFICATION);
  if (!rv) goto ERR_ACK_SEND;
  message_Release(&ack);

  /* EPM on FIB */
  /* only the processor has access to the FIB */
  FIB *fib = forwarder_getFib(mapme->forwarder);

  FibEntry *fibEntry = fib_Contains(fib, name);
  if (!fibEntry) {
    INFO(mapme, "Ignored update with no FIB entry");
    return 0;
#if 0
    INFO(mapme,
         "[MAP-Me]   - Re-creating FIB entry with next hop on connection %d",
         conn_in_id);
    /*
     * This might happen for a node hosting a producer which has moved.
     * Destroying the face has led to removing all corresponding FIB
     * entries. In that case, we need to correctly restore the FIB entries.
     */
    strategy_type fwdStrategy = LAST_STRATEGY_VALUE;

    /*
     * It might also be due to the announcement of a more specific prefix. In
     * that case we need to perform a FIB lookup to find the next hops to which
     * the message should be propagated.
     */
#ifdef WITH_POLICY
    fibEntry = fibEntry_Create(name, fwdStrategy, mapme->forwarder);
#else
    fibEntry = fibEntry_Create(name, fwdStrategy);
#endif /* WITH_POLICY */
    FibEntry *lpm = fib_MatchName(fib, name);
    mapme_CreateTFIB(fibEntry);
    fib_Add(fib, fibEntry);
    if (!lpm) {
      TFIB(fibEntry)->seq = seq;
      fibEntry_AddNexthop(fibEntry, conn_in_id);
      return true;
    }

    /*
     * We make a clone of the FIB entry (zero'ing the sequence number ?) with
     * the more specific name, and proceed as usual. Worst case we clone the
     * default route...
     */
    const NumberSet *lpm_nexthops = fibEntry_GetNexthops(lpm);
    for (size_t i = 0; i < numberSet_Length(lpm_nexthops); i++) {
        fibEntry_AddNexthop(fibEntry, numberSet_GetItem(lpm_nexthops, i));
    }
#endif

  } else if (!TFIB(fibEntry)) {
    /* Create TFIB associated to FIB entry */
    INFO(mapme,
         "[MAP-Me]   - Creating TFIB entry with default sequence number");
    mapme_CreateTFIB(fibEntry);
  }

  /*
   * In case of multihoming, we might receive a message about our own prefix, we
   * should never take it into account, nor send the IU backwards as a sign of
   * outdated propagation.
   *
   * Detection: we receive a message initially sent by ourselves, ie a message
   * for which the prefix has a local next hop in the FIB.
   */
  if (mapme_hasLocalNextHops(mapme, fibEntry)) {
    INFO(mapme, "[MAP-Me]   - Received original interest... Update complete");
    return true;
  }

  fibSeq = TFIB(fibEntry)->seq;
  if (seq > fibSeq) {
    INFO(mapme,
         "[MAP-Me]   - Higher sequence number than FIB %d, updating seq and "
         "next hops",
         fibSeq);
    /* This has to be done first to allow processing SpecialInterestAck's */
    TFIB(fibEntry)->seq = seq;

    /* Reliably forward the IU on all prevHops */
    INFO(mapme, "[MAP-Me]   - (1/3) processing prev hops");
    if (params->type == UPDATE) {
      PARCIterator *iterator = mapmeTFIB_CreateKeyIterator(TFIB(fibEntry));
      while (parcIterator_HasNext(iterator)) {
        PARCUnsigned *cid = parcIterator_Next(iterator);
        unsigned conn_id = parcUnsigned_GetUnsigned(cid);
        INFO(mapme, "[MAP-Me]   - Re-sending IU to pending connection %d",
             conn_id);
        mapme_setFacePending(mapme, fibEntry_GetPrefix(fibEntry), fibEntry,
                             conn_id, false, false, false, 0);
      }
      parcIterator_Release(&iterator);
    }

    /* nextHops -> prevHops
     *
     * We add to the list of pendingUpdates the current next hops, and
     * eventually forward them an IU too.
     *
     * Exception: nextHops -> nextHops
     *   Because of retransmission issues, it is possible that a second interest
     *   (with same of higher sequence number) is receive from a next-hop
     *   interface. In that case, the face remains a next hop.
     */
    const NumberSet *nexthops_old = fibEntry_GetNexthops(fibEntry);

    /* We make a copy to be able to send IU _after_ updating next hops */
    NumberSet *nexthops = numberSet_Create();
    numberSet_AddSet(nexthops, nexthops_old);

    /* We are considering : * -> nextHops
     *
     * If inFace was a previous hop, we need to cancel the timer and remove
     * the entry. Also, the face should be added to next hops.
     *
     * Optimization : nextHops -> nextHops
     *  - no next hop to add
     *  - we know that inFace was not a previous hop since it was a next hop and
     *  this forms a partition. No need for a search
     */

    INFO(mapme, "[MAP-Me]   - (3/3) next hops ~~> prev hops");
    PARCEventTimer *oldTimer =
        (PARCEventTimer *)mapmeTFIB_Get(TFIB(fibEntry), conn_in_id);
    if (oldTimer) {
      /* This happens if we receive an IU while we are still sending
       * one in the other direction
       */
      INFO(mapme, "[MAP-Me]   - Canceled pending timer");
      parcEventTimer_Stop(oldTimer);
    }
    mapmeTFIB_Remove(TFIB(fibEntry), conn_in_id);

    /* Remove all next hops */
    for (size_t k = 0; k < numberSet_Length(nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(nexthops, k);
      INFO(mapme, "[MAP-Me]   - Replaced next hops by connection %d", conn_id);
      fibEntry_RemoveNexthopByConnectionId(fibEntry, conn_id);
    }
    fibEntry_AddNexthop(fibEntry, conn_in_id);

    INFO(mapme, "[MAP-Me]   - (2/3) processing next hops");
    bool complete = true;
    for (size_t k = 0; k < numberSet_Length(nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(nexthops, k);
      INFO(mapme, " - Next hop connection %d", conn_id);
      if (conn_id == conn_in_id) {
        INFO(mapme, "   . Ignored this next hop since equal to ingress face");
        continue;
      }

      INFO(mapme, "[MAP-Me]   - Sending IU on current next hop connection %d",
           conn_id);
      mapme_setFacePending(mapme, fibEntry_GetPrefix(fibEntry), fibEntry,
                           conn_id, send, false, false, 0);
      complete = false;
    }

    /*
     * The update is completed when the IU could not be sent to any
     * other next hop.
     */
    if (complete) INFO(mapme, "[MAP-Me]   - Update completed !");

    numberSet_Release(&nexthops);

  } else if (seq == fibSeq) {
    /*
     * Multipath, multihoming, multiple producers or duplicate interest
     *
     * In all cases, we assume the propagation was already done when the first
     * interest with the same sequence number was received, so we stop here
     *
     * It might happen that the previous AP has still a connection to the
     * producer and that we received back our own IU. In that case, we just
     * need to Ack and ignore it.
     */
#if 0
    if (mapme_hasLocalNextHops(mapme, fibEntry)) {
      INFO(mapme, "[MAP-Me]   - Received original interest... Update complete");
      return true;
    }
#endif

    INFO(mapme, "[MAP-Me]   - Adding multipath next hop on connection %d",
         conn_in_id);
    fibEntry_AddNexthop(fibEntry, conn_in_id);

  } else {  // seq < fibSeq
    /*
     * Face is propagating outdated information, we can just
     * consider it as a prevHops. Send the special interest backwards with
     * the new sequence number to reconciliate this outdated part of the
     * arborescence.
     */
    INFO(
        mapme,
        "[MAP-Me]   - Update interest %d -> %d sent backwards on connection %d",
        seq, fibSeq, conn_in_id);
    mapme_setFacePending(mapme, fibEntry_GetPrefix(fibEntry), fibEntry,
                         conn_in_id, send, false, false, 0);
  }

  return true;

ERR_ACK_SEND:
  message_Release(&ack);
ERR_ACK_CREATE:
  return false;
}

void mapme_onSpecialInterestAck(const MapMe *mapme, const uint8_t *msgBuffer,
                                unsigned conn_in_id, hicn_prefix_t *prefix,
                                mapme_params_t *params) {
  INFO(mapme, "[MAP-Me] Receive IU/IN Ack on connection %d", conn_in_id);

  const Name * name =
      name_CreateFromPacket(msgBuffer, MessagePacketType_ContentObject);
  name_setLen((Name*) name, prefix->len);
  char * name_str = name_ToString(name);
  INFO(mapme, "[MAP-Me] Received ack for name prefix=%s seq=%d on conn id=%d",
          name_str, params->seq, conn_in_id);
  free(name_str);

  FIB *fib = forwarder_getFib(mapme->forwarder);
  FibEntry *fibEntry = fib_Contains(fib, name);
  if (!fibEntry) {
    return;
  }
  parcAssertNotNull(fibEntry,
                    "No corresponding FIB entry for name contained in IU Ack");

  /* Test if the latest pending update has been ack'ed, otherwise just ignore */
  seq_t seq = params->seq;
  if (seq != INVALID_SEQ) {
    seq_t fibSeq = TFIB(fibEntry)->seq;

    if (seq < fibSeq) {

        /* If we receive an old ack:
         *  - either the connection is still a next hop and we have to ignore
         *  the ack until we receive a further update with higher seqno
         *  - or the connection is no more to be informed and the ack is
         *  sufficient and we can remove future retransmissions
         */

      INFO(mapme,
           "[MAP-Me]   - Ignored special interest Ack with seq=%u, expected %u",
           seq, fibSeq);
      return;
    }
  }

  /*
   * Ignore the Ack if no TFIB is present, or it has no corresponding entry
   * with the ingress face.
   * Note: previously, we were creating the TFIB entry
   */
  if (!TFIB(fibEntry)) {
    INFO(mapme, "[MAP-Me]   - Ignored ACK for prefix with no TFIB entry");
    return;
  }

  PARCEventTimer *timer =
      (PARCEventTimer *)mapmeTFIB_Get(TFIB(fibEntry), conn_in_id);
  if (!timer) {
    INFO(mapme,
         "[MAP-Me]   - Ignored ACK for prefix not having the Connection in "
         "TFIB entry. Possible duplicate ?");
    return;
  }

  /* Stop timer and remove entry from TFIB */
  parcEventTimer_Stop(timer);
  mapmeTFIB_Remove(TFIB(fibEntry), conn_in_id);

  INFO(mapme, "[MAP-Me]   - Removing TFIB entry for ack on connection %d",
       conn_in_id);

  /* We need to update the timestamp only for IU Acks, not for IN Acks */
  if (params->type == UPDATE_ACK) {
    INFO(mapme, "[MAP-Me]   - Updating LastAckedUpdate");
    TFIB(fibEntry)->lastAckedUpdate = forwarder_GetTicks(mapme->forwarder);
  }
}

/*-----------------------------------------------------------------------------
 * Overloaded functions
 *----------------------------------------------------------------------------*/

/*
 * @abstract returns where to forward a normal interests(nexthops) defined by
 * mapme, it also set the sequnence number properly if needed
 */

/******************************************************************************
 * Public functions (exposed in the .h)
 ******************************************************************************/

/*
 * Returns true iif the message corresponds to a MAP-Me packet
 */
bool mapme_isMapMe(const uint8_t *packet) {
  hicn_mapme_header_t * mapme = (hicn_mapme_header_t*)packet;

  switch(HICN_IP_VERSION(packet)) {
    case 4:
      if (mapme->v4.ip.protocol != IPPROTO_ICMP)
        return false;
      return HICN_IS_MAPME(mapme->v4.icmp_rd.type, mapme->v4.icmp_rd.code);
    case 6:
      if (mapme->v6.ip.nxt != IPPROTO_ICMPV6)
        return false;
      return HICN_IS_MAPME(mapme->v6.icmp_rd.type, mapme->v6.icmp_rd.code);
    default:
      return false;
  }
}

/**
 * @discussion The exact type of the MapMe message is determined after
 * reception. In hICN, Interest Update and Notifications look like regular
 * Interest packets, and are first punted from the normal path by the forwarder,
 * then treated as such in the Listener to reach this function. Acknowledgements
 * are received as Content (Data) packets and will land here too.
 *
 * This function is in charge of abstracting the low-level implementation of
 * MAP-Me (eg. ICMP packets) and return higher level messages that can be
 * processed by MAP-Me core.
 */
void mapme_Process(const MapMe *mapme, const uint8_t *msgBuffer,
                   unsigned conn_id) {
  hicn_prefix_t prefix;
  mapme_params_t params;
  hicn_mapme_parse_packet(msgBuffer, &prefix, &params);

  switch (params.type) {
    case UPDATE:
    case NOTIFICATION:
      mapme_onSpecialInterest(mapme, msgBuffer, conn_id, &prefix, &params);
      break;
    case UPDATE_ACK:
    case NOTIFICATION_ACK:
      mapme_onSpecialInterestAck(mapme, msgBuffer, conn_id, &prefix, &params);
      break;
    default:
      ERR(mapme, "[MAP-Me] Unknown message");
      break;
  }
}

#endif /* WITH_MAPME */
