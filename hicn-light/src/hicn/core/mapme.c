/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 *
 * TODO:
 *  - review notification code with to integration of VPP implementation
 *  - reflect changes back in VPP
 *  - implement heuristic for update/notification selection
 *
 * MAP-Me hooks in forwarder
 *
 * A) Face table changes
 *
 *  - face added
 *
 *    * new local/producer face : this is a new prefix that we need to advertise
 *      on existing connections.
 *
 *      We go over non-local connections an advertise the prefix through an IU
 *      provided that the connection satisfies the policy associated to the FIB
 *      entry. MAP-Me assumes the prefix already exists in the network, and the
 *      IU shall be discarded if the entry does not exist at the next hop. Three
 *      possibilities:
 *      . a bootstrap mechanism
 *      . we allow subprefixes of a prefix that is not empty by duplicating the
 *        FIB entry
 *      . we allow prefix creation in all circumstances : this is problematic
 *        since we might be creating spurious entries in routers for which we
 *        don't expect entries to be created.
 *
 *     NOTE: because in general we will not allow for FIB entry creation, we
 *     cannot let the forwarder remove FIB entries with no nexthop (for instance
 *     after the producer leaves a point-of-attachment). This might creates
 *     permanent state in router's tables, but we assume it is the role of the
 *     routing plane to take care of routing entries.
 *
 *    * new non-local face : a new face is available (eg. thanks to the face
 *      manager, after the node has connection to a new WiFi/LTE access point),
 *      and we thus need to advertise all local/producer prefixes onto this
 *      interface.
 *
 *      For this, we currently scan the FIB for entries that have at least one
 *      local/producer face in nexthops, advertise the prefix on this new
 *      connection provided that it satisfies the associated policy.
 *
 *  - face removed
 *
 *    Currently, we take no action when a face is removed. It might however be a
 *    signal that a producer application is no more running at a given node, and
 *    that we can temporarily disable the forwarding towards that path.
 *
 *  - face up / down
 *
 *  - face nexthop added
 *
 *  - face changed priority/tags
 *
 * B) Interest and Data forwarder path
 *
 *   mapme_on_interest
 *
 *   mapme_on_data
 *
 *
 *   EVENTS
 *      NH_SET
 *      NH_ADD
 *      PH_ADD
 *      PH_DEL
 *
 * C) Retransmission management
 *
 *   Data structure
 *
 *   mapme_on_timeout
 *
 *
 * This allows us to define a convenient API for implementing MAP-Me:
 *
 * mapme_on_face_event XXX rename
 *
 * mapme_set_all_adjacencies(const mapme_t *mapme, fib_entry_t *entry)
 *  This function is used to update all the adjacencies. It needs to be called
 *  in case of face add/delete/change (priority/tas) and polocy
 *
 * mapme_set_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
 *                        nexthops_t *nexthops)
 *  This function updates only the nexthops and clear the tfib. It
 *  needs to be called by the forwarding strategy in case of path switch
 *
 * mapme_update_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
 *                          bool inc_iu_seq)
 *  This function is called to propagate the IU and it propagates the IU using
 *  the nexthops in the tfib. It needs to be used for mapme prcessing, IU
 *  forwarding, NATs and in case of timeouts
 */

#ifdef WITH_MAPME

// Allow processing of MAP-Me requests when no FIB entry is present.
// An alternative would be to perform a LPM
#define HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY

#include <hicn/hicn.h>
#include <hicn/core/mapme.h>
#include <stdio.h>  // printf

#include <hicn/base/loop.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/msgbuf.h>
#include <hicn/core/ticks.h>
#include <hicn/core/fib_entry.h>
#include <hicn/core/pit.h>
#include <hicn/base/loop.h>
#include <hicn/util/log.h>

#define MS2NS(x) x * 1000000
#define T2NS(x) forwarder_TicksToNanos(x)

#define MAPME_DEFAULT_TU 5000  /* ms */
#define MAPME_DEFAULT_RETX 500 /* ms */
#define MAPME_DEFAULT_DISCOVERY false
#define MAPME_DEFAULT_PROTOCOL IPPROTO_IPV6
#define MAPME_MAX_RETX 3
#define MTU 1500  // XXX TODO Mutualize this define

#define DONT_QUEUE false
#define TIMER_NO_REPEAT false

#define MAPME_INVALID_DICOVERY_SEQ -1
#define INIT_SEQ 0

#define foreach_mapme_event \
  _(UNDEFINED)              \
  _(FACE_ADD)               \
  _(FACE_DEL)               \
  _(NH_SET)                 \
  _(NH_ADD)                 \
  _(PH_ADD)                 \
  _(PH_DEL)                 \
  _(N)

typedef enum {
#define _(x) MAPME_EVENT_##x,
  foreach_mapme_event
#undef _
} mapme_event_t;

/*
 * We need a retransmission pool holding all necessary information for crafting
 * special interests, thus including both the DPO and the prefix associated to
 * it.
 */
#define NUM_RETX_ENTRIES 100
#define NUM_RETX_SLOT 2

typedef struct {
  hicn_prefix_t prefix;
  fib_entry_t *entry;
  uint8_t retx_count;  // Number of retransmissions since last tfib addition
} mapme_retx_t;

/**
 * MAP-Me state data structure
 */
struct mapme_s {
  /* Options XXX mapme_conf_t ! */
  uint32_t retx;      /* retx timeout (in ms) */
  uint32_t timescale; /* timescale (in ms) */
  bool discovery;     /* discovery flag */
  int protocol;
  bool enabled; /* mapme enabled/disabled */

  /*
   * Retransmissions
   * Lite calendar queue with NUM_RETX_SLOT slots
   */
  event_t *timer;
  mapme_retx_t retx_array[NUM_RETX_SLOT][NUM_RETX_ENTRIES];
  uint8_t retx_len[NUM_RETX_SLOT];
  uint8_t cur;
  uint8_t idle;

  forwarder_t *forwarder;
};

#define NEXT_SLOT(CUR) (1 - CUR)
#define CUR mapme->retx_array[mapme->cur]
#define NXT mapme->retx_array[NEXT_SLOT(mapme->cur)]
#define CURLEN mapme->retx_len[mapme->cur]
#define NXTLEN mapme->retx_len[NEXT_SLOT(mapme->cur)]

static mapme_t mapme_default = {
    .retx = MAPME_DEFAULT_RETX,
    .timescale = MAPME_DEFAULT_TU,
    .discovery = MAPME_DEFAULT_DISCOVERY,
    .protocol = MAPME_DEFAULT_PROTOCOL,
    .enabled = true,
    .timer = NULL,
    //    .retx_array = {{ 0 }}, // memset
    .retx_len = {0},
    .cur = 0, /* current slot */
    .idle = 0,
};

/******************************************************************************/

int mapme_on_timeout(void *mapme_arg, int fd, unsigned id, void *data);

mapme_t *mapme_create(void *forwarder) {
  mapme_t *mapme = malloc(sizeof(mapme_t));
  if (!mapme) return NULL;

  /* Internal state : set default values */
  memcpy(mapme, &mapme_default, sizeof(mapme_t));
  memset(mapme->retx_array, 0, NUM_RETX_SLOT * NUM_RETX_ENTRIES);

  mapme->forwarder = forwarder;
  loop_timer_create(&mapme->timer, MAIN_LOOP, mapme, mapme_on_timeout, NULL);
  if (!mapme->timer) {
    ERROR("Error allocating mapme timer.");
    free(mapme);
    return NULL;
  }

  return mapme;
}

void mapme_free(mapme_t *mapme) {
  loop_event_free(mapme->timer);
  free(mapme);
}

/******************************************************************************
 * TFIB
 ******************************************************************************/

typedef struct {
  // XXX We need magic number to know whether the TFIB was initialized or not
  // ... or merge it inside the real data structure.
  // NOTE: in VPP we reuse the nexthops in opposite order to gain room
  // XXX need enough space in user_data !!
  uint32_t seq;
  nexthops_t nexthops;  // XXX useless shadow structure
  /* Update/Notification heuristic */
  Ticks last_acked_update;
} mapme_tfib_t;

#define TFIB(FIB_ENTRY) ((mapme_tfib_t *)fib_entry_get_user_data(FIB_ENTRY))

static mapme_tfib_t *mapme_tfib_create() {
  mapme_tfib_t *tfib;
  tfib = malloc(sizeof(mapme_tfib_t));
  if (!tfib) return NULL;

  // init
  tfib->seq = INIT_SEQ;
  tfib->last_acked_update = 0;
  nexthops_set_len(&tfib->nexthops, 0);

  return tfib;
}

void mapme_release_tfib(mapme_tfib_t **tfibPtr) {
  mapme_tfib_t *tfib = *tfibPtr;
  free(tfib);
  tfibPtr = NULL;
}

/**
 * @function mapme_create_tfib
 * @abstract Associate a new TFIB entry to a FIB entry. If a TFIB already exists
 * the new one will be used
 * @param [in] - Pointer to the FIB entry.
 * @return Boolean indicating the success of the operation.
 */
static void mapme_create_tfib(const mapme_t *mapme, fib_entry_t *entry) {
  mapme_tfib_t *tfib;

  tfib = mapme_tfib_create();
  fib_entry_set_user_data(entry, tfib, (void (*)(void **))mapme_release_tfib);
}

/**
 * @brief Update/Notification heuristic:
 *
 * NOTE: IN are currently disabled until the proper placeholder is agreed in the
 * interest header.
 */
static hicn_mapme_type_t mapme_get_type_from_heuristic(const mapme_t *mapme,
                                                       fib_entry_t *entry) {
  if (!entry)
    return UPDATE;
  if (fib_entry_has_local_nexthop(entry))
    /* We are a producer for this entry, send update */
    return UPDATE;

#if 0 /* interplay of IU/IN */
    if (TFIB(fib_entry)->lastAckedUpdate == 0) {
        return UPDATE;
    } else {
        Ticks interval = now - TFIB(fib_entry)->lastAckedUpdate;
        return (T2NS(interval) > MS2NS(mapme->timescale)) ? UPDATE : NOTIFICATION;
    }
#else /* Always send IU */
  return UPDATE;
#endif
}

/**
 *
 * Here nexthops is not necessarily FIB nexthops as we might advertise given FIB
 * entries on various other connections.
 *
 * prefix can be specified to send an update for a More Specific Prefix (MSP),
 * or left NULL for the default behaviour. Note there will be no support for
 * retransmission for MSP.
 *
 * NOTES:
 *  - if the face is pending an we receive an IN, maybe we should not cancel the
 *  timer
 *  - this function should never be called for Notifications.
 */
int mapme_send_to_nexthops(const mapme_t *mapme, fib_entry_t *entry,
                           const nexthops_t *nexthops,
                           const hicn_prefix_t *prefix) {
  const hicn_prefix_t *mapme_prefix;
  uint32_t mapme_seq;

  assert(!!prefix ^ !!entry);

  INFO("mapme_send_to_nexthops");
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return -1;
  }

  if (entry) {
    mapme_tfib_t *tfib = TFIB(entry);
    if (tfib == NULL) {
      mapme_create_tfib(mapme, entry);
      tfib = TFIB(entry);
    }

    mapme_prefix = fib_entry_get_prefix(entry);
    mapme_seq = tfib->seq;
  } else {
    mapme_prefix = prefix;
    mapme_seq = 1;
  }

  WITH_INFO({
    char buf[MAXSZ_HICN_PREFIX];
    int rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, mapme_prefix);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "(error)");
    INFO("sending IU/IN for name %s on all nexthops", buf);
  })

  mapme_params_t params = {
      .protocol = mapme->protocol,
      .type = mapme_get_type_from_heuristic(mapme, entry),
      .seq = mapme_seq
  };

  uint8_t packet[MTU];
  size_t size = hicn_mapme_create_packet(packet, mapme_prefix, &params);
  if (size <= 0) {
    ERROR("Could not create MAP-Me packet");
    return -1;
  }

  connection_table_t *table = forwarder_get_connection_table(mapme->forwarder);

  INFO("sending to %d nexthops", nexthops_get_len(nexthops));
  nexthops_foreach(nexthops, nexthop, {
    INFO("sending mapme packet on connection %d", nexthop);
    const connection_t *conn = connection_table_get_by_id(table, nexthop);
    connection_send_packet(conn, packet, size);
  });

  return 0;
}

#if 0
/**
 *
 * Here nexthops is not necessarily FIB nexthops as we might advertise given FIB
 * entries on various other connections.
 */
void mapme_maybe_send_to_nexthops(const mapme_t *mapme, fib_entry_t *fib_entry,
                                  const nexthops_t *nexthops) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return;
  }

  /* Detect change */
  if (!fib_entry_nexthops_changed(fib_entry)) {
    INFO("No change in nexthops");
    return;
  }
  fib_entry_set_prev_nexthops(fib_entry);

  mapme_send_to_nexthops(mapme, fib_entry, nexthops);
}
#endif

/******************************************************************************
 * MAPME API
 ******************************************************************************/

int mapme_set_all_adjacencies(const mapme_t *mapme, fib_entry_t *entry) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return -1;
  }

  /* Apply the policy of the fib_entry over all neighbours */
  nexthops_t new_nexthops = NEXTHOPS_EMPTY;
  nexthops_t *nexthops = fib_entry_get_mapme_nexthops(entry, &new_nexthops);

  /* We set force to true to avoid overriding the FIB cache */
  return mapme_set_adjacencies(mapme, entry, nexthops, NULL);
}

// XXX this will change with the FIB cache
// XXX we are sometimes incrementing tfib seq for nothing
int mapme_set_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
                          nexthops_t *nexthops, const hicn_prefix_t *prefix) {
  /*
   * - entry is provided in case of a producer reannouncement
   * - prefix is provided for control plane triggered updates
   */
  assert(!!prefix ^ !!entry);

  INFO("1. mapme_set_adjacencies");
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return -1;
  }

  INFO("2. mapme_set_adjacencies");
  /* Let a control plane update go through even if there is no local prefix...
   * we might for instance serve a /128 while a /64 was advertised.
   *
   * For a producer reannouncement, prefix is NULL, and there we can perform the
   * check.
   */
  if (entry) {
    if (!fib_entry_has_local_nexthop(entry)) return -1;
  INFO("3. mapme_set_adjacencies");

    /* Advertise prefix on all available next hops (if needed) */
    mapme_tfib_t *tfib = TFIB(entry);
    if (tfib == NULL) {
      mapme_create_tfib(mapme, entry);
      tfib = TFIB(entry);
    }

    nexthops_clear(&tfib->nexthops);

  /* We update the sequence number in all cases otherwise this won't allow
   * repetition
   */
  tfib->seq++;
  }

  INFO("5 mapme_set_adjacencies");
  mapme_send_to_nexthops(mapme, entry, nexthops, prefix);
  return 0;
}

int mapme_set_adjacency(const mapme_t *mapme, fib_entry_t *entry,
                        nexthop_t nexthop, const hicn_prefix_t *prefix) {
  nexthops_t nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, nexthop);

  return mapme_set_adjacencies(mapme, entry, &nexthops, prefix);
}

int mapme_update_adjacencies(const mapme_t *mapme, fib_entry_t *entry,
                             bool inc_iu_seq) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return -1;
  }

  mapme_tfib_t *tfib = TFIB(entry);
  if (tfib == NULL) {
    mapme_create_tfib(mapme, entry);
    tfib = TFIB(entry);
  }

  if (inc_iu_seq) tfib->seq++;

  mapme_send_to_nexthops(mapme, entry, &tfib->nexthops, NULL);
  return 0;
}

int mapme_send_to_nexthop(const mapme_t *mapme, fib_entry_t *entry,
                          unsigned nexthop) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return -1;
  }

  nexthops_t nexthops = NEXTHOPS_EMPTY;
  nexthops_add(&nexthops, nexthop);

  return mapme_send_to_nexthops(mapme, entry, &nexthops, NULL);
}

#if 0
/*
 * Callback called everytime a new connection is created by the control protocol
 */
void mapme_on_connection_event(const mapme_t *mapme,
                               const connection_t *conn_added,
                               connection_event_t event) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return;
  }

  /* Does the priority change impacts the default route selection; if so,
   * advertise the prefix on this default route. If there are many default
   * routes, either v4 v6, or many connections as next hops on this default
   * route, then send to all.
   */
  if (conn_added) {
    if (connection_is_local(conn_added)) return;

    unsigned conn_added_id = connection_get_id(conn_added);
    switch (event) {
      case CONNECTION_EVENT_CREATE:
        INFO("Connection %d got created", conn_added_id);
        break;
      case CONNECTION_EVENT_DELETE:
        INFO("Connection %d got deleted", conn_added_id);
        break;
      case CONNECTION_EVENT_UPDATE:
        INFO("Connection %d got updated", conn_added_id);
        break;
      case CONNECTION_EVENT_SET_UP:
        INFO("Connection %d went up", conn_added_id);
        break;
      case CONNECTION_EVENT_SET_DOWN:
        INFO("Connection %d went down", conn_added_id);
        break;
      case CONNECTION_EVENT_TAGS_CHANGED:
        INFO("Connection %d changed tags", conn_added_id);
        break;
      case CONNECTION_EVENT_PRIORITY_CHANGED:
        INFO("Connection %d changed priority to %d", conn_added_id,
             connection_get_priority(conn_added));
        break;
    }
  }

  /* We need to send a MapMe update on the newly selected connections for
   * each concerned fib_entry : connection is involved, or no more involved */
  const fib_t *fib = forwarder_get_fib(mapme->forwarder);
  fib_foreach_entry(fib, entry, { mapme_set_all_adjacencies(mapme, entry); });
}
#endif

/*------------------------------------------------------------------------------
 * Special Interest handling
 *----------------------------------------------------------------------------*/

// XXX this code has not been updated
#ifdef HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY
int mapme_create_fib_entry(const mapme_t *mapme, const Name *name,
                           unsigned ingress_id) {
  INFO("  - Re-creating FIB entry with next hop on connection %d", ingress_id);
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
  entry = fib_entry_Create(name, fwdStrategy, mapme->forwarder);
#else
  entry = fib_entry_Create(name, fwdStrategy);
#endif /* WITH_POLICY */
  fib_entry_t *lpm = fib_MatchName(fib, name);
  fib_Add(fib, entry);
  if (!lpm) {
    TFIB(entry)->seq = seq;
    fib_entry_AddNexthop(entry, ingress_id);
    return true;
  }

  /*
   * We make a clone of the FIB entry (zero'ing the sequence number ?) with
   * the more specific name, and proceed as usual. Worst case we clone the
   * default route...
   */
  const NumberSet *lpm_nexthops = fib_entry_nexthops_get(lpm);
  for (size_t i = 0; i < numberSet_Length(lpm_nexthops); i++) {
    fib_entry_AddNexthop(entry, numberSet_GetItem(lpm_nexthops, i));
  }
  return 0;
}
#endif

int mapme_on_timeout(void *mapme_arg, int fd, unsigned id, void *data) {
  mapme_t *mapme = mapme_arg;
  assert(mapme);
  assert(id == 0);
  assert(!data);
  /* Timeout occurred, we have to retransmit IUs for all pending
   * prefixes having entries in TFIB
   *
   * timeouts are slotted
   *    |     |     |     |
   *
   *      ^
   *      +- event occurred
   *            new face, wait for the second next
   *            (having two arrays and swapping cur and next)
   *         retx : put in next
   */
  mapme->idle += 1;

  for (uint8_t pos = 0; pos < CURLEN; pos++) {
    mapme_retx_t *retx = &CUR[pos];

    if (!retx->entry) /* deleted entry */
      continue;

    mapme_tfib_t *tfib = TFIB(retx->entry);
    assert(tfib);

    /* Re-send interest for all entries */
    mapme_update_adjacencies(mapme, retx->entry, false);

    retx->retx_count++;
    /* If we exceed the numver of retransmittion it means that all tfib
     * entries have seens at least HICN_PARAM_RETX_MAX of retransmission
     */
    if (retx->retx_count < MAPME_MAX_RETX) {
      /*
       * We did some retransmissions, so let's reschedule a check in the
       * next slot
       */
      NXT[NXTLEN++] = CUR[pos];
      mapme->idle = 0;
    } else {
      WARN("Maximum retransmissions exceeded");
      /* If we exceed the numver of retransmission it means that all TFIB
       * entries have seens at least HICN_PARAM_RTX_MAX retransmissions.
       * (Deletion might be slightly late).
       *
       * XXX document: when adding an entry in TFIB, we might exceed max
       * retransmissions for previous entries that started retransmitting
       * beforehand.
       */
      nexthops_clear(&tfib->nexthops);
    }
  }

  /* Reset events in this slot and prepare for next one */
  CURLEN = 0;
  mapme->cur = NEXT_SLOT(mapme->cur);

  /* After two empty slots, we disable the timer */
  if (mapme->idle > 1) {
    loop_event_unregister(mapme->timer);
  }

  return 0;
}

static void mapme_on_event(mapme_t *mapme, mapme_event_t event,
                           fib_entry_t *entry, unsigned ingress_id) {
  switch (event) {
#if 0
        case HICN_MAPME_EVENT_FACE_ADD:
        {
            /*
             * A face has been added:
             *  - In case of a local app face, we need to advertise a new prefix
             *  - For another local face type, we need to advertise local
             *  prefixes and schedule retransmissions
             */
            mapme_retx_t *retx_events = event_data;
            for (uint8_t i = 0; i < vec_len (retx_events); i++) {
                hicn_mapme_on_face_added(mapme, retx_events[i].dpo);
            }

            if (mapme->timer_fd == -1)
                mapme->timer_fd = loop_register_timer(MAIN_LOOP,
                        mapme->retx, mapme, mapme_on_timeout, NULL);
            mapme->idle = 0;
            break;
        }
        case HICN_MAPME_EVENT_FACE_DEL:
            if (mapme->timer_fd == -1)
                mapme->timer_fd = loop_register_timer(MAIN_LOOP,
                        DEFAULT_TIMEOUT, mapme, mapme_on_timeout, NULL);
            mapme->idle = 0;
            break;
#endif

    case MAPME_EVENT_NH_SET:
      /*
       * An hICN FIB entry has been modified. All operations so far
       * have been procedded in the nodes. Here we need to track
       * retransmissions upon timeout: we mark the FIB entry as pending in
       * the second-to-next slot
       */

      /*
       * XXX Move this in doc
       *
       * The FIB entry has a new next hop, and its TFIB section has:
       *  - eventually previous prev hops for which a IU with a
       *  lower seqno has been sent
       *  - the prev hops that have just been added.
       *
       * We don't distinguish any and just send an updated IU to all
       * of them. The retransmission of the latest IU to all
       * facilitates the matching of ACKs to a single seqno which is
       * the one stored in the FIB.
       *
       * Since we retransmit to all prev hops, we can remove this
       * (T)FIB entry for the check at the end of the current slot.
       */

      /* Mark FIB entry as pending for second-to-next slot */
      /*
       * Transmit IU for all TFIB entries with latest seqno (we have
       * at least one for sure!)
       */
      mapme_update_adjacencies(mapme, entry, false);

      /* Delete entry_id from retransmissions in the current slot (if present)
       * ... */
      /* ... and schedule it for next slot (if not already) */
      uint8_t j;
      for (j = 0; j < CURLEN; j++) {
        if (CUR[j].entry == entry) CUR[j].entry = NULL; /* sufficient */
      }
      for (j = 0; j < NXTLEN; j++) {
        if (NXT[j].entry == entry) break;
      }
      if (j == NXTLEN) /* not found */
        NXT[NXTLEN++] = (mapme_retx_t){
            .entry = entry,
            .retx_count = 0,
        };

      if (!loop_timer_is_enabled(mapme->timer)) {
        if (loop_timer_register(mapme->timer, mapme->retx) < 0) {
          ERROR("Error setting mapme timer.");
          break;
        }
      }
      mapme->idle = 0;
      break;

    case MAPME_EVENT_NH_ADD:
      /*
       * XXX move this in doc
       *
       * As per the description of states, this event should add the face
       * to the list of next hops, and eventually remove it from TFIB.
       * This corresponds to the multipath case.
       *
       * In all cases, we assume the propagation was already done when the first
       * interest with the same sequence number was received, so we stop here
       * No change in TFIB = no IU to send
       *
       * No change in timers.
       */

      // XXX useless
#if 0
            /* Add ingress face as next hop */
            idle = 0;
#endif
      break;

    case MAPME_EVENT_PH_ADD:
      /* Back-propagation, interesting even for IN (desync) */
      mapme_send_to_nexthop(mapme, entry, ingress_id);

      mapme->idle = 0;
      if (!loop_timer_is_enabled(mapme->timer))
        loop_timer_register(mapme->timer, mapme->retx);
      break;

    case MAPME_EVENT_PH_DEL:
      /* Ack : remove an element from TFIB */
      break;

    case MAPME_EVENT_FACE_ADD:
    case MAPME_EVENT_FACE_DEL:

    case MAPME_EVENT_UNDEFINED:
    case MAPME_EVENT_N:
      ERROR("Unexpected event");
      break;
  }
}

static void mapme_on_interest(mapme_t *mapme, msgbuf_t *msgbuf,
                              unsigned ingress_id, hicn_prefix_t *prefix,
                              mapme_params_t *params) {
  connection_table_t *table = forwarder_get_connection_table(mapme->forwarder);

  /* The cast is needed since connectionTable_FindById miss the
   * const qualifier for the first parameter */
  const connection_t *conn_in = connection_table_get_by_id(table, ingress_id);

  /*
   * Immediately send an acknowledgement back on the ingress connection
   * We always ack, even duplicates. Clone mgsbuf to avoid to overwrite the
   * received message
   */
  msgbuf_t *ack;
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(mapme->forwarder);
  off_t interest_offset = msgbuf_pool_get_id(msgbuf_pool, (msgbuf_t *)msgbuf);
  msgbuf_pool_clone(msgbuf_pool, &ack, interest_offset);

  uint8_t *ack_packet = msgbuf_get_packet(ack);
  size_t size = hicn_mapme_create_ack(ack_packet, params);
  if (!connection_send_packet(conn_in, ack_packet, size)) {
    /* We accept the packet knowing we will get a retransmit */
    ERROR("Failed to send ACK packet");
  }

  msgbuf_pool_put(msgbuf_pool, ack);

  WITH_DEBUG({
    char buf[MAXSZ_HICN_PREFIX];
    int rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, prefix);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "%s", "(error)");
    DEBUG("Ack'ed interest : connection=%d  prefix=%s seq=%d", ingress_id, buf,
          params->seq);
  });

  /* EPM on FIB */
  const fib_t *fib = forwarder_get_fib(mapme->forwarder);
  fib_entry_t *entry = fib_contains(fib, prefix);
  if (!entry) {
#ifdef HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY
    if (mapme_create_fib_entry(mapme, &name, ingress_id) < 0) {
      ERROR("Failed to create FIB entry");
      return;
    }
#else
    INFO("Ignored update with no FIB entry");
    return;
#endif
  }

  mapme_tfib_t *tfib = TFIB(entry);
  if (tfib == NULL) {
    mapme_create_tfib(mapme, entry);
    tfib = TFIB(entry);
  }

  /*
   * In case of multihoming, we might receive a message about our own prefix, we
   * should never take it into account, nor send the IU backwards as a sign of
   * outdated propagation.
   *
   * Detection: we receive a message initially sent by ourselves, ie a message
   * for which the prefix has a local next hop in the FIB.
   */
  // XXX NOT IN VPP ?
  if (fib_entry_has_local_nexthop(entry)) {
    INFO("Received original interest... Update complete");
    return;
  }

  mapme_event_t event = MAPME_EVENT_UNDEFINED;
  if (params->seq > tfib->seq) {
    INFO(
        "MAPME IU seq %d > fib_seq %d, updating seq and next hops, new "
        "nexthop=%d",
        params->seq, tfib->seq, ingress_id);
    /* This has to be done first to allow processing ack */
    // XXX this should even be done before sending ack, as in VPP.
    tfib->seq = params->seq;

    /*
     * Move nexthops to TFIB... but ingress_id that lands in nexthops
     *
     * This could might optimized for situations where nothing changes, but
     * this is very unlikely if not impossible...
     * */
    nexthops_foreach(&entry->nexthops, prevhop,
                     { nexthops_add(&tfib->nexthops, prevhop); });
    nexthops_remove(&tfib->nexthops, ingress_id);
    nexthops_clear(&entry->nexthops);
    nexthops_add(&entry->nexthops, ingress_id);

    event = MAPME_EVENT_NH_SET;

    // XXX tell things are complete if we have no IU to send

  } else if (params->seq == tfib->seq) {
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
    DEBUG("params.seq %d == fib_seq %d, adding nethop %d", params->seq,
          tfib->seq, ingress_id);

    /* Move ingress to nexthops (and eventually remove it from TFIB) */
    nexthops_add(&entry->nexthops, ingress_id);
    nexthops_remove(&tfib->nexthops, ingress_id);

    event = MAPME_EVENT_NH_ADD;

  } else {  // params->seq < tfib->seq
    /*
     * Face is propagating outdated information, we can just
     * consider it as a prevHops. Send the special interest backwards with
     * the new sequence number to reconciliate this outdated part of the
     * arborescence.
     */
    if (nexthops_contains(&entry->nexthops, ingress_id)) {
      INFO("Ignored seq %d < fib_seq %d from current nexthop on face %d",
           params->seq, tfib->seq, ingress_id);
      return;
    } else {
      DEBUG("Received seq %d < fib_seq %d, sending backwards on face %d",
            params->seq, tfib->seq, ingress_id);
      nexthops_add(&tfib->nexthops, ingress_id);
    }

    event = MAPME_EVENT_PH_ADD;
  }

  /* Don't trigger events for notification unless we need to send interests
   * backwards */
  if ((params->type != UPDATE) && (event != MAPME_EVENT_PH_ADD)) return;

  mapme_on_event(mapme, event, entry, ingress_id);
}

static void mapme_on_data(mapme_t *mapme, msgbuf_t *msgbuf, unsigned ingress_id,
                          hicn_prefix_t *prefix, mapme_params_t *params) {
  WITH_DEBUG({
    char buf[MAXSZ_HICN_PREFIX];
    int rc = hicn_prefix_snprintf(buf, MAXSZ_HICN_PREFIX, prefix);
    if (rc < 0 || rc >= MAXSZ_HICN_PREFIX)
      snprintf(buf, MAXSZ_HICN_PREFIX, "(error)");
    DEBUG("Received ack for name prefix=%s seq=%d on conn id=%d", buf,
          params->seq, ingress_id);
  })

  const fib_t *fib = forwarder_get_fib(mapme->forwarder);
  fib_entry_t *entry = fib_contains(fib, prefix);
  if (!entry) {
    INFO("Ignored ACK with no corresponding FIB entry");
    return;
  }
  mapme_tfib_t *tfib = TFIB(entry);

  /*
   * As we always retransmit IU with the latest seq, we are not interested in
   * ACKs with inferior seq
   */
  if (params->seq < tfib->seq) {
    INFO("Ignored ACK with seq %d < %d", params->seq, tfib->seq);
    return;
  }

  nexthops_remove(&tfib->nexthops, ingress_id);
  mapme_on_event(mapme, MAPME_EVENT_PH_DEL, entry, ingress_id);

  /* We need to update the timestamp only for IU Acks, not for IN Acks */
  if (params->type == UPDATE_ACK) {
    INFO("  - Updating LastAckedUpdate");
    tfib->last_acked_update = ticks_now();
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
void mapme_process(mapme_t *mapme, msgbuf_t *msgbuf) {
  if (mapme->enabled == false) {
    WARN("MAP-Me is NOT enabled");
    return;
  }

  hicn_prefix_t prefix;
  mapme_params_t params;

  uint8_t *packet = msgbuf_get_packet(msgbuf);
  unsigned conn_id = msgbuf_get_connection_id(msgbuf);

  int rc = hicn_mapme_parse_packet(packet, &prefix, &params);
  if (rc < 0) return;

  // XXX TYPE STR
  DEBUG("Received interest type: %d seq: %d len:%d", params.type, params.seq,
        prefix.len);

  // XXX RENAME TYPES
  switch (params.type) {
    case UPDATE:
    case NOTIFICATION:
      mapme_on_interest(mapme, msgbuf, conn_id, &prefix, &params);
      break;
    case UPDATE_ACK:
    case NOTIFICATION_ACK:
      mapme_on_data(mapme, msgbuf, conn_id, &prefix, &params);
      break;
    default:
      ERROR("Unknown message");
      break;
  }
}

#if 0
/*
 * Returns true iif the message corresponds to a MAP-Me packet
 */
bool mapme_match_packet(const uint8_t *packet) {
  hicn_mapme_header_t *mapme = (hicn_mapme_header_t *)packet;

  switch (HICN_IP_VERSION(packet)) {
    case 4:
      if (mapme->v4.ip.protocol != IPPROTO_ICMP) return false;
      return HICN_IS_MAPME(mapme->v4.icmp_rd.type, mapme->v4.icmp_rd.code);
    case 6:
      if (mapme->v6.ip.nxt != IPPROTO_ICMPV6) return false;
      return HICN_IS_MAPME(mapme->v6.icmp_rd.type, mapme->v6.icmp_rd.code);
    default:
      return false;
  }
}
#endif

void mapme_set_enable(mapme_t *mapme, bool enable) { mapme->enabled = enable; }
void mapme_set_discovery(mapme_t *mapme, bool enable) {
  mapme->discovery = enable;
}
void mapme_set_timescale(mapme_t *mapme, uint32_t time) {
  mapme->timescale = time;
}
void mapme_set_retransmision(mapme_t *mapme, uint32_t time) {
  mapme->retx = time;
}

#endif /* WITH_MAPME */
