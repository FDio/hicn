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
 * Event based router
 *
 * This module is the glue around the event scheduler.
 * Its the packet i/o module.
 *
 * Packet processing is done in dispatcher.c, which is the actual wrapper around
 * the event scheduler
 */

/* Bypass FIB and send packet one by one */
//#define BYPASS_FIB 1

/* Send packets one by one : only effective if FIB is not bypassed */
//#define USE_SEND_PACKET 1

/* Batch sending: only if the previous option is undefined */
#define USE_QUEUE true

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
//#include <hicn/hicn-light/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "connection_table.h"
#include "fib.h"
#include "forwarder.h"
#include "listener_table.h"
#ifdef WITH_MAPME
#include "mapme.h"
#endif /* WITH_MAPME */
#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "packet_cache.h"
#include "../config/configuration.h"
// #include "../config/configuration_file.h"
#include "../config/commands.h"
#include "../io/base.h"  // MAX_MSG

#ifdef WITH_POLICY_STATS
#include <hicn/core/policy_stats.h>
#endif /* WITH_POLICY_STATS */

#include <hicn/core/wldr.h>
#include <hicn/core/interest_manifest.h>
#include <hicn/util/log.h>

typedef struct {
  // Packets processed
  uint32_t countReceived;  // Interest and data only
  uint32_t countInterestsReceived;
  uint32_t countObjectsReceived;

  // Packets Dropped
  uint32_t countDropped;
  uint32_t countInterestsDropped;
  uint32_t countObjectsDropped;
  uint32_t countOtherDropped;

  // Forwarding
  uint32_t countInterestForwarded;
  uint32_t countObjectsForwarded;

  // Errors while forwarding
  uint32_t countDroppedConnectionNotFound;
  uint32_t countSendFailures;
  uint32_t countDroppedNoRoute;

  // Interest processing
  uint32_t countInterestsAggregated;
  uint32_t countInterestsRetransmitted;
  uint32_t countInterestsSatisfiedFromStore;
  uint32_t countInterestsExpired;
  uint32_t countDataExpired;

  // Data processing
  uint32_t countDroppedNoReversePath;

  // TODO(eloparco): Currently not used
  // uint32_t countDroppedNoHopLimit;
  // uint32_t countDroppedZeroHopLimitFromRemote;
  // uint32_t countDroppedZeroHopLimitToRemote;
} forwarder_stats_t;

struct forwarder_s {
  //    uint16_t server_port;

  // used by seed48 and nrand48
  unsigned short seed[3];

  connection_table_t *connection_table;
  listener_table_t *listener_table;
  configuration_t *config;

  pkt_cache_t *pkt_cache;
  fib_t *fib;
  msgbuf_pool_t *msgbuf_pool;

#ifdef WITH_MAPME
  mapme_t *mapme;
#endif /* WITH_MAPME */

  bool store_in_cs;
  bool serve_from_cs;

  forwarder_stats_t stats;
#ifdef WITH_POLICY_STATS
  policy_stats_mgr_t policy_stats_mgr;
#endif /* WITH_POLICY_STATS */

  /*
   * The message forwarder has to decide whether to queue incoming packets for
   * batching, or trigger the transmission on the connection
   */
  unsigned *pending_conn;

  subscription_table_t *subscriptions;

  // Used to store the msgbufs that need to be released
  off_t *acquired_msgbuf_ids;
};

/**
 * Reseed our pseudo-random number generator.
 */
static void forwarder_seed(forwarder_t *forwarder) {
#ifndef _WIN32
  int fd;
  ssize_t res;

  res = -1;
  fd = open("/dev/urandom", O_RDONLY);
  if (fd != -1) {
    res = read(fd, forwarder->seed, sizeof(forwarder->seed));
    close(fd);
  }
  if (res != sizeof(forwarder->seed)) {
    forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
    forwarder->seed[2] = (unsigned short)time(NULL);
  }
  /*
   * The call to seed48 is needed by cygwin, and should be harmless
   * on other platforms.
   */
  seed48(forwarder->seed);
#else
  forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
  forwarder->seed[2] = (unsigned short)time(NULL);
#endif
}

forwarder_t *forwarder_create(configuration_t *configuration) {
  forwarder_t *forwarder = malloc(sizeof(forwarder_t));
  if (!forwarder) goto ERR_MALLOC;

  forwarder_seed(forwarder);
  srand(forwarder->seed[0] ^ forwarder->seed[1] ^ forwarder->seed[2]);

  forwarder->config = configuration;

  forwarder->listener_table = listener_table_create();
  if (!forwarder->listener_table) goto ERR_LISTENER_TABLE;

  forwarder->connection_table = connection_table_create();
  if (!forwarder->connection_table) goto ERR_CONNECTION_TABLE;

  forwarder->fib = fib_create(forwarder);
  if (!forwarder->fib) goto ERR_FIB;

  forwarder->msgbuf_pool = msgbuf_pool_create();
  if (!forwarder->msgbuf_pool) goto ERR_PACKET_POOL;

  size_t objectStoreSize = configuration_get_cs_size(configuration);
  forwarder->pkt_cache = pkt_cache_create(objectStoreSize);
  if (!forwarder->pkt_cache) goto ERR_PKT_CACHE;

  forwarder->subscriptions = subscription_table_create();
  if (!forwarder->subscriptions) goto ERR_SUBSCRIPTION;

  // the two flags for the cs are set to true by default. If the cs
  // is active it always work as expected unless the use modifies this
  // values using controller
  if (objectStoreSize != 0) {
    forwarder->store_in_cs = true;
    forwarder->serve_from_cs = true;
  }

#ifdef WITH_MAPME
  forwarder->mapme = mapme_create(forwarder);
  if (!forwarder->mapme) goto ERR_MAPME;
#endif /* WITH_MAPME */

#ifdef WITH_POLICY_STATS
  if (policy_stats_mgr_initialize(&forwarder->policy_stats_mgr, forwarder) < 0)
    goto ERR_MGR;
#endif /* WITH_POLICY_STATS */

  memset(&forwarder->stats, 0, sizeof(forwarder_stats_t));
  vector_init(forwarder->pending_conn, MAX_MSG, 0);
  vector_init(forwarder->acquired_msgbuf_ids, MAX_MSG, 0);

  return forwarder;

ERR_MGR:
#ifdef WITH_MAPME
ERR_MAPME:
#endif /* WITH_MAPME */

ERR_SUBSCRIPTION:
  subscription_table_free(forwarder->subscriptions);
ERR_PKT_CACHE:
  pkt_cache_free(forwarder->pkt_cache);

  msgbuf_pool_free(forwarder->msgbuf_pool);
ERR_PACKET_POOL:
  fib_free(forwarder->fib);
ERR_FIB:
  connection_table_free(forwarder->connection_table);
ERR_CONNECTION_TABLE:
  listener_table_free(forwarder->listener_table);
ERR_LISTENER_TABLE:
  free(forwarder);
ERR_MALLOC:
  return NULL;
}

void forwarder_free(forwarder_t *forwarder) {
  assert(forwarder);

  policy_stats_mgr_finalize(&forwarder->policy_stats_mgr);

#ifdef WITH_MAPME
  mapme_free(forwarder->mapme);
#endif /* WITH_MAPME */

  pkt_cache_free(forwarder->pkt_cache);
  msgbuf_pool_free(forwarder->msgbuf_pool);
  fib_free(forwarder->fib);
  connection_table_free(forwarder->connection_table);
  listener_table_free(forwarder->listener_table);
  subscription_table_free(forwarder->subscriptions);
  configuration_free(forwarder->config);
  vector_free(forwarder->pending_conn);
  vector_free(forwarder->acquired_msgbuf_ids);
  free(forwarder);
}

void forwarder_setup_local_listeners(forwarder_t *forwarder, uint16_t port) {
  assert(forwarder);
  listener_setup_local(forwarder, port);
}

configuration_t *forwarder_get_configuration(forwarder_t *forwarder) {
  assert(forwarder);
  return forwarder->config;
}

subscription_table_t *forwarder_get_subscriptions(forwarder_t *forwarder) {
  return forwarder->subscriptions;
}

connection_table_t *forwarder_get_connection_table(
    const forwarder_t *forwarder) {
  assert(forwarder);
  return forwarder->connection_table;
}

listener_table_t *forwarder_get_listener_table(forwarder_t *forwarder) {
  assert(forwarder);
  return forwarder->listener_table;
}

void forwarder_cs_set_store(forwarder_t *forwarder, bool val) {
  assert(forwarder);
  forwarder->store_in_cs = val;
}

bool forwarder_cs_get_store(forwarder_t *forwarder) {
  assert(forwarder);
  return forwarder->store_in_cs;
}

void forwarder_cs_set_serve(forwarder_t *forwarder, bool val) {
  assert(forwarder);
  forwarder->serve_from_cs = val;
}

bool forwarder_cs_get_serve(forwarder_t *forwarder) {
  assert(forwarder);
  return forwarder->serve_from_cs;
}

void forwarder_cs_set_size(forwarder_t *forwarder, size_t size) {
  assert(forwarder);

  if (pkt_cache_set_cs_size(forwarder->pkt_cache, size) < 0) {
    ERROR(
        "Unable to resize the CS: provided maximum size (%u) is smaller than "
        "the number of elements currently stored in the CS (%u). Clear the CS "
        "and retry.",
        size, pkt_cache_get_cs_size(forwarder->pkt_cache));
  }
}

size_t forwarder_cs_get_size(forwarder_t *forwarder) {
  assert(forwarder);
  return pkt_cache_get_cs_size(forwarder->pkt_cache);
}

size_t forwarder_cs_get_num_stale_entries(forwarder_t *forwarder) {
  assert(forwarder);
  return pkt_cache_get_num_cs_stale_entries(forwarder->pkt_cache);
}

void forwarder_cs_clear(forwarder_t *forwarder) {
  assert(forwarder);

  pkt_cache_cs_clear(forwarder->pkt_cache);
}

/**
 * @function forwarder_Drop
 * @abstract Whenever we "drop" a message, increment counters
 * @discussion
 *   This is a bookkeeping function.  It increments the appropriate counters.
 *
 *   The default action for a message is to destroy it in
 * <code>forwarder_Receive()</code>, so this function does not need to do
 * that.
 *
 */
static ssize_t forwarder_drop(forwarder_t *forwarder, off_t msgbuf_id) {
  forwarder->stats.countDropped++;

  const msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  const msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  switch (msgbuf_get_type(msgbuf)) {
    case MSGBUF_TYPE_INTEREST:
      forwarder->stats.countInterestsDropped++;
      break;

    case MSGBUF_TYPE_DATA:
      forwarder->stats.countObjectsDropped++;
      break;

    default:
      forwarder->stats.countOtherDropped++;
      break;
  }

  return msgbuf_get_len(msgbuf);
  // dont destroy message here, its done at end of receive
}

#ifndef BYPASS_FIB
/*
 *   If the hoplimit is equal to 0, then we may only forward it to local
 * applications.  Otherwise, we may forward it off the system.
 *
 */

static ssize_t forwarder_forward_via_connection(forwarder_t *forwarder,
                                                off_t msgbuf_id,
                                                unsigned conn_id) {
  connection_table_t *table = forwarder_get_connection_table(forwarder);

  const msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  const connection_t *conn = connection_table_get_by_id(table, conn_id);

  if (!conn) {
    forwarder->stats.countDroppedConnectionNotFound++;
    WARN("forward msgbuf %lu to interface %u not found (count %u)", msgbuf_id,
         conn_id, forwarder->stats.countDroppedConnectionNotFound);
    return forwarder_drop(forwarder, msgbuf_id);
  }

  /* Always queue the packet... */
  // DEBUG("Queueing packet\n");

#if defined(USE_SEND_PACKET) || !defined(__linux__)

  // Here we need to update the path label of a data packet before send
  // it. The path label update can be done here because the packet is sent
  // directly to the socket
  if (msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA)
    msgbuf_update_pathlabel(msgbuf, connection_get_id(conn));

  bool success = connection_send_packet(conn, msgbuf_get_packet(msgbuf),
                                        msgbuf_get_len(msgbuf));
#else

  // In this case we cannot update the path label even if it is need because
  // the packet is not copied and only the packet id is enqueued to the ring
  // buffer associated the output interface. If the path label is updated here
  // all data packets get delivered to the next hop with the same label that is
  // associated to the last connection used. For this reason the path label
  // update must be done before the packet is actually sent inside the different
  // IO implementations.
  bool success = connection_send(conn, msgbuf_id, USE_QUEUE);

#endif

  /* ... and mark the connection as pending if this is not yet the case */
  if (!vector_contains(forwarder->pending_conn, conn_id))
    vector_push(forwarder->pending_conn, conn_id);

  if (!success) {
    forwarder->stats.countSendFailures++;

    DEBUG("forward msgbuf %llu to interface %u send failure (count %u)",
          msgbuf_id, conn_id, forwarder->stats.countSendFailures);
    return forwarder_drop(forwarder, msgbuf_id);
  }

  switch (msgbuf_get_type(msgbuf)) {
    case MSGBUF_TYPE_INTEREST:
      forwarder->stats.countInterestForwarded++;
      break;

    case MSGBUF_TYPE_DATA:
      forwarder->stats.countObjectsForwarded++;
      break;

    default:
      break;
  }

  TRACE("forward msgbuf %p (size=%u) to interface %u", msgbuf,
        msgbuf_get_len(msgbuf), conn_id);
  return msgbuf_get_len(msgbuf);
}

/**
 * @function forwarder_forward_to_nexthops
 * @abstract Try to forward to each nexthop listed in the NumberSet
 * @discussion
 *   Will not forward to the ingress connection.
 *
 * @return The number of nexthops tried
 */
static unsigned forwarder_forward_to_nexthops(forwarder_t *forwarder,
                                              off_t msgbuf_id,
                                              const nexthops_t *nexthops) {
  // DEBUG("[forwarder_forward_to_nexthops] num=%d/%d",
  // nexthops_get_curlen(nexthops), nexthops_get_len(nexthops));
  unsigned forwardedCopies = 0;

  const msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  unsigned ingressId = msgbuf_get_connection_id(msgbuf);

  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
    // DEBUG("[forwarder_forward_to_nexthops]  - nexthop = %d");
    if (nexthop == ingressId) continue;

    forwardedCopies++;
    // INFO("[forwarder_forward_to_nexthops]  - nexthop = %d OK", nexthop);
    forwarder_forward_via_connection(forwarder, msgbuf_id, nexthop);
  });

  return forwardedCopies;
}

static bool forwarder_forward_via_fib(forwarder_t *forwarder, off_t msgbuf_id,
                                      pkt_cache_verdict_t verdict,
                                      pkt_cache_entry_t *entry,
                                      bool is_aggregated) {
  assert(forwarder);
  assert(msgbuf_id_is_valid(msgbuf_id));

  const msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

  fib_entry_t *fib_entry = fib_match_message(forwarder->fib, msgbuf);
  if (!fib_entry) return false;

  // DEBUG("[forwarder] Getting nexthops from strategy");
  nexthops_t *nexthops = fib_entry_get_nexthops_from_strategy(
      fib_entry, msgbuf, verdict == PKT_CACHE_VERDICT_RETRANSMIT_INTEREST);

  if (nexthops_get_curlen(nexthops) == 0) {
    ERROR("Message %p returned an empty next hop set", msgbuf);
    return false;
  }

  pit_entry_t *pit_entry = &entry->u.pit_entry;
  if (!pit_entry) return false;

  pit_entry_set_fib_entry(pit_entry, fib_entry);

  // this requires some additional checks. It may happen that some of the output
  // faces selected by the forwarding strategy are not usable. So far all the
  // forwarding strategy return only valid faces (or an empty list)
  unsigned nexthop;
  nexthops_foreach(nexthops, nexthop, {
    // DEBUG("Adding egress to PIT for nexthop %d", nexthop);
    pit_entry_egress_add(pit_entry, nexthop);
  });

  // Forwarding is done separately for aggregated interests
  if (is_aggregated) return true;

  if (forwarder_forward_to_nexthops(forwarder, msgbuf_id, nexthops) <= 0) {
    // this should never happen
    ERROR("Message %p returned an empty next hop set", msgbuf);
    return false;
  }

  return true;
}

#endif /* ! BYPASS_FIB */

ssize_t _forwarder_forward_upon_interest(
    forwarder_t *forwarder, msgbuf_pool_t *msgbuf_pool, off_t data_msgbuf_id,
    off_t interest_msgbuf_id, pkt_cache_entry_t *entry,
    pkt_cache_verdict_t verdict, bool is_aggregated) {
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, interest_msgbuf_id);

  if (verdict == PKT_CACHE_VERDICT_AGGREGATE_INTEREST) {
    // the packet shuold not be forwarder
    forwarder_drop(forwarder, interest_msgbuf_id);
    return msgbuf_get_len(msgbuf);
  }

  // - Forward reply if a data packet matching the interest was found
  if (verdict == PKT_CACHE_VERDICT_FORWARD_DATA) {
    assert(forwarder->serve_from_cs == true);

    msgbuf_t *interest_msgbuf = msgbuf_pool_at(msgbuf_pool, interest_msgbuf_id);
    msgbuf_t *data_msgbuf = msgbuf_pool_at(msgbuf_pool, data_msgbuf_id);

    msgbuf_reset_pathlabel(data_msgbuf);

    forwarder_forward_via_connection(forwarder, data_msgbuf_id,
                                     msgbuf_get_connection_id(interest_msgbuf));

    // - Try to forward the interest
  } else if (!forwarder_forward_via_fib(forwarder, interest_msgbuf_id, verdict,
                                        entry, is_aggregated)) {
    forwarder->stats.countDroppedNoRoute++;
    INFO("Message %lu did not match FIB, no route (count %u)",
         interest_msgbuf_id, forwarder->stats.countDroppedNoRoute);

    // - Drop the packet (no forwarding)
    forwarder_drop(forwarder, interest_msgbuf_id);
    return -1;
  }

  return msgbuf_get_len(msgbuf);
}

static void _forwarder_update_interest_stats(forwarder_t *forwarder,
                                             pkt_cache_verdict_t verdict,
                                             msgbuf_t *msgbuf,
                                             bool has_expire_ts,
                                             uint64_t expire_ts) {
  long expiration = has_expire_ts ? expire_ts : -1;
  switch (verdict) {
    case PKT_CACHE_VERDICT_FORWARD_INTEREST:
      DEBUG("Message added to PIT (expiration=%ld)", expiration);
      break;

    case PKT_CACHE_VERDICT_AGGREGATE_INTEREST:
      forwarder->stats.countInterestsAggregated++;
      DEBUG("Message aggregated in PIT (expiration=%ld)", expiration);
      break;

    case PKT_CACHE_VERDICT_RETRANSMIT_INTEREST:
      forwarder->stats.countInterestsRetransmitted++;
      DEBUG("Message retransmitted (expiration=%ld)", expiration);
      break;

    case PKT_CACHE_VERDICT_FORWARD_DATA:
      forwarder->stats.countInterestsSatisfiedFromStore++;
      DEBUG("Message satisfied from content store (expiration=%ld)",
            expiration);
      break;

    case PKT_CACHE_VERDICT_INTEREST_EXPIRED_FORWARD_INTEREST:
      forwarder->stats.countInterestsExpired++;
      DEBUG("Message replaced expired interest (expiration=%ld)", expiration);
      break;

    case PKT_CACHE_VERDICT_DATA_EXPIRED_FORWARD_INTEREST:
      forwarder->stats.countDataExpired++;
      DEBUG("Message replaced expired data (expiration=%ld)", expiration);
      break;

    case PKT_CACHE_VERDICT_ERROR:
      ERROR("Invalid packet cache content");
      break;

    default:
      break;
  }
}

static interest_manifest_header_t *_forwarder_get_interest_manifest(
    msgbuf_t *msgbuf) {
  uint8_t *packet = msgbuf_get_packet(msgbuf);
  hicn_header_t *header = (hicn_header_t *)packet;
  hicn_type_t type = hicn_header_to_type(header);

  hicn_payload_type_t payload_type;
  int rc = hicn_ops_vft[type.l1]->get_payload_type(type, &header->protocol,
                                                   &payload_type);
  _ASSERT(rc == HICN_LIB_ERROR_NONE);
  if (payload_type != HPT_MANIFEST) return NULL;

  size_t header_length, payload_length;
  rc = hicn_ops_vft[type.l1]->get_header_length(type, &header->protocol,
                                                &header_length);
  assert(rc == HICN_LIB_ERROR_NONE);

  rc = hicn_ops_vft[type.l1]->get_payload_length(type, &header->protocol,
                                                 &payload_length);
  assert(rc == HICN_LIB_ERROR_NONE);

  u8 *payload = (u8 *)header + header_length;
  interest_manifest_header_t *int_manifest_header =
      (interest_manifest_header_t *)payload;
  if (!interest_manifest_is_valid(int_manifest_header, payload_length))
    return NULL;

  return int_manifest_header;
}

// Manifest is split using splitting strategy, then every
// sub-manifest is sent using the forwarding strategy defined for the prefix
int _forwarder_forward_aggregated_interest(
    forwarder_t *forwarder, interest_manifest_header_t *int_manifest_header,
    int n_suffixes_to_fwd, msgbuf_t *msgbuf, off_t msgbuf_id) {
  fib_entry_t *fib_entry = fib_match_message(forwarder->fib, msgbuf);
  assert(fib_entry);
  nexthops_t *nexthops =
      fib_entry_get_nexthops_from_strategy(fib_entry, msgbuf, false);

  switch (disaggregation_strategy) {
    case INT_MANIFEST_SPLIT_NONE: {
      if (forwarder_forward_to_nexthops(forwarder, msgbuf_id, nexthops) <= 0) {
        ERROR("Message %p returned an empty next hop set", msgbuf);
        return -1;
      }

      return msgbuf_get_len(msgbuf);
    }

    case INT_MANIFEST_SPLIT_MAX_N_SUFFIXES: {
      // Generate sub-manifests: same as original manifest,
      // but different suffix in the header and different bitmap

      int total_len = 0;
      // Suffixes in manifest plus the one in the header
      int total_suffixes = int_manifest_header->n_suffixes + 1;

      // Save copy of original bitmap to use as a reference
      // to generate bitmaps for sub-manifests
      u32 original_bitmap[BITMAP_SIZE] = {0};
      memcpy(&original_bitmap, int_manifest_header->request_bitmap,
             BITMAP_SIZE * sizeof(u32));

      int pos = 0;
      while (pos < total_suffixes) {
        // If more than one sub-manifest,
        // clone original interest manifest and update suffix
        if (pos > 0) {
          msgbuf_t *clone;
          off_t clone_id =
              msgbuf_pool_clone(forwarder->msgbuf_pool, &clone, msgbuf_id);
          msgbuf_pool_acquire(clone);
          forwarder_acquired_msgbuf_ids_push(forwarder, clone_id);

          msgbuf_id = clone_id;
          msgbuf = clone;
        }

        u32 curr_bitmap[BITMAP_SIZE] = {0};
        pos = interest_manifest_update_bitmap(original_bitmap, curr_bitmap, pos,
                                              total_suffixes,
                                              N_SUFFIXES_PER_SPIT);

        // Update manifest bitmap in current msgbuf
        interest_manifest_header_t *manifest =
            _forwarder_get_interest_manifest(msgbuf);
        assert(manifest != NULL);
        memcpy(manifest->request_bitmap, curr_bitmap,
               BITMAP_SIZE * sizeof(u32));

        if (forwarder_forward_to_nexthops(forwarder, msgbuf_id, nexthops) <=
            0) {
          ERROR("Message %p returned an empty next hop set", msgbuf);
          continue;
        }

        total_len += msgbuf_get_len(msgbuf);
      }

      return total_len;
    }

    default:
      return -1;
  }
}

/**
 * @function forwarder_process_interest
 * @abstract Receive an interest from the network
 * @discussion
 *   (1) if interest in the PIT, aggregate in PIT
 *   (2) if interest in the ContentStore, reply
 *   (3) if in the FIB, forward
 *   (4) drop
 *
 */
static ssize_t forwarder_process_interest(forwarder_t *forwarder,
                                          off_t msgbuf_id) {
  assert(forwarder);
  assert(msgbuf_id_is_valid(msgbuf_id));

  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

  u32 n_suffixes = 0;
  interest_manifest_header_t *int_manifest_header =
      _forwarder_get_interest_manifest(msgbuf);
  if (int_manifest_header) n_suffixes = int_manifest_header->n_suffixes;

  forwarder->stats.countReceived += 1 + n_suffixes;
  forwarder->stats.countInterestsReceived += 1 + n_suffixes;
  WITH_DEBUG({
    char *nameString = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG("INTEREST (%s) suffixes=%u msgbuf_id=%lu ingress=%u length=%u",
          nameString, n_suffixes, msgbuf_id, msgbuf_get_connection_id(msgbuf),
          msgbuf_get_len(msgbuf));
    free(nameString);
  })

  int pos = 0;  // Position of current suffix in manifest
  int n_suffixes_to_fwd = 0;
  u32 *suffix = NULL;
  if (int_manifest_header) suffix = (u32 *)(int_manifest_header + 1);
  u32 seq = name_GetSegment(msgbuf_get_name(msgbuf));
  pkt_cache_verdict_t verdict = PKT_CACHE_VERDICT_ERROR;
  off_t data_msgbuf_id = INVALID_MSGBUF_ID;
  pkt_cache_entry_t *entry = NULL;

  Name name_copy = EMPTY_NAME;
  name_Copy(msgbuf_get_name(msgbuf), &name_copy);

  // Cache suffixes for current prefix to (possibly) avoid double lookups
  pkt_cache_save_suffixes_for_prefix(forwarder->pkt_cache,
                                     name_GetContentName(&name_copy));

  while (true) {
    if (int_manifest_header &&
        !is_bit_set(int_manifest_header->request_bitmap, pos))
      goto NEXT_SUFFIX;

    // Update packet cache
    pkt_cache_on_interest(forwarder->pkt_cache, msgbuf_pool, msgbuf_id,
                          &verdict, &data_msgbuf_id, &entry, &name_copy,
                          forwarder->serve_from_cs);
    _forwarder_update_interest_stats(forwarder, verdict, msgbuf,
                                     entry->has_expire_ts, entry->expire_ts);

    // Interest forwarding is performed only for single interests,
    // otherwise '_forwarder_forward_aggregated_interest()' is used
    int rc = (int)_forwarder_forward_upon_interest(
        forwarder, msgbuf_pool, data_msgbuf_id, msgbuf_id, entry, verdict,
        int_manifest_header != NULL);

    // No route when trying to forward interest, remove from PIT
    if (rc == -1)
      pkt_cache_pit_remove_entry(forwarder->pkt_cache, entry, &name_copy);

    if (int_manifest_header) {
      // Unset in bitmap if no interest forwarding needed,
      // otherwise increase count of suffixes to forward
      if (rc == -1 || verdict == PKT_CACHE_VERDICT_AGGREGATE_INTEREST ||
          verdict == PKT_CACHE_VERDICT_FORWARD_DATA) {
        unset_bit(int_manifest_header->request_bitmap, pos);
      } else {
        n_suffixes_to_fwd++;
      }
    }

  NEXT_SUFFIX:
    if (pos++ >= n_suffixes) break;

    // Use next segment in manifest
    seq = *suffix;
    suffix++;
    name_SetSegment(&name_copy, seq);

    WITH_DEBUG({
      char *nameString = name_ToString(&name_copy);
      DEBUG("Next in manifest: %s", nameString);
      free(nameString);
    })
  }

  // Return if single interest (i.e. no manifest)
  // or nothing in the manifest to forward
  if (!int_manifest_header || n_suffixes_to_fwd == 0)
    return msgbuf_get_len(msgbuf);

  return _forwarder_forward_aggregated_interest(
      forwarder, int_manifest_header, n_suffixes_to_fwd, msgbuf, msgbuf_id);
}

static void _forwarder_log_on_data(forwarder_t *forwarder,
                                   pkt_cache_verdict_t verdict) {
  switch (verdict) {
    case PKT_CACHE_VERDICT_FORWARD_DATA:
      DEBUG("Message added to CS from PIT");
      break;
    case PKT_CACHE_VERDICT_STORE_DATA:
      DEBUG("Message added to CS (expired or no previous interest pending)");
      break;
    case PKT_CACHE_VERDICT_CLEAR_DATA:
      break;
    case PKT_CACHE_VERDICT_UPDATE_DATA:
      DEBUG("Message updated in CS");
      break;
    case PKT_CACHE_VERDICT_IGNORE_DATA:
      DEBUG("Message not stored in CS");
      break;
    case PKT_CACHE_VERDICT_ERROR:
      ERROR("Invalid packet cache content");
      break;
    default:
      break;
  }
}

/**
 * @function forwarder_process_data
 * @abstract Process an in-bound content object
 * @discussion
 *   (1) If it does not match anything in the PIT, drop it
 *   (2) Add to Content Store
 *   (3) Reverse path forward via PIT entries
 *
 * @param <#param1#>
 */
static ssize_t forwarder_process_data(forwarder_t *forwarder, off_t msgbuf_id) {
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  WITH_DEBUG({
    char *nameString = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG("DATA (%s) msgbuf_id=%lu ingress=%u length=%u", nameString, msgbuf_id,
          msgbuf_get_connection_id(msgbuf), msgbuf_get_len(msgbuf));
    free(nameString);
  )}

  forwarder->stats.countReceived++;
  forwarder->stats.countObjectsReceived++;

  const connection_table_t *table = forwarder_get_connection_table(forwarder);
  const connection_t *conn =
      connection_table_get_by_id(table, msgbuf_get_connection_id(msgbuf));

  // Cache suffixes for current prefix to (possibly) avoid double lookups
  pkt_cache_save_suffixes_for_prefix(forwarder->pkt_cache,
   name_GetContentName(msgbuf_get_name(msgbuf)));

  pkt_cache_verdict_t verdict = PKT_CACHE_VERDICT_ERROR;
  bool wrong_egress;
  nexthops_t *ingressSetUnion =
      pkt_cache_on_data(forwarder->pkt_cache, msgbuf_pool, msgbuf_id,
                        forwarder->store_in_cs, connection_is_local(conn), &wrong_egress, &verdict);

  _forwarder_log_on_data(forwarder, verdict);

  if (wrong_egress) {  // Interest sent via a connection but received from another
    WARN("Data coming from unexpected connection, discarded");
  } else if (!ingressSetUnion) {  // No match in the PIT
    forwarder->stats.countDroppedNoReversePath++;
    DEBUG("Message %lu did not match PIT, no reverse path", msgbuf_id);

    // MOVE PROBE HOOK ELSEWHERE
    // XXX relationship with forwarding strategy... insert hooks
    // if the packet is a probe we need to analyze it
    // NOTE : probes are not stored in PIT
    if (msgbuf_is_probe(msgbuf)) {
      fib_entry_t *entry = fib_match_message(forwarder->fib, msgbuf);
      if (entry && fib_entry_strategy_type(entry) == STRATEGY_TYPE_BESTPATH) {
        nexthops_t probe_nexthops = NEXTHOPS_EMPTY;
        nexthops_add(&probe_nexthops, msgbuf_get_connection_id(msgbuf));
        fib_entry_on_data(entry, &probe_nexthops, msgbuf, 0, ticks_now());
        // XXX TODO CONFIRM WE DON'T EXIT HERE ?
      }
    }
    forwarder_drop(forwarder, msgbuf_id);
  } else {
    // Reverse path forward via PIT entries
    forwarder_forward_to_nexthops(forwarder, msgbuf_id, ingressSetUnion);
    free(ingressSetUnion);
  }

  return msgbuf_get_len(msgbuf);
}

void forwarder_flush_connections(forwarder_t *forwarder) {
  // DEBUG("[forwarder_flush_connections]");
  const connection_table_t *table = forwarder_get_connection_table(forwarder);

  for (unsigned i = 0; i < vector_len(forwarder->pending_conn); i++) {
    unsigned conn_id = forwarder->pending_conn[i];
    const connection_t *conn = connection_table_at(table, conn_id);
    if (!connection_flush(conn)) {
      WARN("Could not flush connection queue");
      // XXX keep track of non flushed connections...
    }
  }
  vector_reset(forwarder->pending_conn);
  // DEBUG("[forwarder_flush_connections] done");
}

// XXX move to wldr file, worst case in connection.
void forwarder_apply_wldr(const forwarder_t *forwarder, const msgbuf_t *msgbuf,
                          connection_t *connection) {
  // this are the checks needed to implement WLDR. We set wldr only on the STAs
  // and we let the AP to react according to choice of the client.
  // if the STA enables wldr using the set command, the AP enable wldr as well
  // otherwise, if the STA disable it the AP remove wldr
  // WLDR should be enabled only on the STAs using the command line
  // TODO
  // disable WLDR command line on the AP
  if (msgbuf_has_wldr(msgbuf)) {
    if (connection_has_wldr(connection)) {
      // case 1: WLDR is enabled
      connection_wldr_detect_losses(connection, msgbuf);
    } else if (!connection_has_wldr(connection) &&
               connection_wldr_autostart_is_allowed(connection)) {
      // case 2: We are on an AP. We enable WLDR
      connection_wldr_enable(connection, true);
      connection_wldr_detect_losses(connection, msgbuf);
    }
    // case 3: Ignore WLDR
  } else {
    if (connection_has_wldr(connection) &&
        connection_wldr_autostart_is_allowed(connection)) {
      // case 1: STA do not use WLDR, we disable it
      connection_wldr_enable(connection, false);
    }
  }
}

bool forwarder_add_or_update_route(forwarder_t *forwarder, ip_prefix_t *prefix,
                                   unsigned ingress_id) {
  assert(forwarder);
  assert(prefix);

  configuration_t *config = forwarder_get_configuration(forwarder);

  char prefix_s[MAXSZ_IP_PREFIX];
  int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, prefix);
  assert(rc < MAXSZ_IP_PREFIX);
  if (rc < 0) return false;

  DEBUG("Adding prefix=%s for conn_id=%d", prefix_s, ingress_id);

  // XXX TODO this should store options too
  strategy_type_t strategy_type = configuration_get_strategy(config, prefix_s);

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, prefix->family, prefix->address,
                         prefix->len);
  fib_entry_t *entry = fib_contains(forwarder->fib, &name_prefix);
  if (!entry) {
    entry = fib_entry_create(&name_prefix, strategy_type, NULL, forwarder);
    fib_entry_nexthops_add(entry, ingress_id);
    fib_add(forwarder->fib, entry);

  } else {
    fib_entry_nexthops_add(entry, ingress_id);
  }

  return true;
}

bool forwarder_remove_route(forwarder_t *forwarder, ip_prefix_t *prefix,
                            unsigned ingress_id) {
  assert(forwarder);
  assert(prefix);

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, prefix->family, prefix->address,
                         prefix->len);
  fib_remove(forwarder->fib, &name_prefix, ingress_id);

  return true;
}

#ifdef WITH_POLICY

bool forwarder_add_or_update_policy(forwarder_t *forwarder, ip_prefix_t *prefix,
                                    hicn_policy_t *policy) {
  assert(forwarder);
  assert(prefix);
  assert(policy);

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, prefix->family, prefix->address,
                         prefix->len);
  fib_entry_t *entry = fib_contains(forwarder->fib, &name_prefix);
  if (!entry) return false;
  fib_entry_set_policy(entry, *policy);

  return true;
}

bool forwarder_remove_policy(forwarder_t *forwarder, ip_prefix_t *prefix) {
  assert(forwarder);
  assert(prefix);

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, prefix->family, prefix->address,
                         prefix->len);
  fib_entry_t *entry = fib_contains(forwarder->fib, &name_prefix);

  if (!entry) return false;

  fib_entry_set_policy(entry, POLICY_EMPTY);

  return true;
}

#endif /* WITH_POLICY */

void forwarder_remove_connection_id_from_routes(forwarder_t *forwarder,
                                                unsigned connection_id) {
  assert(forwarder);

  fib_remove_connection_id(forwarder->fib, connection_id);
}

void forwarder_add_strategy_options(forwarder_t *forwarder, Name *name_prefix,
                                    strategy_type_t strategy_type,
                                    strategy_options_t *strategy_options) {
  assert(forwarder);
  assert(name_prefix);
  assert(strategy_options);
  assert(STRATEGY_TYPE_VALID(strategy_type));

  fib_entry_t *entry = fib_contains(forwarder->fib, name_prefix);
  if (!entry) return;

  fib_entry_add_strategy_options(entry, strategy_type, strategy_options);
}

void forwarder_set_strategy(forwarder_t *forwarder, Name *name_prefix,
                            strategy_type_t strategy_type,
                            strategy_options_t *strategy_options) {
  assert(forwarder);
  assert(name_prefix);
  assert(STRATEGY_TYPE_VALID(strategy_type));
  /* strategy_options might be NULL */

  fib_entry_t *entry = fib_contains(forwarder->fib, name_prefix);
  if (!entry) {
    // there is no exact match. so if the forwarding strategy is not in the list
    // of strategies that can be set by the transport, return
    if (strategy_type != STRATEGY_TYPE_BESTPATH &&
        strategy_type != STRATEGY_TYPE_REPLICATION) {
      return;
    }

    // here it may be the transprot that wants to set the strategy, but it has
    // no knowledge of the length of the prefix. so we apply the strategy at the
    // matching fib entry, which later will be the one that will be used to send
    // interests with this name
    entry = fib_match_name(forwarder->fib, name_prefix);
    if (!entry) {
      return;  // no fib match, return
    }
  }

  fib_entry_set_strategy(entry, strategy_type, strategy_options);
}

cs_t *forwarder_get_cs(const forwarder_t *forwarder) {
  assert(forwarder);

  return pkt_cache_get_cs(forwarder->pkt_cache);
}

// IMPORTANT: Use this function ONLY for read-only operations since a realloc
// would otherwise modify the returned copy but not the original msgbuf ids
// vector in the forwarder. This constraint cannot be enforced by returning a
// (const off_t *) because the vector_t macros still cast to (void **).
off_t *forwarder_get_acquired_msgbuf_ids(const forwarder_t *forwarder) {
  return forwarder->acquired_msgbuf_ids;
}

void forwarder_acquired_msgbuf_ids_reset(const forwarder_t *forwarder) {
  vector_reset(forwarder->acquired_msgbuf_ids);
}

void forwarder_acquired_msgbuf_ids_push(const forwarder_t *forwarder,
                                        off_t msgbuf_id) {
  vector_push(forwarder->acquired_msgbuf_ids, msgbuf_id);
}

// =======================================================

fib_t *forwarder_get_fib(forwarder_t *forwarder) { return forwarder->fib; }

msgbuf_pool_t *forwarder_get_msgbuf_pool(const forwarder_t *forwarder) {
  return forwarder->msgbuf_pool;
}

#ifdef WITH_MAPME
void forwarder_on_connection_event(const forwarder_t *forwarder,
                                   const connection_t *connection,
                                   connection_event_t event) {
  mapme_on_connection_event(forwarder->mapme, connection, event);
}

mapme_t *forwarder_get_mapme(const forwarder_t *forwarder) {
  return forwarder->mapme;
}

#endif /* WITH_MAPME */

#ifdef WITH_POLICY_STATS
const policy_stats_mgr_t *forwarder_get_policy_stats_mgr(
    const forwarder_t *forwarder) {
  return &forwarder->policy_stats_mgr;
}
#endif /* WITH_POLICY_STATS */

/**
 * @brief Process a packet by creating the corresponding message buffer and
 * dispatching it to the forwarder for further processing.
 * @param[in] forwarder Forwarder instance.
 *
 */
// XXX ??? XXX = process for listener as we are resolving connection id
//

msgbuf_type_t get_type_from_packet(uint8_t *packet) {
  if (messageHandler_IsTCP(packet)) {
    if (messageHandler_IsData(packet)) {
      return MSGBUF_TYPE_DATA;
    } else if (messageHandler_IsInterest(packet)) {
      return MSGBUF_TYPE_INTEREST;
    } else {
      return MSGBUF_TYPE_UNDEFINED;
    }

  } else if (messageHandler_IsWldrNotification(packet)) {
    return MSGBUF_TYPE_WLDR_NOTIFICATION;

  } else if (mapme_match_packet(packet)) {
    return MSGBUF_TYPE_MAPME;

  } else if (*packet == REQUEST_LIGHT) {
    return MSGBUF_TYPE_COMMAND;

  } else {
    return MSGBUF_TYPE_UNDEFINED;
  }
}

/**
 * @brief Finalize (i.e. close fd and free internal data structures)
 * the current connection ("SELF") when the command is received.
 * The connection cannot be removed inside the command handling
 * because it is needed to return the ack back.
 */
static void _forwarder_finalize_connection_if_self(connection_t *conn,
                                                   msgbuf_t *msgbuf) {
  uint8_t *packet = msgbuf_get_packet(msgbuf);
  msg_connection_remove_t *msg = (msg_connection_remove_t *)packet;
  cmd_connection_remove_t *control = &msg->payload;

  if (strcmp(control->symbolic_or_connid, "SELF") == 0)
    connection_finalize(conn);
}

ssize_t forwarder_receive(forwarder_t *forwarder, listener_t *listener,
                          off_t msgbuf_id, address_pair_t *pair, Ticks now) {
  assert(forwarder);
  /* listener can be NULL */
  assert(msgbuf_id_is_valid(msgbuf_id));
  assert(pair);

  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  assert(msgbuf);

  uint8_t *packet = msgbuf_get_packet(msgbuf);
  size_t size = msgbuf_get_len(msgbuf);

  /* Connection lookup */
  const connection_table_t *table =
      forwarder_get_connection_table(listener->forwarder);
  connection_t *connection = connection_table_get_by_pair(table, pair);
  unsigned conn_id = connection ? (unsigned)connection_table_get_connection_id(
                                      table, connection)
                                : CONNECTION_ID_UNDEFINED;

  assert((conn_id != CONNECTION_ID_UNDEFINED) || listener);

  msgbuf_type_t type = get_type_from_packet(msgbuf_get_packet(msgbuf));

  msgbuf->type = type;
  msgbuf->connection_id = conn_id;
  msgbuf->recv_ts = now;

  switch (type) {
    case MSGBUF_TYPE_INTEREST:
      if (!connection_id_is_valid(msgbuf->connection_id)) {
        char conn_name[SYMBOLIC_NAME_LEN];
        int rc = connection_table_get_random_name(table, conn_name);
        if (rc < 0) return 0;

        unsigned connection_id =
            listener_create_connection(listener, conn_name, pair);
        msgbuf->connection_id = connection_id;
        connection = connection_table_get_by_id(table, connection_id);
      }
      msgbuf->path_label = 0;  // not used for interest packets
      name_create_from_interest(packet, msgbuf_get_name(msgbuf));
      forwarder_apply_wldr(forwarder, msgbuf, connection);
      forwarder_process_interest(forwarder, msgbuf_id);

      pkt_cache_log(forwarder->pkt_cache);
      return size;

    case MSGBUF_TYPE_DATA:
      if (!connection_id_is_valid(msgbuf->connection_id))
        return forwarder_drop(forwarder, msgbuf_id);
      msgbuf_init_pathlabel(msgbuf);
      name_create_from_data(packet, msgbuf_get_name(msgbuf));
      forwarder_apply_wldr(forwarder, msgbuf, connection);
      forwarder_process_data(forwarder, msgbuf_id);

      pkt_cache_log(forwarder->pkt_cache);
      return size;

    case MSGBUF_TYPE_WLDR_NOTIFICATION:
      if (!connection_id_is_valid(msgbuf->connection_id))
        return forwarder_drop(forwarder, msgbuf_id);
      connection_wldr_handle_notification(connection, msgbuf);
      return size;

    case MSGBUF_TYPE_MAPME:
      // XXX what about acks ?
      if (!connection_id_is_valid(msgbuf->connection_id)) {
        char conn_name[SYMBOLIC_NAME_LEN];
        int rc = connection_table_get_random_name(table, conn_name);
        if (rc < 0) return 0;

        msgbuf->connection_id =
            listener_create_connection(listener, conn_name, pair);
      }
      mapme_process(forwarder->mapme, msgbuf);
      return size;

    case MSGBUF_TYPE_COMMAND:
      // Create the connection to send the ack back
      if (!connection_id_is_valid(msgbuf->connection_id)) {
        char conn_name[SYMBOLIC_NAME_LEN];
        int rc = connection_table_get_random_name(table, conn_name);
        if (rc < 0) return 0;

        unsigned connection_id =
            listener_create_connection(listener, conn_name, pair);
        msgbuf->connection_id = connection_id;
        connection = connection_table_get_by_id(table, connection_id);
      }

      msg_header_t *msg = (msg_header_t *)packet;
      msgbuf->command.type = msg->header.command_id;
      if (!command_type_is_valid(msgbuf->command.type)) {
        ERROR("Invalid command");
        return 0;
      }

      size = command_process_msgbuf(forwarder, msgbuf);
      if (msgbuf->command.type == COMMAND_TYPE_CONNECTION_REMOVE)
        _forwarder_finalize_connection_if_self(connection, msgbuf);
      return size;

    default:
      ERROR("Invalid msgbuf type");
      forwarder_drop(forwarder, msgbuf_id);
      return 0;
  }
}

void forwarder_log(forwarder_t *forwarder) {
  DEBUG(
      "Forwarder: received = %u (interest = %u, data = %u), dropped = %u "
      "(interest = %u, data = %u, other = %u), forwarded = { interests = %u, "
      "data = %u }, dropped = { connection_not_found = %u, send_failure = %u, "
      "no_route_in_fib = %u }, interest processing = { aggregated = %u, "
      "retransmitted = %u, satisfied_from_cs = %u, expired_interests = %u, "
      "expired_data = %u }, data processing = { "
      "no_reverse_path = %u }\n",
      forwarder->stats.countReceived, forwarder->stats.countInterestsReceived,
      forwarder->stats.countObjectsReceived, forwarder->stats.countDropped,
      forwarder->stats.countInterestsDropped,
      forwarder->stats.countObjectsDropped, forwarder->stats.countOtherDropped,
      forwarder->stats.countInterestForwarded,
      forwarder->stats.countObjectsForwarded,
      forwarder->stats.countDroppedConnectionNotFound,
      forwarder->stats.countSendFailures, forwarder->stats.countDroppedNoRoute,
      forwarder->stats.countInterestsAggregated,
      forwarder->stats.countInterestsRetransmitted,
      forwarder->stats.countInterestsSatisfiedFromStore,
      forwarder->stats.countInterestsExpired, forwarder->stats.countDataExpired,
      forwarder->stats.countDroppedNoReversePath);
}
