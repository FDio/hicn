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
 * \file stats.c
 * \brief Implementation of stats.
 */

#include <hicn/ctrl/api.h>
#include <hicn/util/log.h>

#include "../object_vft.h"

/* GENERAL STATS */

int _hc_stats_validate(const hc_object_t *object, bool allow_partial) {
  // Nothing to validate
  return 0;
}

int _hc_stats_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  ERROR("[_hc_stats_cmp] Not implemented");
  return -1;
}

int _hc_stats_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_stats_snprintf(s, size, &object->stats);
}

int hc_stats_snprintf(char *s, size_t size, const hc_stats_t *stats) {
  return snprintf(
      s, size,
      "*** STATS ***\nreceived = %u (interest = %u, data = %u)\ndropped = %u "
      "(interest = %u, data = %u, other = %u)\nforwarded = { interests = "
      "%u, data = %u }\ndropped_reason = { connection_not_found = %u, "
      "send_failure = %u, no_route_in_fib = %u }\ninterest processing = { "
      "aggregated = %u, retransmitted = %u, satisfied_from_cs = %u, "
      "expired_interests = %u, expired_data = %u }\ndata processing = { "
      "no_reverse_path = %u }\npacket cache = {PIT size = %u, CS size = %u, "
      "eviction = %u}",
      stats->forwarder.countReceived, stats->forwarder.countInterestsReceived,
      stats->forwarder.countObjectsReceived, stats->forwarder.countDropped,
      stats->forwarder.countInterestsDropped,
      stats->forwarder.countObjectsDropped, stats->forwarder.countOtherDropped,
      stats->forwarder.countInterestForwarded,
      stats->forwarder.countObjectsForwarded,
      stats->forwarder.countDroppedConnectionNotFound,
      stats->forwarder.countSendFailures, stats->forwarder.countDroppedNoRoute,
      stats->forwarder.countInterestsAggregated,
      stats->forwarder.countInterestsRetransmitted,
      stats->forwarder.countInterestsSatisfiedFromStore,
      stats->forwarder.countInterestsExpired, stats->forwarder.countDataExpired,
      stats->forwarder.countDroppedNoReversePath,
      stats->pkt_cache.n_pit_entries, stats->pkt_cache.n_cs_entries,
      stats->pkt_cache.n_lru_evictions);
}

int hc_stats_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_STATS, NULL, pdata);
}

DECLARE_OBJECT_OPS(OBJECT_TYPE_STATS, stats);

/* PER-FACE STATS */

int _hc_face_stats_validate(const hc_object_t *object, bool allow_partial) {
  // Nothing to validate
  return 0;
}

int _hc_face_stats_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  ERROR("[_hc_stats_cmp] Not implemented");
  return -1;
}

int _hc_face_stats_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_face_stats_snprintf(s, size, &object->face_stats);
}

int hc_face_stats_snprintf(char *s, size_t size, const hc_face_stats_t *stats) {
  return snprintf(
      s, size,
      "conn #%u:\tinterests =\t{ rx packets = %u, rx bytes = %u,  "
      "tx packets = %u,  tx bytes = %u }\n\t\tdata =\t\t{ rx packets "
      "= %u, rx bytes = %u,  "
      "tx packets = %u,  tx bytes = %u }",
      stats->conn_id, stats->interests.rx_pkts, stats->interests.rx_bytes,
      stats->interests.tx_pkts, stats->interests.tx_bytes, stats->data.rx_pkts,
      stats->data.rx_bytes, stats->data.tx_pkts, stats->data.tx_bytes);
}

int hc_face_stats_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_FACE_STATS, NULL, pdata);
}

DECLARE_OBJECT_OPS(OBJECT_TYPE_FACE_STATS, face_stats);