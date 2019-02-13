/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __IETF_HICN_H__
#define __IETF_HICN_H__

#include "../hicn_vpp_comm.h"

#define MEM_ALIGN 4096


typedef struct __attribute__ ((__packed__)) {

  int32_t retval;
  uint64_t pkts_processed;
  uint64_t pkts_interest_count;
  uint64_t pkts_data_count;
  uint64_t pkts_from_cache_count;
  uint64_t pkts_no_pit_count;
  uint64_t pit_expired_count;
  uint64_t cs_expired_count;
  uint64_t cs_lru_count;
  uint64_t pkts_drop_no_buf;
  uint64_t interests_aggregated;
  uint64_t interests_retx;
  uint64_t interests_hash_collision;
  uint64_t pit_entries_count;
  uint64_t cs_entries_count;
  uint64_t cs_entries_ntw_count;

} hicn_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint8_t description[200];
  int32_t retval;
} hicn_strategy_t;


typedef struct __attribute__ ((__packed__)) {

  uint8_t n_strategies;
  uint32_t strategy_id[256];
  int32_t retval;
} hicn_strategies_t;

typedef struct __attribute__ ((__packed__)) {
  uint16_t faceids[1000];
  uint32_t strategy_id;
  int32_t retval;
} hicn_route_t;

typedef struct __attribute__ ((__packed__)) {
  int32_t retval;
  uint64_t nh_addr[2];
  uint32_t swif;
  uint32_t flags;
} hicn_face_ip_params_t;

int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription);

#endif /* __IETF_HICN_H__ */