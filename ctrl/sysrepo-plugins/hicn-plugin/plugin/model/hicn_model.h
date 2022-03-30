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
 * @file hicn_model.h
 * @brief This file contains main calls for hICN events coresponding to the hICN
 * yang models
 */

#ifndef __IETF_HICN_H__
#define __IETF_HICN_H__

#include "../hicn_vpp_comm.h"
#include <vapi/hicn.api.vapi.h>

/**
 * @brief Align memory to one page boundary
 */
#define MEM_ALIGN 4096

/**
 * @brief 32 bits = 4 bytes
 */
#define B32 4
/**
 * @brief 64bits = 8 bytes
 */
#define B64 8
/**
 * @brief 128 bits = 16 bytes
 */
#define B128 16

/**
 * @brief set number of lock to 5
 */
#define NLOCKS 5

/**
 * @brief initialize all locks by 0, better to initialize by 0 :)
 */
#define LOCK_INIT 0

/**
 * @brief enumeration for the locks
 */
enum locks_name { lstate, lstrategy, lstrategies, lroute, lfaces };

// It is a coarse grain approach later can be changed to fine grained

/**
 * @brief This indicates the number of leaves for the hICN state
 */
#define NSTATE_LEAVES 15
/**
 * @brief This indicates the number of leaves for strategy
 */
#define NSTRATEGY_LEAVES 1
/**
 * @brief This indicates the number of leaves for strategies
 */
#define NSTRATEGIES_LEAVES 2
/**
 * @brief This indicates the maximum faces which can be read as operational data
 */
#define MAX_FACE_POOL 100
/**
 * @brief This indicates the  maximum routes which can be read as operational
 * data
 */
#define MAX_ROUTE_POOL 100
/**
 * @brief This indicates the number of leaves for faces
 */
#define FACES_CHILDREN \
  9 /*this is the number of children of each leave in face except the key*/
/**
 * @brief This indicates the number of leaves for routes
 */
#define ROUTES_CHILDREN \
  2 /*this is the number of children of each leave in face except the key*/

typedef struct __attribute__((__packed__)) {
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

typedef struct __attribute__((__packed__)) {
  uint8_t n_strategies;
  uint32_t strategy_id[256];
  int32_t retval;
} hicn_strategies_t;

typedef struct __attribute__((__packed__)) {
  uint32_t faceid;
  uint32_t intfc;
  uint64_t irx_packets;
  uint64_t irx_bytes;
  uint64_t itx_packets;
  uint64_t itx_bytes;
  uint64_t drx_packets;
  uint64_t drx_bytes;
  uint64_t dtx_packets;
  uint64_t dtx_bytes;
} hicn_face_inf_t;

typedef struct __attribute__((__packed__)) {
  u32 route_id;
  vapi_type_prefix prefix;
  u32 faceids[5];
  u8 nfaces;
  u32 strategy_id;
} hicn_route_inf_t;

/**
 * @brief This is the link list to maintain the statistics of the faces
 */
struct hicn_faces_s {
  hicn_face_inf_t face;
  struct hicn_faces_s *next;
};

typedef struct __attribute__((__packed__)) {
  uint32_t nface;
  struct hicn_faces_s *next;
} hicn_faces_t;

/**
 * @brief This is the link list to maintain the route informations
 */
struct hicn_routes_s {
  hicn_route_inf_t route;
  struct hicn_routes_s *next;
};

typedef struct __attribute__((__packed__)) {
  uint32_t nroute;
  struct hicn_routes_s *next;
} hicn_routes_t;

/**
 * @brief This function subscribes the hICN evens consisting of all RPCs
 * as well as operational data
 */
int hicn_subscribe_events(sr_session_ctx_t *session,
                          sr_subscription_ctx_t **subscription);

#endif /* __IETF_HICN_H__ */
