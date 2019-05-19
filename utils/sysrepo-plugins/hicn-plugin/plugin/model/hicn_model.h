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
#define B32 4
#define B64 8

// Number of locks is equal to number of nodes in hicn-state
// It is a coarse grain approach later can be changed to fine grained
// better to initialize the lock by 0
#define NLOCKS 5
#define LOCK_INIT 0


enum locks_name {lstate, lstrategy, lstrategies, lroute, lfaces};

#define NSTATE_LEAVES 15
#define NSTRATEGY_LEAVES 1
#define NSTRATEGIES_LEAVES 2
#define NROUTE_LEAVES 2
#define MAX_FACE_POOL 200
#define FACES_CHILDREN 9 /*this is the number of children of each leave*/


#define  params_send( msg , resp ) \
{  \
 if (VAPI_OK != vapi_send(g_vapi_ctx_instance, (msg))) {  \
   SRP_LOG_DBG_MSG("Sending msg to VPP failed"); \
   return SR_ERR_OPERATION_FAILED; \
 }   \
 HICN_VPP_VAPI_RECV;   \
};

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
 uint32_t faceids[1000];
 uint32_t strategy_id;
 int32_t retval;
} hicn_route_t;

typedef struct __attribute__ ((__packed__)) {
 uint64_t nh_addr[2];
 uint32_t swif;
 uint32_t flags;
 int32_t retval;
} hicn_face_ip_params_t;

typedef struct __attribute__ ((__packed__)) {
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


struct  hicn_faces_s{
 hicn_face_inf_t face;
 struct hicn_faces_s * next;
};

typedef struct  __attribute__ ((__packed__)) {
 uint32_t nface;
 struct hicn_faces_s * next;
} hicn_faces_t;

// typedef struct __attribute__ ((__packed__)) {
//   int32_t retval;
//   uint32_t faceid;
//   uint64_t irx_packets;
//   uint64_t irx_bytes;
//   uint64_t itx_packets;
//   uint64_t itx_bytes;
//   uint64_t drx_packets;
//   uint64_t drx_bytes;
//   uint64_t dtx_packets;
//   uint64_t dtx_bytes;
// } hicn_face_stat_t;

// typedef struct __attribute__ ((__packed__)) {

//   int32_t retval;
//   uint32_t faceid;
//   uint64_t irx_packets;
//   uint64_t irx_bytes;
//   uint64_t itx_packets;
//   uint64_t itx_bytes;
//   uint64_t drx_packets;
//   uint64_t drx_bytes;
//   uint64_t dtx_packets;
//   uint64_t dtx_bytes;

// } hicn_state_face_t;


int hicn_subscribe_events(sr_session_ctx_t *session,
                         sr_subscription_ctx_t **subscription);

#endif /* __IETF_HICN_H__ */
