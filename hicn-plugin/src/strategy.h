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

#ifndef __HICN_STRATEGY__
#define __HICN_STRATEGY__

#include "hicn.h"
#include "hashtb.h"
#include "mgmt.h"
#include "faces/face.h"

/**
 * @File
 *
 * A strategy is defined as a vpp node and a set of function that will be called
 * during the packet processing. Having one vpp node per strategy allows to
 * easily process multiple interests in the same node (x2 or x4) and call the
 * same function for choosing the next hop.
 * Here we provide:
 * - a template for the callbacks to implement in order to create a new strategy
 *   (hicn_fwd_strategy_t)
 * - the base structure for a strategy node
 *   (list of next vpp nodes, errors, tracing and the main function processing an
 *    interest and calling hicn_select_next_hop)
 */

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  dpo_type_t dpo_type;
} hicn_strategy_trace_t;

typedef struct hicn_strategy_vft_s
{
  void (*hicn_receive_data) (index_t dpo_idx, int nh_idx);
  void (*hicn_on_interest_timeout) (index_t dpo_idx);
  void (*hicn_add_interest) (index_t dpo_idx, hicn_hash_entry_t * pit_entry);
  u32 (*hicn_select_next_hop) (index_t dpo_idx, int *nh_idx,
                               dpo_id_t ** outface);
  u8 * (*hicn_format_strategy) (u8 *, hicn_strategy_trace_t *);
} hicn_strategy_vft_t;

hicn_face_vft_t *hicn_strategy_get_face_vft (u16 index);

/* Strategy node API */
/* Basic interest processing function. To be called in all the strategy nodes */
/* uword */
/* hicn_forward_interest_fn (vlib_main_t * vm, */
/* 			  vlib_node_runtime_t * node, */
/* 			  vlib_frame_t * frame, */
/* 			  hicn_strategy_vft_t * strategy, */
/* 			  dpo_type_t dpo_type, */
/* 			  vlib_node_registration_t * hicn_strategy_node); */

typedef enum
{
  HICN_STRATEGY_NEXT_INTEREST_HITPIT,
  HICN_STRATEGY_NEXT_INTEREST_HITCS,
  HICN_STRATEGY_NEXT_ERROR_DROP,
  HICN_STRATEGY_NEXT_EMPTY,
  HICN_STRATEGY_N_NEXT,
} hicn_strategy_next_t;

extern vlib_node_registration_t hicn_strategy_node;

#endif /* //__HICN_STRATEGY__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
