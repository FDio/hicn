/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * A strategy is defined as a dpo and a set of function (vft) that will be called
 * during the packet processing. A strategy is associated to an entry in the fib by
 * assigning the corresponding dpo to the fib entry. The dpo points to a hICN dpo
 * context (ctx) which contains the information needed by the strategy to compute
 * the next hop. Each strategy hash its own dpo type, which means that the dpo_type
 * uniquely identify a strategy and its vft. The strategy node will use the dpo_type
 * to retrieve the corresponding vft.
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
				 hicn_face_id_t* outface);
  u8 *(*hicn_format_strategy_trace) (u8 *, hicn_strategy_trace_t *);
  u8 *(*hicn_format_strategy) (u8 * s, va_list * ap);
  /**< Format an hICN dpo*/
} hicn_strategy_vft_t;

typedef enum
{
  HICN_STRATEGY_NEXT_INTEREST_HITPIT,
  HICN_STRATEGY_NEXT_INTEREST_HITCS,
  HICN_STRATEGY_NEXT_INTEREST_FACE4,
  HICN_STRATEGY_NEXT_INTEREST_FACE6,
  HICN_STRATEGY_NEXT_ERROR_DROP,
  HICN_STRATEGY_N_NEXT,
} hicn_strategy_next_t;

extern vlib_node_registration_t hicn_strategy_node;

#endif /* //__HICN_STRATEGY__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
