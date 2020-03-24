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

#ifndef __HICN_STRATEGY_DPO_CTX_H__
#define __HICN_STRATEGY_DPO_CTX_H__

#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>

#include "params.h"
#include "faces/face.h"

//FIB table for hicn. 0 is the default one used by ip
#define HICN_FIB_TABLE 10

#define NEXT_HOP_INVALID ~0

#define INIT_SEQ 0

/**
 * @brief Definition of the general hICN DPO ctx (shared among all the strategies).
 *
 * An hICN DPO ctx contains the list of next hops, auxiliaries fields to maintain the dpo, map-me
 * specifics (tfib_entry_count and seq), the dpo_type and 64B to let each strategy to store additional
 * information. Each next hop is a dpo_id_t that refers to an hICN face. The dpo_type is used to
 * identify the strategy and to retrieve the vft corresponding to the strategy (see strategy.h)
 * and to the dpo ctx (see strategy_dpo_manager.h)
 */
typedef struct __attribute__ ((packed)) hicn_dpo_ctx_s
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* 4B*10 = 40B */
  hicn_face_id_t next_hops[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
  /* 40B + 4B = 44B */
  u32 locks;
  /* 44B + 1B = 45B */
  u8 entry_count;
  /* 45B + 1B = 46B */
  /* Number of TFIB entries (stored at the end of the next_hops array */
  u8 tfib_entry_count;

  dpo_type_t dpo_type;

  /* 46B + 2B = 48B */
  u8 padding;			/* To align to 8B */

  /* 48 + 4B = 52; last sequence number */
  u32 seq;

  /* 52 + 12 = 64 */
  fib_node_t fib_node;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  fib_node_index_t fib_entry_index;

  u32 fib_sibling;

  union
  {
    u32 padding_proto;
    fib_protocol_t proto;
  };

  u8 data[CLIB_CACHE_LINE_BYTES - 12];

} hicn_dpo_ctx_t;

extern hicn_dpo_ctx_t *hicn_strategy_dpo_ctx_pool;

/**
 * @brief Initialize the hICN dpo ctx
 *
 * @param dpo_ctx Pointer to the hICN dpo ctx to initialize
 * @param next_hop List of netx hops to store in the dpo ctx
 * @param nh_len Number of elements in the list of next hops
 * @param dpo_type Type of dpo. It identifies the strategy.
 */
always_inline void
init_dpo_ctx (hicn_dpo_ctx_t * dpo_ctx, const hicn_face_id_t * next_hop,
	      int nh_len, dpo_type_t dpo_type, dpo_proto_t proto)
{
  hicn_face_id_t invalid = NEXT_HOP_INVALID;

  dpo_ctx->entry_count = 0;
  dpo_ctx->locks = 0;

  dpo_ctx->tfib_entry_count = 0;

  dpo_ctx->seq = INIT_SEQ;
  dpo_ctx->dpo_type = dpo_type;

  dpo_ctx->proto = proto;

  for (int i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX && i < nh_len; i++)
    {
      dpo_ctx->next_hops[i] = next_hop[i];
      dpo_ctx->entry_count++;
    }


  for (int i = nh_len; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; i++)
    {
      dpo_ctx->next_hops[i] = invalid;
    }

}

/**
 * @brief Initialize the pool containing the hICN dpo ctx
 *
 */
void hicn_strategy_init_dpo_ctx_pool (void);

/**
 * @brief Allocate a new hICN dpo ctx from the pool
 */
hicn_dpo_ctx_t *hicn_strategy_dpo_ctx_alloc ();

/**
 * @brief Retrieve an existing hICN dpo ctx from the pool
 */
hicn_dpo_ctx_t *hicn_strategy_dpo_ctx_get (index_t index);

/**
 * @brief Retrieve the index of the hICN dpo ctx
 */
index_t hicn_strategy_dpo_ctx_get_index (hicn_dpo_ctx_t * cd);

/**
 * @brief Lock the dpo of a strategy ctx
 *
 * @param dpo Identifier of the dpo of the strategy ctx
 */
void hicn_strategy_dpo_ctx_lock (dpo_id_t * dpo);

/**
 * @brief Unlock the dpo of a strategy ctx
 *
 * @param dpo Identifier of the dpo of the strategy ctx
 */
void hicn_strategy_dpo_ctx_unlock (dpo_id_t * dpo);

/**
 * @brief Add or update a next hop in the dpo ctx.
 *
 * This function is meant to be used in the control plane and not in the data plane,
 * as it is not optimized for the latter.
 *
 * @param nh Next hop to insert in the dpo ctx
 * @param dpo_ctx Dpo ctx to update with the new or updated next hop
 * @param pos Return the position of the nh that has been added
 * @return HICN_ERROR_NONE if the update or insert was fine,
 * otherwise HICN_ERROR_DPO_CTX_NOT_FOUND
 */
int
hicn_strategy_dpo_ctx_add_nh (hicn_face_id_t nh, hicn_dpo_ctx_t * dpo_ctx,
			      u8 * pos);

/**
 * @brief Delete a next hop in the dpo ctx.
 *
 * @param face_id Face identifier of the next hop
 * @param dpo_ctx Dpo ctx to update by removing the face
 * @return HICN_ERROR_NONE if the update or insert was fine,
 * otherwise HICN_ERROR_DPO_CTS_NOT_FOUND
 */
int
hicn_strategy_dpo_ctx_del_nh (hicn_face_id_t face_id,
			      hicn_dpo_ctx_t * dpo_ctx);


STATIC_ASSERT (sizeof (hicn_dpo_ctx_t) <= 2 * CLIB_CACHE_LINE_BYTES,
	       "sizeof hicn_dpo_ctx_t is greater than 128B");

#endif /* // __HICN_STRATEGY_DPO_CTX_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
