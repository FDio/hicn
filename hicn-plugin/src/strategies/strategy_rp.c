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

#include "dpo_rp.h"
#include "../strategy.h"
#include "../strategy_dpo_ctx.h"
#include "../faces/face.h"
#include "../hashtb.h"
#include "../strategy_dpo_manager.h"

/* Simple strategy that forwards intertests to all next hops */
/* It does not require to exend the hicn_dpo */
void hicn_receive_data_rp (index_t dpo_idx, int nh_idx);
void hicn_add_interest_rp (index_t dpo_idx, hicn_hash_entry_t *pit_entry);
void hicn_on_interest_timeout_rp (index_t dpo_idx);
u32 hicn_select_next_hop_rp (index_t dpo_idx, int *nh_idx,
			     hicn_face_id_t *outfaces, uint32_t *len);
u8 *hicn_strategy_format_trace_rp (u8 *s, hicn_strategy_trace_t *t);
u8 *hicn_strategy_format_rp (u8 *s, va_list *ap);

static hicn_strategy_vft_t hicn_strategy_rp_vft = {
  .hicn_receive_data = &hicn_receive_data_rp,
  .hicn_add_interest = &hicn_add_interest_rp,
  .hicn_on_interest_timeout = &hicn_on_interest_timeout_rp,
  .hicn_select_next_hop = &hicn_select_next_hop_rp,
  .hicn_format_strategy_trace = &hicn_strategy_format_trace_rp,
  .hicn_format_strategy = &hicn_strategy_format_rp
};

/*
 * Return the vft of the strategy.
 */
hicn_strategy_vft_t *
hicn_rp_strategy_get_vft (void)
{
  return &hicn_strategy_rp_vft;
}

/* DPO should be give in input as it containes all the information to calculate
 * the next hops*/
u32
hicn_select_next_hop_rp (index_t dpo_idx, int *nh_idx,
			 hicn_face_id_t *outfaces, uint32_t *len)
{
  hicn_dpo_ctx_t *dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);

  if (dpo_ctx == NULL || dpo_ctx->entry_count == 0)
    {
      *len = 0;
      return HICN_ERROR_STRATEGY_NOT_FOUND;
    }

  int i = 0;
  while (i < MAX_OUT_FACES && i < dpo_ctx->entry_count)
    {
      outfaces[i] = dpo_ctx->next_hops[i];
      i++;
    }
  *len = i;

  return HICN_ERROR_NONE;
}

void
hicn_add_interest_rp (index_t dpo_ctx_idx, hicn_hash_entry_t *hash_entry)
{
  /* Nothing to do */
}

void
hicn_on_interest_timeout_rp (index_t dpo_idx)
{
  /* Nothing to do in the rp strategy when we receive an interest */
}

void
hicn_receive_data_rp (index_t dpo_idx, int nh_idx)
{
  /* nothing to do */
}

/* packet trace format function */
u8 *
hicn_strategy_format_trace_rp (u8 *s, hicn_strategy_trace_t *t)
{
  s = format (s, "Strategy_rp: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

u8 *
hicn_strategy_format_rp (u8 *s, va_list *ap)
{

  u32 indent = va_arg (*ap, u32);
  s = format (s, "Replication: send to all the next hops \n", indent);
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
