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

#include "dpo_lr.h"
#include "../strategy.h"
#include "../strategy_dpo_ctx.h"
#include "../faces/face.h"
#include "../strategy_dpo_manager.h"

/* Simple strategy that forwards intertests to all next hops */
/* It does not require to exend the hicn_dpo */
void hicn_receive_data_lr (index_t dpo_idx, int nh_idx);
void hicn_add_interest_lr (index_t dpo_idx);
int hicn_send_after_aggregation_lr (index_t dpo_idx, hicn_face_id_t in_face);
void hicn_on_interest_timeout_lr (index_t dpo_idx);
u32 hicn_select_next_hop_lr (index_t dpo_idx, hicn_face_id_t in_face,
			     hicn_face_id_t *outfaces, u16 *len);
u8 *hicn_strategy_format_trace_lr (u8 *s, hicn_strategy_trace_t *t);
u8 *hicn_strategy_format_lr (u8 *s, va_list *ap);

static hicn_strategy_vft_t hicn_strategy_lr_vft = {
  .hicn_receive_data = &hicn_receive_data_lr,
  .hicn_add_interest = &hicn_add_interest_lr,
  .hicn_send_after_aggregation = &hicn_send_after_aggregation_lr,
  .hicn_on_interest_timeout = &hicn_on_interest_timeout_lr,
  .hicn_select_next_hop = &hicn_select_next_hop_lr,
  .hicn_format_strategy_trace = &hicn_strategy_format_trace_lr,
  .hicn_format_strategy = &hicn_strategy_format_lr
};

/*
 * Return the vft of the strategy.
 */
hicn_strategy_vft_t *
hicn_lr_strategy_get_vft (void)
{
  return &hicn_strategy_lr_vft;
}

/* DPO should be given in input as it containes all the information to
 * calculate the next hops*/
u32
hicn_select_next_hop_lr (index_t dpo_idx, hicn_face_id_t in_face,
			 hicn_face_id_t *outfaces, u16 *len)
{
  hicn_dpo_ctx_t *dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);

  *len = 0;

  if (dpo_ctx == NULL || dpo_ctx->entry_count == 0)
    {
      return HICN_ERROR_STRATEGY_NOT_FOUND;
    }

  // Check if input face is local face
  int in_is_local = hicn_face_is_local (in_face);

  int i = 0;
  while (i < MAX_OUT_FACES && i < dpo_ctx->entry_count)
    {
      if (hicn_face_is_local (dpo_ctx->next_hops[i]) != in_is_local)
	{
	  outfaces[0] = dpo_ctx->next_hops[i];
	  *len = 1;
	  break;
	}

      i++;
    }

  return HICN_ERROR_NONE;
}

void
hicn_add_interest_lr (index_t dpo_ctx_idx)
{
  /* Nothing to do */
}

int
hicn_send_after_aggregation_lr (index_t dpo_idx, hicn_face_id_t in_face)
{
  // Do not aggregate
  return true;
}

void
hicn_on_interest_timeout_lr (index_t dpo_idx)
{
  /* Nothing to do in the lr strategy when we receive an interest */
}

void
hicn_receive_data_lr (index_t dpo_idx, int nh_idx)
{
  /* nothing to do */
}

/* packet trace format function */
u8 *
hicn_strategy_format_trace_lr (u8 *s, hicn_strategy_trace_t *t)
{
  s = format (s,
	      "Strategy_lr: pkt: %d, sw_if_index %d, next index %d, dpo_type "
	      "%d, out_face %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index, t->dpo_type,
	      t->out_face);
  return (s);
}

u8 *
hicn_strategy_format_lr (u8 *s, va_list *ap)
{

  u32 indent = va_arg (*ap, u32);
  s = format (
    s, "Local-Remote: send from local face to remote only and viceversa \n",
    indent);
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
