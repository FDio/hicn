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

#include "dpo_rr.h"
#include "strategy_rr.h"
#include "../strategy_dpo_manager.h"
#include "../strategy_dpo_ctx.h"

/**
 * @brief DPO type value for the rr_strategy
 */
static dpo_type_t hicn_dpo_type_rr;

static const hicn_dpo_vft_t hicn_dpo_rr_vft = {
  .hicn_dpo_is_type = &hicn_dpo_is_type_strategy_rr,
  .hicn_dpo_get_type = &hicn_dpo_strategy_rr_get_type,
  .hicn_dpo_module_init = &hicn_dpo_strategy_rr_module_init,
  .hicn_dpo_create = &hicn_strategy_rr_ctx_create,
  .hicn_dpo_add_update_nh = &hicn_strategy_rr_ctx_add_nh,
  .hicn_dpo_del_nh = &hicn_strategy_rr_ctx_del_nh,
  .hicn_dpo_format = &hicn_strategy_rr_format_ctx
};

int
hicn_dpo_is_type_strategy_rr (const dpo_id_t * dpo)
{
  return dpo->dpoi_type == hicn_dpo_type_rr;
}

void
hicn_dpo_strategy_rr_module_init (void)
{
  /*
   * Register our type of dpo
   */
  hicn_dpo_type_rr =
    hicn_dpo_register_new_type (hicn_nodes_strategy, &hicn_dpo_rr_vft,
				hicn_rr_strategy_get_vft (),
				&dpo_strategy_rr_ctx_vft);
}

dpo_type_t
hicn_dpo_strategy_rr_get_type (void)
{
  return hicn_dpo_type_rr;
}

//////////////////////////////////////////////////////////////////////////////////////////////////


u8 *
hicn_strategy_rr_format_ctx (u8 * s, int n, ...)
{
  va_list args;
  va_start (args, n);
  s = format_hicn_strategy_rr_ctx (s, &args);
  return s;
}

u8 *
format_hicn_strategy_rr_ctx (u8 * s, va_list * ap)
{
  int i = 0;
  index_t index = va_arg (*ap, index_t);
  hicn_dpo_ctx_t *dpo_ctx = NULL;
  hicn_strategy_rr_ctx_t *rr_dpo_ctx = NULL;
  u32 indent = va_arg (*ap, u32);

  dpo_ctx = hicn_strategy_dpo_ctx_get (index);
  if (dpo_ctx == NULL)
    return s;

  rr_dpo_ctx = (hicn_strategy_rr_ctx_t *) dpo_ctx->data;

  s =
    format (s, "hicn-rr, next hop Face %d",
	    dpo_ctx->next_hops[rr_dpo_ctx->current_nhop]);

  for (i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; i++)
    {
      u8 *buf = NULL;
      if (i < dpo_ctx->entry_count)
	buf = format (NULL, "FIB");
      else if (i >=
	       HICN_PARAM_FIB_ENTRY_NHOPS_MAX - dpo_ctx->tfib_entry_count)
	buf = format (NULL, "TFIB");
      else
	continue;

      s = format (s, "\n");
      s =
        format (s, "%U ", format_hicn_face, dpo_ctx->next_hops[i],
                indent);
      s = format (s, " %s", buf);
    }

  return (s);
}

void
hicn_strategy_rr_ctx_create (fib_protocol_t proto, const hicn_face_id_t * next_hop,
			     int nh_len, index_t * dpo_idx)
{
  hicn_strategy_rr_ctx_t *hicn_strategy_rr_ctx;
  hicn_dpo_ctx_t *hicn_strategy_ctx;

  /* Allocate a hicn_dpo_ctx on the vpp pool and initialize it */
  hicn_strategy_ctx = hicn_strategy_dpo_ctx_alloc ();
  hicn_strategy_rr_ctx = (hicn_strategy_rr_ctx_t *) hicn_strategy_ctx->data;

  *dpo_idx = hicn_strategy_dpo_ctx_get_index (hicn_strategy_ctx);

  init_dpo_ctx (hicn_strategy_ctx, next_hop, nh_len, hicn_dpo_type_rr, proto);

  hicn_strategy_rr_ctx->current_nhop = 0;
}

int
hicn_strategy_rr_ctx_add_nh (hicn_face_id_t nh, index_t dpo_idx)
{
  hicn_dpo_ctx_t *hicn_strategy_dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);
  u8 pos = 0;

  if (hicn_strategy_dpo_ctx == NULL)
    {
      return HICN_ERROR_STRATEGY_NOT_FOUND;
    }

  hicn_strategy_dpo_ctx_add_nh (nh, hicn_strategy_dpo_ctx, &pos);
  //nothing else to initialize in this strategy
  return HICN_ERROR_NONE;
}

int
hicn_strategy_rr_ctx_del_nh (hicn_face_id_t face_id, index_t dpo_idx)
{
  hicn_dpo_ctx_t *hicn_strategy_dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);
  //No need to change the current_nhop. It will be updated at the next selection.
  return hicn_strategy_dpo_ctx_del_nh (face_id, hicn_strategy_dpo_ctx);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
