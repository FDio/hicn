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

#include "../strategy_dpo_ctx.h"
#include "dpo_mw.h"
#include "strategy_mw.h"
#include "../strategy_dpo_manager.h"

hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx_pool;

const static char *const hicn_ip6_nodes[] = {
  "hicn-iface-ip6-input",		// this is the name you give your node in VLIB_REGISTER_NODE
  NULL,
};

const static char *const hicn_ip4_nodes[] = {
  "hicn-iface-ip4-input",		// this is the name you give your node in VLIB_REGISTER_NODE
  NULL,
};

const static char *const *const hicn_nodes_mw[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = hicn_ip6_nodes,
  [DPO_PROTO_IP4] = hicn_ip4_nodes,
};

/**
 * @brief DPO type value for the mw_strategy
 */
static dpo_type_t hicn_dpo_type_mw;

static const hicn_dpo_vft_t hicn_dpo_mw_vft = {
  .hicn_dpo_get_ctx = &hicn_strategy_mw_ctx_get,
  .hicn_dpo_is_type = &hicn_dpo_is_type_strategy_mw,
  .hicn_dpo_get_type = &hicn_dpo_strategy_mw_get_type,
  .hicn_dpo_module_init = &hicn_dpo_strategy_mw_module_init,
  .hicn_dpo_create = &hicn_strategy_mw_ctx_create,
  .hicn_dpo_add_update_nh = &hicn_strategy_mw_ctx_add_nh,
  .hicn_dpo_del_nh = &hicn_strategy_mw_ctx_del_nh,
  .hicn_dpo_lock_dpo_ctx = &hicn_strategy_mw_ctx_lock,
  .hicn_dpo_unlock_dpo_ctx = hicn_strategy_mw_ctx_unlock,
  .format_hicn_dpo = &format_hicn_dpo_strategy_mw
};

int
hicn_dpo_is_type_strategy_mw (const dpo_id_t * dpo)
{
  return dpo->dpoi_type == hicn_dpo_type_mw;
}

void
hicn_dpo_strategy_mw_module_init (void)
{
  pool_validate_index (hicn_strategy_mw_ctx_pool, 0);
  /*
   * Register our type of dpo
   */
  hicn_dpo_type_mw =
    hicn_dpo_register_new_type (hicn_nodes_mw, &hicn_dpo_mw_vft,
				hicn_mw_strategy_get_vft (),
				&dpo_strategy_mw_ctx_vft);
}

u8 *
format_hicn_dpo_strategy_mw (u8 * s, va_list * ap)
{

  u32 indent = va_arg (*ap, u32);
  s =
    format (s,
	    "Static Weights: weights are updated by the control plane, next hop is the one with the maximum weight.\n",
	    indent);
  return (s);
}

dpo_type_t
hicn_dpo_strategy_mw_get_type (void)
{
  return hicn_dpo_type_mw;
}

//////////////////////////////////////////////////////////////////////////////////////////////////

void
hicn_strategy_mw_ctx_lock (dpo_id_t * dpo)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx =
    (hicn_strategy_mw_ctx_t *) hicn_strategy_mw_ctx_get (dpo->dpoi_index);

  if (hicn_strategy_mw_ctx != NULL)
    {
      hicn_strategy_mw_ctx->default_ctx.locks++;
    }
}

void
hicn_strategy_mw_ctx_unlock (dpo_id_t * dpo)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx =
    (hicn_strategy_mw_ctx_t *) hicn_strategy_mw_ctx_get (dpo->dpoi_index);

  if (hicn_strategy_mw_ctx != NULL)
    {
      hicn_strategy_mw_ctx->default_ctx.locks--;

      if (0 == hicn_strategy_mw_ctx->default_ctx.locks)
	{
	  pool_put (hicn_strategy_mw_ctx_pool, hicn_strategy_mw_ctx);
	}
    }
}

u8 *
format_hicn_strategy_mw_ctx (u8 * s, va_list * ap)
{
  int i = 0;
  index_t index = va_arg (*ap, index_t);
  hicn_strategy_mw_ctx_t *dpo = NULL;
  dpo_id_t *next_hop = NULL;
  hicn_face_vft_t *face_vft = NULL;
  u32 indent = va_arg (*ap, u32);;

  dpo = (hicn_strategy_mw_ctx_t *) hicn_strategy_mw_ctx_get (index);

  s = format (s, "hicn-mw");
  for (i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX && dpo != NULL; i++)
    {
      u8 *buf = NULL;
      if (i < dpo->default_ctx.entry_count)
	buf = format(NULL, "FIB");
      else if (i >= HICN_PARAM_FIB_ENTRY_NHOPS_MAX - dpo->default_ctx.tfib_entry_count)
	buf = format(NULL, "TFIB");
      else
	continue;
      next_hop = &dpo->default_ctx.next_hops[i];
      face_vft = hicn_face_get_vft (next_hop->dpoi_type);
      if (face_vft != NULL)
	{
	  s = format (s, "\n");
	  s =
	    format (s, "%U ", face_vft->format_face, next_hop->dpoi_index,
		    indent);
	  s = format (s, "weight %u", dpo->weight[i]);
	  s = format (s, " %s", buf);
	}
    }

  return (s);
}

static index_t
hicn_strategy_mw_ctx_get_index (hicn_strategy_mw_ctx_t * cd)
{
  return (cd - hicn_strategy_mw_ctx_pool);
}

int
hicn_strategy_mw_ctx_create (dpo_proto_t proto, const dpo_id_t * next_hop,
			     int nh_len, index_t * dpo_idx)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx;
  int ret = HICN_ERROR_NONE, i;

  /* Allocate a hicn_dpo_ctx on the vpp pool and initialize it */
  pool_get (hicn_strategy_mw_ctx_pool, hicn_strategy_mw_ctx);

  *dpo_idx = hicn_strategy_mw_ctx_get_index (hicn_strategy_mw_ctx);

  init_dpo_ctx (&(hicn_strategy_mw_ctx->default_ctx));

  for (i = 0; i < HICN_PARAM_FIB_ENTRY_NHOPS_MAX && i < nh_len; i++)
    {
      clib_memcpy (&hicn_strategy_mw_ctx->default_ctx.next_hops[i],
		   &next_hop[i], sizeof (dpo_id_t));
      hicn_strategy_mw_ctx->default_ctx.entry_count++;
    }

  memset (hicn_strategy_mw_ctx->weight, 0, HICN_PARAM_FIB_ENTRY_NHOPS_MAX);

  return ret;
}

hicn_dpo_ctx_t *
hicn_strategy_mw_ctx_get (index_t index)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx = NULL;
  if (!pool_is_free_index (hicn_strategy_mw_ctx_pool, index))
    {
      hicn_strategy_mw_ctx =
        (pool_elt_at_index (hicn_strategy_mw_ctx_pool, index));
    }

  return (hicn_dpo_ctx_t *)hicn_strategy_mw_ctx;
}

int
hicn_strategy_mw_ctx_add_nh (const dpo_id_t * nh, index_t dpo_idx)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx =
    (hicn_strategy_mw_ctx_t *) hicn_strategy_mw_ctx_get (dpo_idx);

  if (hicn_strategy_mw_ctx == NULL)
    {
      return HICN_ERROR_STRATEGY_NOT_FOUND;
    }

  int empty = hicn_strategy_mw_ctx->default_ctx.entry_count;

  /* Iterate through the list of faces to add new faces */
  for (int i = 0; i < hicn_strategy_mw_ctx->default_ctx.entry_count; i++)
    {
      if (!memcmp
          (nh, &hicn_strategy_mw_ctx->default_ctx.next_hops[i],
           sizeof (dpo_id_t)))
        {
          /* If face is marked as deleted, ignore it */
          hicn_face_t *face =
            hicn_dpoi_get_from_idx (hicn_strategy_mw_ctx->
                                    default_ctx.next_hops[i].dpoi_index);
          if (face->shared.flags & HICN_FACE_FLAGS_DELETED)
            {
              continue;
            }
          return HICN_ERROR_DPO_CTX_NHOPS_EXISTS;
        }
    }

  /* Get an empty place */
  if (empty > HICN_PARAM_FIB_ENTRY_NHOPS_MAX)
    {
      return HICN_ERROR_DPO_CTX_NHOPS_NS;
    }

  clib_memcpy (&hicn_strategy_mw_ctx->default_ctx.next_hops[empty], nh,
               sizeof (dpo_id_t));
  hicn_strategy_mw_ctx->default_ctx.entry_count++;

  return HICN_ERROR_NONE;
}

int
hicn_strategy_mw_ctx_del_nh (hicn_face_id_t face_id, index_t dpo_idx,
			     fib_prefix_t * fib_pfx)
{
  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx =
    (hicn_strategy_mw_ctx_t *) hicn_strategy_mw_ctx_get (dpo_idx);
  int ret = HICN_ERROR_DPO_CTX_NOT_FOUND;
  dpo_id_t invalid = NEXT_HOP_INVALID;

  if (hicn_strategy_mw_ctx == NULL)
    return HICN_ERROR_STRATEGY_NOT_FOUND;

  for (int i = 0; i < hicn_strategy_mw_ctx->default_ctx.entry_count; i++)
    {
      if (hicn_strategy_mw_ctx->default_ctx.next_hops[i].dpoi_index ==
          face_id)
        {
          hicn_face_unlock (&hicn_strategy_mw_ctx->default_ctx.
                            next_hops[i]);
          hicn_strategy_mw_ctx->default_ctx.entry_count--;
          hicn_strategy_mw_ctx->default_ctx.next_hops[i] = hicn_strategy_mw_ctx->default_ctx.next_hops[hicn_strategy_mw_ctx->default_ctx.entry_count];
          hicn_strategy_mw_ctx->default_ctx.next_hops[hicn_strategy_mw_ctx->default_ctx.entry_count] = invalid;
          ret = HICN_ERROR_NONE;
          break;
        }
    }

  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
