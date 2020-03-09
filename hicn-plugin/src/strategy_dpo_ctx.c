/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"

hicn_dpo_ctx_t *hicn_strategy_dpo_ctx_pool;

void hicn_strategy_init_dpo_ctx_pool ()
{
  pool_init_fixed (hicn_strategy_dpo_ctx_pool, 256);

}

void
hicn_strategy_dpo_ctx_lock (dpo_id_t * dpo)
{
  hicn_dpo_ctx_t * dpo_ctx = hicn_strategy_dpo_ctx_get (dpo->dpoi_index);

  if (dpo_ctx != NULL)
    {
      dpo_ctx->locks++;
    }
}

void
hicn_strategy_dpo_ctx_unlock (dpo_id_t * dpo)
{
  hicn_dpo_ctx_t *hicn_strategy_dpo_ctx =
    (hicn_dpo_ctx_t *) hicn_strategy_dpo_ctx_get (dpo->dpoi_index);

  if (hicn_strategy_dpo_ctx != NULL)
    {
      hicn_strategy_dpo_ctx->locks--;

      if (0 == hicn_strategy_dpo_ctx->locks)
	{
	  pool_put (hicn_strategy_dpo_ctx_pool, hicn_strategy_dpo_ctx);
	}
    }
}

u8 *
hicn_strategy_dpo_format_ctx (u8 * s, va_list * ap)
{
  index_t index = va_arg (*ap, index_t);
  hicn_dpo_ctx_t *dpo = NULL;
  u32 indent = va_arg (*ap, u32);

  dpo = (hicn_dpo_ctx_t *) hicn_strategy_dpo_ctx_get (index);

  const hicn_dpo_vft_t *dpo_vft = hicn_dpo_get_vft(dpo->dpo_type);

  s = dpo_vft->hicn_dpo_format(s, 2, index, indent);

  return (s);
}

index_t
hicn_strategy_dpo_ctx_get_index (hicn_dpo_ctx_t * cd)
{
  return (cd - hicn_strategy_dpo_ctx_pool);
}

hicn_dpo_ctx_t *
hicn_strategy_dpo_ctx_get (index_t index)
{
  hicn_dpo_ctx_t *hicn_strategy_dpo_ctx = NULL;
  if (!pool_is_free_index (hicn_strategy_dpo_ctx_pool, index))
    {
      hicn_strategy_dpo_ctx =
        (pool_elt_at_index (hicn_strategy_dpo_ctx_pool, index));
    }

  return hicn_strategy_dpo_ctx;
}

hicn_dpo_ctx_t *
hicn_strategy_dpo_ctx_create ()
{
  hicn_dpo_ctx_t * dpo_ctx;
  pool_get(hicn_strategy_dpo_ctx_pool, dpo_ctx);
  return dpo_ctx;
}

int
hicn_strategy_dpo_ctx_add_nh (const dpo_id_t * nh, hicn_dpo_ctx_t * dpo_ctx, u8 * pos)
{

  int empty = dpo_ctx->entry_count;

  /* Iterate through the list of faces to find if the face is already a next hop */
  for (int i = 0; i < dpo_ctx->entry_count; i++)
    {
      if (!memcmp
          (nh, &dpo_ctx->next_hops[i],
           sizeof (dpo_id_t)))
        {
          /* If face is marked as deleted, ignore it */
          hicn_face_t *face =
            hicn_dpoi_get_from_idx (dpo_ctx->next_hops[i].dpoi_index);
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

  clib_memcpy (&dpo_ctx->next_hops[empty], nh,
               sizeof (dpo_id_t));
  dpo_ctx->entry_count++;
  *pos=empty;

  return HICN_ERROR_NONE;
}

int
hicn_strategy_dpo_ctx_del_nh (hicn_face_id_t face_id, hicn_dpo_ctx_t * dpo_ctx)
{
  int ret = HICN_ERROR_DPO_CTX_NOT_FOUND;
  dpo_id_t invalid = NEXT_HOP_INVALID;

  for (int i = 0; i < dpo_ctx->entry_count; i++)
    {
      if (dpo_ctx->next_hops[i].dpoi_index ==
          face_id)
        {
          hicn_face_unlock (&dpo_ctx->next_hops[i]);
          dpo_ctx->entry_count--;
          dpo_ctx->next_hops[i] = dpo_ctx->next_hops[dpo_ctx->entry_count];
          dpo_ctx->next_hops[dpo_ctx->entry_count] = invalid;
          ret = HICN_ERROR_NONE;
          break;
        }
    }

  return ret;

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
