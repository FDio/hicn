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

#include <vnet/dpo/dpo.h>

#include "strategy_dpo_manager.h"
#include "strategy_dpo_ctx.h"
#include "strategies/dpo_mw.h"
#include "strategies/dpo_rr.h"
#include "strategy.h"
#include "faces/face.h"

static dpo_type_t *strategies_id;
static const hicn_dpo_vft_t **hicn_dpo_vfts;

static const hicn_strategy_vft_t **hicn_strategy_vfts;

int hicn_strategies = 0;

hicn_dpo_vft_t default_dpo;

dpo_type_t
hicn_dpo_register_new_type (const char *const *const *hicn_nodes,
			    const hicn_dpo_vft_t * hicn_dpo_vft,
			    const hicn_strategy_vft_t * hicn_strategy_vft,
			    const dpo_vft_t * dpo_ctx_vft)
{
  dpo_type_t dpo_type = dpo_register_new_type (dpo_ctx_vft, hicn_nodes);
  vec_validate (hicn_dpo_vfts, dpo_type);
  hicn_dpo_vfts[dpo_type] = hicn_dpo_vft;

  vec_validate (hicn_strategy_vfts, dpo_type);
  hicn_strategy_vfts[dpo_type] = hicn_strategy_vft;

  vec_validate (strategies_id, hicn_strategies);
  strategies_id[hicn_strategies] = dpo_type;
  hicn_strategies++;

  return dpo_type;
}

u32
dpo_is_hicn (const dpo_id_t * dpo)
{
  for (int i = 0; i < hicn_strategies; i++)
    {
      if (hicn_dpo_vfts[strategies_id[i]]->hicn_dpo_is_type (dpo))
	return 1;
    }
  return 0;
}

dpo_type_t
hicn_dpo_get_vft_id (const dpo_id_t * dpo)
{
  return dpo->dpoi_type;
}

const hicn_dpo_vft_t *
hicn_dpo_get_vft (dpo_type_t vfts_id)
{
  return hicn_dpo_vfts[vfts_id];
}

const hicn_dpo_vft_t *
hicn_dpo_get_vft_from_id (u8 strategy_id)
{
  return hicn_dpo_vfts[strategies_id[strategy_id]];
}

const hicn_strategy_vft_t *
hicn_dpo_get_strategy_vft (dpo_type_t vfts_id)
{
  return hicn_strategy_vfts[vfts_id];
}

const hicn_strategy_vft_t *
hicn_dpo_get_strategy_vft_from_id (u8 vfts_id)
{
  return hicn_strategy_vfts[strategies_id[vfts_id]];
}

void
hicn_dpos_init (void)
{
  hicn_strategy_init_dpo_ctx_pool ();
  hicn_dpo_strategy_mw_module_init ();
  hicn_dpo_strategy_rr_module_init ();

  default_dpo.hicn_dpo_is_type = &hicn_dpo_is_type_strategy_mw;
  default_dpo.hicn_dpo_get_type = &hicn_dpo_strategy_mw_get_type;
  default_dpo.hicn_dpo_module_init = &hicn_dpo_strategy_mw_module_init;
  default_dpo.hicn_dpo_create = &hicn_strategy_mw_ctx_create;
  default_dpo.hicn_dpo_add_update_nh = &hicn_strategy_mw_ctx_add_nh;
  default_dpo.hicn_dpo_del_nh = &hicn_strategy_mw_ctx_del_nh;
  default_dpo.hicn_dpo_format = &hicn_strategy_mw_format_ctx;
}

u8 *
format_hicn_strategy_list (u8 * s, int n, ...)
{
  va_list ap;
  va_start (ap, n);
  u32 indent = va_arg (ap, u32);
  va_end (ap);

  s = format (s, "Strategies:\n", indent);
  indent += 4;
  int i;
  vec_foreach_index (i, strategies_id)
  {
    s = format (s, "(%d) ", i, indent);
    s = hicn_strategy_vfts[strategies_id[i]]->hicn_format_strategy (s, &ap);
  }

  return (s);
}

u8
hicn_dpo_strategy_id_is_valid (int strategy_id)
{
  return vec_len (strategies_id) > strategy_id ?
    HICN_ERROR_NONE : HICN_ERROR_DPO_MGR_ID_NOT_VALID;
}

int
hicn_strategy_get_all_available (void)
{
  return hicn_strategies;
}

/**
 * @brief Registers a dpo by calling its module init function.
 *
 * This is typically called from the ctor for dpo's registered at compilation
 * time.
 */
void
hicn_dpo_register (const hicn_dpo_vft_t * hicn_dpo)
{
  hicn_dpo->hicn_dpo_module_init ();
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
