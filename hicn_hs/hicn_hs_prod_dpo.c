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

#include "hicn_hs_prod_dpo.h"
#include "hicn_hs.h"

#include <vnet/ip/format.h>
#include <vnet/adj/adj.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>

dpo_type_t hicn_hs_dpo_type;

const static char *const hicn_hs_prod_dpo4_nodes[] = {
  "hicn_hs-input4",
  NULL,
};

const static char *const hicn_hs_prod_dpo6_nodes[] = {
  "hicn_hs-input6",
  NULL,
};

const static char *const *const hicn_hs_prod_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = hicn_hs_prod_dpo4_nodes,
  [DPO_PROTO_IP6] = hicn_hs_prod_dpo6_nodes
};

void hicn_hs_prod_dpo_lock(dpo_id_t *dpo)
{
  return;
}

void hicn_hs_prod_dpo_unlock(dpo_id_t *dpo)
{
  return;
}

u8 *format_hicn_hs_prod_dpo (u8 * s, va_list * args)
{
  return NULL;
}

const static dpo_vft_t hicn_hs_prod_dpo_vft = {
  .dv_lock = hicn_hs_prod_dpo_lock,
  .dv_unlock = hicn_hs_prod_dpo_unlock,
  .dv_format = format_hicn_hs_prod_dpo,
};

/**
 * Register the new DPO type.
 */
void hicn_hs_dpo_module_init(void)
{
  hicn_hs_dpo_type = dpo_register_new_type (&hicn_hs_prod_dpo_vft, hicn_hs_prod_dpo_nodes);
}

int dpo_is_hicn_hs(const dpo_id_t *dpo)
{
  return dpo->dpoi_type == hicn_hs_dpo_type;
}

u32 hicn_hs_dpo_create(u32 hicn_hs_ctx_idx, u8 is_ip4, dpo_id_t *dpo)
{
  dpo->dpoi_type = DPO_FIRST;
  dpo->dpoi_proto = DPO_PROTO_NONE;
  dpo->dpoi_index = INDEX_INVALID;
  dpo->dpoi_next_node = 0;

  u16 next_node = is_ip4 ? hicn_hs_input4_node.index : hicn_hs_input6_node.index;
  
  index_t dpoi_index = hicn_hs_ctx_idx;
  dpo_set(dpo, hicn_hs_dpo_type, is_ip4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6, dpoi_index);
  dpo->dpoi_next_node = next_node;
  dpo_unlock (dpo);

  return HICN_HS_ERROR_NONE;
}
