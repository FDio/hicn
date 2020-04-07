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

#include <stdlib.h>
#include <vlib/vlib.h>

#include "hashtb.h"
#include "pcs.h"
#include "cache_policies/cs_lru.h"

int
hicn_pit_create (hicn_pit_cs_t * p, u32 num_elems)
{
  int ret =
    hicn_hashtb_alloc (&p->pcs_table, num_elems, sizeof (hicn_pcs_entry_t));
  p->pcs_table->ht_flags |= HICN_HASHTB_FLAG_KEY_FMT_NAME;

  p->pcs_pit_count = p->pcs_cs_count = 0;

  p->policy_state.max =
    HICN_PARAM_CS_LRU_DEFAULT -
    (HICN_PARAM_CS_LRU_DEFAULT * HICN_PARAM_CS_RESERVED_APP / 100);
  p->policy_state.count = 0;
  p->policy_state.head = p->policy_state.tail = 0;

  p->policy_vft.hicn_cs_insert = hicn_cs_lru.hicn_cs_insert;
  p->policy_vft.hicn_cs_update = hicn_cs_lru.hicn_cs_update;
  p->policy_vft.hicn_cs_dequeue = hicn_cs_lru.hicn_cs_dequeue;
  p->policy_vft.hicn_cs_delete_get = hicn_cs_lru.hicn_cs_delete_get;
  p->policy_vft.hicn_cs_trim = hicn_cs_lru.hicn_cs_trim;
  p->policy_vft.hicn_cs_flush = hicn_cs_lru.hicn_cs_flush;

  return (ret);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
