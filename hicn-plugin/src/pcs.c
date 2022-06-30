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

#include <stdlib.h>
#include <vlib/vlib.h>

#include "pcs.h"
#include "cache_policies/cs_lru.h"

void
hicn_pit_create (hicn_pit_cs_t *p, u32 max_pit_elt, u32 max_cs_elt)
{
  // Allocate PCS hash table. KEY=Name, VALUE=pool_idx
  clib_bihash_24_8_t *pcs_table = &p->pcs_table;
  u32 n_elements = max_pit_elt / BIHASH_KVP_PER_PAGE;
  clib_bihash_init_24_8 (pcs_table, "hicn_pcs_table", n_elements, 512 << 20);

  // Allocate pool of PIT/CS entries
  pool_alloc (p->pcs_entries_pool, max_pit_elt);

  // Init counters
  p->max_pit_size = max_pit_elt;
  p->pcs_pit_count = p->pcs_cs_count = 0;
  p->policy_state = hicn_cs_lru_create (max_cs_elt);
  p->pcs_cs_count = 0;
  p->pcs_pcs_alloc = 0;
  p->pcs_pcs_dealloc = 0;
  p->pcs_pit_count = 0;
}

void
hicn_pit_destroy (hicn_pit_cs_t *p)
{
  // Deallocate PCS hash table.
  clib_bihash_24_8_t *pcs_table = &p->pcs_table;
  clib_bihash_free_24_8 (pcs_table);

  // Deallocate pool of PIT/CS entries
  pool_free (p->pcs_entries_pool);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
