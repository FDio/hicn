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

#ifndef __HICN_STRATEGY_DPO_CTX_H__
#define __HICN_STRATEGY_DPO_CTX_H__

#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>

#include "hicn.h"
#include "params.h"
#include "faces/face.h"

#define HICN_FIB_TABLE 0

#define DATA_LEN 8

#define NEXT_HOP_INVALID DPO_INVALID

/*
 * An hicn dpo is a list of next hops (face + weight).
 */
typedef struct __attribute__ ((packed)) hicn_dpo_ctx_s
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* 8B*5 = 40B */
  dpo_id_t next_hops[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
  /* 40B + 4B = 44B */
  u32 locks;
  /* 44B + 1B = 45B */
  u8 entry_count;
  /* 45B + 1B = 46B */
  /* Number of TFIB entries (stored at the end of the next_hops array */
  u8 tfib_entry_count;

  /* 46B + 2B = 48B */
  u16 padding;			/* To align to 8B */

#ifdef HICN_MAPME_NOTIFICATIONS
  /* (8B) last acked update for IU/IN heuristic on producer */
  f64 last_iu_ack;
#endif
  /* (4B) last sequence number */
  seq_t seq;

} hicn_dpo_ctx_t;

STATIC_ASSERT (sizeof (hicn_dpo_ctx_t) <= CLIB_CACHE_LINE_BYTES,
	       "sizeof hicn_dpo_ctx_t is greater than 64B");

#endif /* // __HICN_STRATEGY_DPO_CTX_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
