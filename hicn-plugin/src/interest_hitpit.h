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

#ifndef __HICN_INTEREST_HITPIT_H__
#define __HICN_INTEREST_HITPIT_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "pcs.h"

/*
 * Node context data; we think this is per-thread/instance
 */
typedef struct hicn_interest_hitpit_runtime_s
{
  int id;
  hicn_pit_cs_t *pitcs;
} hicn_interest_hitpit_runtime_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
} hicn_interest_hitpit_trace_t;

typedef enum
{
  HICN_INTEREST_HITPIT_NEXT_INTEREST_HITCS,
  HICN_INTEREST_HITPIT_NEXT_IP4_LOOKUP,
  HICN_INTEREST_HITPIT_NEXT_IP6_LOOKUP,
  HICN_INTEREST_HITPIT_NEXT_ERROR_DROP,
  HICN_INTEREST_HITPIT_N_NEXT,
} hicn_interest_hitpit_next_t;

#endif /* // __HICN_INTEREST_HITPIT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
