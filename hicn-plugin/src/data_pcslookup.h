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

#ifndef __HICN_DATA_PCSLOOKUP_H__
#define __HICN_DATA_PCSLOOKUP_H__

#include "pcs.h"

/**
 * @file data_pcslookup.h
 *
 * This is the node encoutered by data packets after the hicn6-face-input or
 * hicn4-face-input. This node performs a lookup in the pit and content store and
 * if there is a hit in the PIT, the vlib buffer is passed to the hicn-data-fwd
 * while if there is a hit in the CS or there isn't any hit, the packet is dropped.
 */

/*
 * Node context data; we think this is per-thread/instance
 */
typedef struct hicn_data_pcslookup_runtime_s
{
  int id;
  hicn_pit_cs_t *pitcs;
} hicn_data_pcslookup_runtime_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
} hicn_data_pcslookup_trace_t;

typedef enum
{
  HICN_DATA_PCSLOOKUP_NEXT_DATA_FWD,	/* This must be one position
					 * before the error drop!! */
  HICN_DATA_PCSLOOKUP_NEXT_ERROR_DROP,
  HICN_DATA_PCSLOOKUP_N_NEXT,
} hicn_data_pcslookup_next_t;

#endif /* //__HICN_DATA_PCSLOOKUP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
