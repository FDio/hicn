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

#ifndef __HICN_HANDOFF_H__
#define __HICN_HANDOFF_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/**
 * @file hicn_handoff.h
 *
 * This node is meant to loadl-balance packets across different VPP workers.
 */

/* Trace context struct */
typedef struct
{
  u32 sw_if_index;
  u32 next_worker_index;
  u32 buffer_index;
} hicn_handoff_trace_t;

typedef struct
{
  /* Workers info */
  u32 num_workers;
  u32 first_worker_index;

  /* Frame queue index for ipv6 interests */
  u32 frame_queue_index_interest_6;
  /* Frame queue index for ipv4 interests */
  u32 frame_queue_index_interest_4;
    /* Frame queue index for ipv6 data */
  u32 frame_queue_index_data_6;
  /* Frame queue index for ipv4 data */
  u32 frame_queue_index_data_4;
} hicn_handoff_main_t;

void
hicn_handoff_init();

#endif /* // __HICN_HANDOFF_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
