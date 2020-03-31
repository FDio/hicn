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

#include <vlib/vlib.h>		// vlib_node_registration_t (vlib/node.h)

/*
 * Structure carrying all necessary information for managing Special Interest
 * (re)transmissions.
 */
typedef struct
{
  hicn_prefix_t prefix;
  dpo_id_t dpo;
  u8 rtx_count; // Number of retransmissions since last tfib addition
} retx_t;

#if 0
#define HASH32(x) ((u16)x ^ (x << 16))
#endif

/**
 * @brief This is a process node reacting to face events.
 */
// not static !
vlib_node_registration_t hicn_mapme_eventmgr_process_node;

/**
 * @brief Initialize MAP-Me on forwarder
 * @params vm - vlib_main_t pointer
 */
void hicn_mapme_init (vlib_main_t * vm);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
