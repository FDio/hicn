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

#ifndef __HICN_ROUTE__
#define __HICN_ROUTE__

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include "hicn.h"
#include "faces/face.h"

/*
 * Retrieve the hicn dpo corresponding to a hicn prefix
 */
int
hicn_route_get_dpo (const ip46_address_t * prefix, u8 plen,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index);

/*
 * Add a new route for a name prefix
 */
int
hicn_route_add (hicn_face_id_t * face_id, u32 len,
		const ip46_address_t * prefix, u8 plen);

/*
 * Add new next hops for a prefix route
 */
int
hicn_route_add_nhops (hicn_face_id_t * face_id, u32 len,
		      const ip46_address_t * prefix, u8 plen);

/* Remove a route for a name prefix */
int hicn_route_del (ip46_address_t * prefix, u8 plen);

/* Remove a next hop route for a name prefix */
int hicn_route_del_nhop (ip46_address_t * prefix, u8 plen, u32 face_id);

/* Remove a next hop route for a name prefix */
int
hicn_route_set_strategy (ip46_address_t * prefix, u8 plen, u32 strategy_id);

#endif /* //__HICN_ROUTE__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
