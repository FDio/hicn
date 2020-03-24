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

#ifndef __HICN_HS_ROUTE_H__
#define __HICN_HS_ROUTE_H__

#include <vnet/fib/fib.h>
#include <vnet/dpo/dpo.h>

/* Init the route module */
void
hicn_hs_route_init ();

clib_error_t *
hicn_hs_set_local_prefix(const fib_prefix_t * prefix);

/* Add a new route for a name prefix */
int
hicn_hs_route_add (const fib_prefix_t * prefix, const dpo_id_t *dpo);

/* Remove route for a name prefix */
int
hicn_route_del (fib_prefix_t * prefix);

#endif /* __HICN_HS_ROUTE_H__ */
