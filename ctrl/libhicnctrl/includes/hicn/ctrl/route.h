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

/**
 * \file route.h
 * \brief hICN route
 */
#ifndef HICN_ROUTE_H
#define HICN_ROUTE_H

#include <hicn/util/ip_address.h>
#include <hicn/face.h>

typedef u16 route_cost_t;

typedef struct hicn_route_s hicn_route_t;

#define MAXSZ_ROUTE_ MAXSZ_PREFIX + 3 + MAXSZ_COST
#define MAXSZ_ROUTE MAXSZ_ROUTE_ + NULLTERM

hicn_route_t * hicn_route_create(ip_prefix_t * prefix, face_id_t face_id, route_cost_t cost);
hicn_route_t * hicn_route_dup(const hicn_route_t * route);
void hicn_route_free(hicn_route_t * route);

int hicn_route_cmp(const hicn_route_t * route1, const hicn_route_t * route2);

int hicn_route_get_prefix(const hicn_route_t * route, ip_prefix_t * prefix);
int hicn_route_set_prefix(hicn_route_t * route, const ip_prefix_t prefix);

int hicn_route_get_cost(const hicn_route_t * route, int * cost);
int hicn_route_set_cost(hicn_route_t * route, const int cost);

size_t hicn_route_snprintf(char * s, size_t size, const hicn_route_t * route);

#endif
