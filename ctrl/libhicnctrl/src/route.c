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
 * \file route.c
 * \brief Implementation of hICN route
 */

#include <hicn/hicn.h>
#include <hicn/ctrl/route.h>
#include <hicn/util/ip_address.h>

#define DEFAULT_HICN_ROUTE_COST 1

struct hicn_route_s {
    ip_prefix_t prefix;
    face_id_t face_id;
    route_cost_t cost; /* Optional, 0 means no value, defaults to 1 */
};

hicn_route_t *
hicn_route_create(ip_prefix_t * prefix, face_id_t face_id, route_cost_t cost)
{
    hicn_route_t * route = malloc(sizeof(hicn_route_t));
    if (!route)
        return NULL;
    route->prefix = *prefix;
    route->face_id = face_id;
    route->cost = cost != 0 ? cost : DEFAULT_HICN_ROUTE_COST;

    return route;
}

hicn_route_t *
hicn_route_dup(const hicn_route_t * route)
{
    hicn_route_t * new_route = malloc(sizeof(hicn_route_t));
    if (!route)
        return NULL;
    memcpy(new_route, route, sizeof(hicn_route_t));
    return new_route;
}

void hicn_route_free(hicn_route_t * route)
{
    free(route);
}

int
hicn_route_cmp(const hicn_route_t * route1, const hicn_route_t * route2)
{
    int rc;
    rc = ip_prefix_cmp(&route1->prefix, &route2->prefix);
    if (rc != 0)
        return rc;

    return (route1->face_id > route2->face_id) ?  1 :
           (route1->face_id < route2->face_id) ? -1 : 0;
}

int
hicn_route_get_prefix(const hicn_route_t * route, ip_prefix_t * prefix)
{
    *prefix = route->prefix;
    return 0;
}

int
hicn_route_set_prefix(hicn_route_t * route, const ip_prefix_t prefix)
{
    route->prefix = prefix;
    return 0;
}

int
hicn_route_get_cost(const hicn_route_t * route, int * cost)
{
    *cost = route->cost;
    return 0;
}

int
hicn_route_set_cost(hicn_route_t * route, const int cost)
{
    route->cost = cost;
    return 0;
}

/* /!\ Please update constants in header file upon changes */
size_t
hicn_route_snprintf(char * s, size_t size, const hicn_route_t * route)
{
    char prefix_s[MAXSZ_PREFIX];
    ip_prefix_ntop(&route->prefix, prefix_s, MAXSZ_PREFIX);
    return snprintf(s, size, "%s [%d]", prefix_s, route->cost);
}
