/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * \brief Implementation of route object.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/route.h>
#include <hicn/util/log.h>

#include "../object_private.h"
#include "../object_vft.h"
#include "face.h"
#include "base.h"

bool hc_route_has_face(const hc_route_t *route) {
  return !iszero(&route->face, sizeof(hc_face_t));
}

/* ROUTE VALIDATE */

int hc_route_validate(const hc_route_t *route, bool allow_partial) {
  int has_id = 0;
  int has_name = 0;
  int has_face = 0;

  int has_family = 0;
  int has_remote_addr = 0;

  if (!IS_VALID_CONNECTION_ID(route->face_id)) {
    ERROR("[hc_route_validate] Invalid face id");
    return -1;
  }
  has_id = 1;

  if (!isempty(route->face_name)) {
    if (!IS_VALID_NAME(route->face_name)) {
      ERROR("[hc_route_validate] Invalid name specified");
      return -1;
    }
    has_name = 1;
  }

  if (route->family != AF_UNSPEC) {
    if (!IS_VALID_FAMILY(route->family)) {
      ERROR("[hc_route_validate] Invalid family specified");
      return -1;
    }
    has_family = 1;
  }

  if (!hicn_ip_address_empty(&route->remote_addr)) {
    if (!IS_VALID_ADDRESS(route->remote_addr)) {
      ERROR("[hc_route_validate] Invalid remote_addr specified");
      return -1;
    }
    has_remote_addr = 1;
  }

  if (!IS_VALID_ROUTE_COST(route->cost)) {
    ERROR("[hc_route_validate] Invalid cost");
    return -1;
  }

  if (!IS_VALID_PREFIX_LEN(route->len)) {
    ERROR("[hc_route_validate] Invalid len");
    return -1;
  }

  if (hc_route_has_face(route)) {
    if (!hc_face_validate(&route->face, allow_partial)) {
      ERROR("[hc_route_validate] Invalid face");
      return -1;
    }
    has_face = 1;
  }

  int has_face_info = has_id || has_name || has_face;

  if (!has_face_info) return -1;
  if (allow_partial && (has_name + has_face != 1)) return -1;

  if (has_face_info && has_family && has_remote_addr) return 0;

  return -1;
}

int _hc_route_validate(const hc_object_t *object, bool allow_partial) {
  return hc_route_validate(&object->route, allow_partial);
}

/* ROUTE CMP */

// XXX TODO
int hc_route_cmp(const hc_route_t *route1, const hc_route_t *route2) {
  return -1;
}

int _hc_route_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return hc_route_cmp(&object1->route, &object2->route);
}

/* ROUTE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_route_snprintf(char *s, size_t size, const hc_route_t *route) {
  /* interface cost prefix length */

  char prefix[MAXSZ_IP_ADDRESS];
  int rc;

  rc = hicn_ip_address_snprintf(prefix, MAXSZ_IP_ADDRESS, &route->remote_addr);
  if (rc >= MAXSZ_IP_ADDRESS)
    ;
  if (rc < 0) return rc;

  return snprintf(s, size, "%d (%s) %*d %s %*d", route->face_id,
                  route->face_name, MAXSZ_COST, route->cost, prefix, MAXSZ_LEN,
                  route->len);
}

int _hc_route_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_route_snprintf(s, size, &object->route);
}

int hc_route_create(hc_sock_t *s, hc_route_t *route) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.route = *route;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_ROUTE, &object, NULL);
}

int hc_route_get(hc_sock_t *s, hc_route_t *route, hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.route = *route;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_ROUTE, &object, pdata);
}

int hc_route_delete(hc_sock_t *s, hc_route_t *route) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.route = *route;
  return hc_execute(s, ACTION_DELETE, OBJECT_TYPE_ROUTE, &object, NULL);
}

int hc_route_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_ROUTE, NULL, pdata);
}

int hc_route_list_async(hc_sock_t *s) {
  return hc_execute_async(s, ACTION_LIST, OBJECT_TYPE_ROUTE, NULL, NULL, NULL);
}

// XXX difference between GET and FIND
GENERATE_FIND(route);

DECLARE_OBJECT_OPS(OBJECT_TYPE_ROUTE, route);
