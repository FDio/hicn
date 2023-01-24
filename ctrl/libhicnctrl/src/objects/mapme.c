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
 * \file mapme.c
 * \brief Implementation of mapme object.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/mapme.h>
#include <hicn/util/log.h>

#include "../object_private.h"
#include "../object_vft.h"
#include "face.h"
#include "base.h"

/* MAPME VALIDATE */

int hc_mapme_validate(const hc_mapme_t *mapme, bool allow_partial) {
  int has_family = 0;
  int has_address = 0;
  int has_len = 0;

  if (allow_partial) return 0;

  if (mapme->family != AF_UNSPEC) {
    if (!IS_VALID_FAMILY(mapme->family)) {
      ERROR("[hc_mapme_validate] Invalid family specified");
      return -1;
    }
    has_family = 1;
  }

  if (!hicn_ip_address_empty(&mapme->address)) {
    if (!IS_VALID_ADDRESS(mapme->address)) {
      ERROR("[hc_mapme_validate] Invalid remote_addr specified");
      return -1;
    }
    has_address = 1;
  }

  if (!IS_VALID_PREFIX_LEN(mapme->len)) {
    ERROR("[hc_mapme_validate] Invalid len");
    return -1;
  }
  has_len = 1;
  return has_family && has_address && has_len;
}

int _hc_mapme_validate(const hc_object_t *object, bool allow_partial) {
  return hc_mapme_validate(&object->mapme, allow_partial);
}

/* MAPME CMP */

int hc_mapme_cmp(const hc_mapme_t *mapme1, const hc_mapme_t *mapme2) {
  return -1;
}

int _hc_mapme_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return -1;
}

/* MAPME SNPRINTF */

int hc_mapme_snprintf(char *s, size_t size, const hc_mapme_t *mapme) {
  return -1;
}

int _hc_mapme_snprintf(char *s, size_t size, const hc_object_t *object) {
  return -1;
}

int hc_mapme_create(hc_sock_t *s, hc_mapme_t *mapme) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.mapme = *mapme;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_MAPME, &object, NULL);
}

DECLARE_OBJECT_OPS(OBJECT_TYPE_MAPME, mapme);
