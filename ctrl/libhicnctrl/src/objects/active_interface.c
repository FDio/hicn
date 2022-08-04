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
 * \file active_interface.c
 * \brief Implementation of active_interface object.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/active_interface.h>
#include <hicn/util/log.h>
#include <hicn/util/ip_address.h>

#include "../object_private.h"
#include "../object_vft.h"

/* ACTIVE_INTERFACE VALIDATE */

int hc_active_interface_validate(const hc_active_interface_t *active_interface,
                                 bool allow_partial) {
  return 0;  // XXX TODO
}

int _hc_active_interface_validate(const hc_object_t *object,
                                  bool allow_partial) {
  return hc_active_interface_validate(&object->active_interface, allow_partial);
}

/* ACTIVE_INTERFACE CMP */

// XXX TODO
int hc_active_interface_cmp(const hc_active_interface_t *active_interface1,
                            const hc_active_interface_t *active_interface2) {
  return -1;
}

int _hc_active_interface_cmp(const hc_object_t *object1,
                             const hc_object_t *object2) {
  return hc_active_interface_cmp(&object1->active_interface,
                                 &object2->active_interface);
}

/* ACTIVE_INTERFACE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_active_interface_snprintf(
    char *s, size_t size, const hc_active_interface_t *active_interface) {
  int rc;
  char *pos = s;

  rc = hicn_ip_prefix_snprintf(pos, size, &active_interface->prefix);
  if ((rc < 0) || (rc >= size)) return rc;
  pos += rc;
  size -= rc;

  for (netdevice_type_t type = NETDEVICE_TYPE_UNDEFINED + 1;
       type < NETDEVICE_TYPE_N; type++) {
    if (!netdevice_flags_has(active_interface->interface_types, type)) continue;
    rc = snprintf(pos, size, " %s", netdevice_type_str(type));
    if ((rc < 0) || (rc >= size)) return (int)(pos - s + rc);

    pos += rc;
    size -= rc;
  }
  return (int)(pos - s);
}

int _hc_active_interface_snprintf(char *s, size_t size,
                                  const hc_object_t *object) {
  return hc_active_interface_snprintf(s, size, &object->active_interface);
}

DECLARE_OBJECT_OPS(OBJECT_TYPE_ACTIVE_INTERFACE, active_interface);
