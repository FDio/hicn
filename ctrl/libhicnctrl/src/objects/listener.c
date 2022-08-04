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
 * \file listener.c
 * \brief Implementation of listener.
 */

#include <string.h>

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/listener.h>
#include <hicn/util/log.h>

#include "../object_vft.h"
#include "../object_private.h"
#include "base.h"

bool hc_listener_is_local(const hc_listener_t *listener) {
  return (strncmp(listener->interface_name, "lo", INTERFACE_LEN) == 0);
}

/* LISTENER VALIDATE */

int hc_listener_validate(const hc_listener_t *listener, bool allow_partial) {
  // if a field is specified it should be valid
  // then we allow different specification, by key or by attributes, if
  // allow_partial

  int has_id = 0;
  int has_name = 0;
  int has_interface_name = 0;
  int has_type = 0;
  int has_family = 0;
  int has_local_addr = 0;
  int has_local_port = 0;

  if (listener->id == ~0) {
    ERROR("[hc_listener_validate] Invalid id specified");
    return -1;
  }
  has_id = 1;

  if (!isempty(listener->name)) {
    if (!IS_VALID_NAME(listener->name)) {
      ERROR("[hc_listener_validate] Invalid name specified");
      return -1;
    }
    has_name = 1;
  }

  if (!isempty(listener->interface_name)) {
    if (!IS_VALID_INTERFACE_NAME(listener->interface_name)) {
      ERROR("[hc_listener_validate] Invalid interface_name specified");
      return -1;
    }
    has_interface_name = 1;
  }

  if (listener->type != FACE_TYPE_UNDEFINED) {
    if (!IS_VALID_TYPE(listener->type)) {
      ERROR("[hc_listener_validate] Invalid type specified");
      return -1;
    }
    has_type = 1;
  }

  if (listener->family != AF_UNSPEC) {
    if (!IS_VALID_FAMILY(listener->family)) {
      ERROR("[hc_listener_validat] Invalid family specified");
      return -1;
    }
    has_family = 1;
  }

  if (!hicn_ip_address_empty(&listener->local_addr)) {
    if (!IS_VALID_ADDRESS(listener->local_addr)) {
      ERROR("[hc_listener_validate] Invalid local_addr specified");
      return -1;
    }
    has_local_addr = 1;
  }

  if (listener->local_port != 0) {
    if (!IS_VALID_PORT(listener->local_port)) {
      ERROR("[hc_listener_validate] Invalid local_port specified");
      return -1;
    }
    has_local_port = 1;
  }

  if (allow_partial) {
    if ((has_id || has_name) && !has_type && !has_family && !has_local_port &&
        !has_local_port)
      return 0;
    else if (has_name && has_type && has_family && has_local_addr &&
             has_local_port)
      return 0;
    else
      return -1;
  } else {
    /* name is optional */
    if (has_id && has_interface_name && has_type && has_family &&
        has_local_addr && has_local_port)
      return 0;
    return -1;
  }
}

int _hc_listener_validate(const hc_object_t *object, bool allow_partial) {
  return hc_listener_validate(&object->listener, allow_partial);
}

/* LISTENER CMP */

int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2) {
  int rc;

  rc = INT_CMP(l1->type, l2->type);
  if (rc != 0) return rc;

  rc = INT_CMP(l1->family, l2->family);
  if (rc != 0) return rc;

  rc = strncmp(l1->interface_name, l2->interface_name, INTERFACE_LEN);
  if (rc != 0) return rc;

  rc = hicn_ip_address_cmp(&l1->local_addr, &l2->local_addr);
  if (rc != 0) return rc;

  rc = INT_CMP(l1->local_port, l2->local_port);
  if (rc != 0) return rc;

  return rc;
}

int _hc_listener_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return hc_listener_cmp(&object1->listener, &object2->listener);
}

/* LISTENER SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_listener_snprintf(char *s, size_t size, const hc_listener_t *listener) {
  char local[MAXSZ_URL];
  int rc;
  rc = url_snprintf(local, MAXSZ_URL, &listener->local_addr,
                    listener->local_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_listener_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s %s interface=%s", listener->name, local,
                  face_type_str(listener->type), listener->interface_name);
}

int _hc_listener_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_listener_snprintf(s, size, &object->listener);
}

/* OPERATIONS */

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.listener = *listener;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_LISTENER, &object, NULL);
}

int hc_listener_get(hc_sock_t *s, hc_listener_t *listener, hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.listener = *listener;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_LISTENER, &object, pdata);
}

int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.listener = *listener;
  return hc_execute(s, ACTION_DELETE, OBJECT_TYPE_LISTENER, &object, NULL);
}

int hc_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_LISTENER, NULL, pdata);
}

GENERATE_FIND(listener);

DECLARE_OBJECT_OPS(OBJECT_TYPE_LISTENER, listener);
