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
 * \file face.c
 * \brief Implementation of face object.
 */

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/face.h>
#include <hicn/util/log.h>

#include "../object_private.h"
#include "../object_vft.h"

bool hc_face_has_netdevice(const hc_face_t *face) {
  return netdevice_is_empty(&face->netdevice);
}

/* FACE VALIDATE */

int hc_face_validate(const hc_face_t *face, bool allow_partial) {
  if ((!allow_partial || !hc_face_has_netdevice(face)) &&
      !IS_VALID_INTERFACE_NAME(face->interface_name)) {
    ERROR("[hc_face_validate] Invalid interface_name specified");
    return -1;
  }
  if (!IS_VALID_TYPE(face->type)) {
    ERROR("[hc_face_validate] Invalid type specified");
    return -1;
  }
  if ((!allow_partial || face->family != AF_UNSPEC) &&
      !IS_VALID_FAMILY(face->family)) {
    ERROR("[hc_face_validate] Invalid family specified");
    return -1;
  }
  if ((!allow_partial || !hicn_ip_address_empty(&face->local_addr)) &&
      !IS_VALID_ADDRESS(face->local_addr)) {
    ERROR("[hc_face_validate] Invalid local_addr specified");
    return -1;
  }
  if ((!allow_partial || !(face->local_port == 0)) &&
      !IS_VALID_PORT(face->local_port)) {
    ERROR("[hc_face_validate] Invalid local_port specified");
    return -1;
  }
  if (!IS_VALID_ADDRESS(face->remote_addr)) {
    ERROR("[hc_face_validate] Invalid remote_addr specified");
    return -1;
  }
  if (!IS_VALID_PORT(face->remote_port)) {
    ERROR("[hc_face_validate] Invalid remote_port specified");
    return -1;
  }
  return 0;
}

int _hc_face_validate(const hc_object_t *object, bool allow_partial) {
  return hc_face_validate(&object->face, allow_partial);
}

/* FACE CMP */

int hc_face_cmp(const hc_face_t *c1, const hc_face_t *c2) {
  return -99;  // Not implemented
}

int _hc_face_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return hc_face_cmp(&object1->face, &object2->face);
}

/* FACE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_face_snprintf(char *s, size_t size, const hc_face_t *face) {
  /* URLs are also big enough to contain IP addresses in the hICN case */
  char local[MAXSZ_URL];
  char remote[MAXSZ_URL];
  char tags[MAXSZ_POLICY_TAGS];
  int rc;

  switch (face->type) {
    case FACE_TYPE_HICN:
    case FACE_TYPE_HICN_LISTENER:
      rc = hicn_ip_address_snprintf(local, MAXSZ_URL, &face->local_addr);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      rc = hicn_ip_address_snprintf(remote, MAXSZ_URL, &face->remote_addr);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      break;
    case FACE_TYPE_TCP:
    case FACE_TYPE_UDP:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_UDP_LISTENER:
      rc = url_snprintf(local, MAXSZ_URL, &face->local_addr, face->local_port);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      rc = url_snprintf(remote, MAXSZ_URL, &face->remote_addr,
                        face->remote_port);
      if (rc >= MAXSZ_URL)
        WARN("[hc_face_snprintf] Unexpected truncation of URL string");
      if (rc < 0) return rc;
      break;
    default:
      return -1;
  }

  // [#ID NAME] TYPE LOCAL_URL REMOTE_URL STATE/ADMIN_STATE (TAGS)
  rc = policy_tags_snprintf(tags, MAXSZ_POLICY_TAGS, face->tags);
  if (rc >= MAXSZ_POLICY_TAGS)
    WARN("[hc_face_snprintf] Unexpected truncation of policy tags string");
  if (rc < 0) return rc;

  return snprintf(
      s, size, "[#%d %s] %s %s %s %s %s/%s [%d] (%s)", face->id, face->name,
      face->netdevice.index != NETDEVICE_UNDEFINED_INDEX ? face->netdevice.name
                                                         : "*",
      face_type_str(face->type), local, remote, face_state_str(face->state),
      face_state_str(face->admin_state), face->priority, tags);
}

int _hc_face_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_face_snprintf(s, size, &object->face);
}

int hc_face_create(hc_sock_t *s, hc_face_t *face) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.face = *face;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_FACE, &object, NULL);
}

int hc_face_get(hc_sock_t *s, hc_face_t *face, hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.face = *face;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_FACE, &object, pdata);
}

int hc_face_delete(hc_sock_t *s, hc_face_t *face) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.face = *face;
  return hc_execute(s, ACTION_DELETE, OBJECT_TYPE_FACE, &object, NULL);
}

int hc_face_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_FACE, NULL, pdata);
}

int hc_face_list_async(hc_sock_t *s) {
  return hc_execute_async(s, ACTION_LIST, OBJECT_TYPE_FACE, NULL, NULL, NULL);
}

GENERATE_FIND(face);

DECLARE_OBJECT_OPS(OBJECT_TYPE_FACE, face);
