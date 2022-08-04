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
 * \file connection.c
 * \brief Implementation of connection object.
 */

#include <assert.h>

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/object.h>
#include <hicn/ctrl/objects/connection.h>
#include <hicn/util/log.h>

#include "../object_private.h"
#include "../object_vft.h"
#include "base.h"

bool hc_connection_is_local(const hc_connection_t *connection) {
  return (strncmp(connection->interface_name, "lo", INTERFACE_LEN) == 0);
}

bool hc_connection_has_local(const hc_connection_t *connection) {
  assert(connection);
  return IS_VALID_PORT(connection->local_port) &&
         IS_VALID_ADDRESS(connection->local_addr);
}

/* CONNECTION VALIDATE */

int hc_connection_validate(const hc_connection_t *connection,
                           bool allow_partial) {
  int has_id = 0;
  int has_name = 0;
  int has_interface_name = 0;
  int has_netdevice_type = 0;
  int has_type = 0;
  int has_family = 0;
  int has_local_addr = 0;
  int has_local_port = 0;
  int has_remote_addr = 0;
  int has_remote_port = 0;
  int has_admin_state = 0;
  int has_priority = 0;
  int has_tags = 0;
  int has_state = 0;

  if (connection->id == ~0) {
    ERROR("[hc_listener_validate] Invalid id specified");
    return -1;
  }
  has_id = 1;

  if (!isempty(connection->name)) {
    if (!IS_VALID_NAME(connection->name)) {
      ERROR("[hc_connection_validate] Invalid name specified");
      return -1;
    }
    has_name = 1;
  }

  if (!isempty(connection->interface_name)) {
    if (!IS_VALID_INTERFACE_NAME(connection->interface_name)) {
      ERROR("[hc_connection_validate] Invalid interface_name specified");
      return -1;
    }
    has_interface_name = 1;
  }

  if (connection->type != FACE_TYPE_UNDEFINED) {
    if (!IS_VALID_TYPE(connection->type)) {
      ERROR("[hc_connection_validate] Invalid type specified");
      return -1;
    }
    has_type = 1;
  }

  if (connection->family != AF_UNSPEC) {
    if (!IS_VALID_FAMILY(connection->family)) {
      ERROR("[hc_connection_validate] Invalid family specified");
      return -1;
    }
    has_family = 1;
  }

  if (!hicn_ip_address_empty(&connection->local_addr)) {
    if (!IS_VALID_ADDRESS(connection->local_addr)) {
      ERROR("[hc_connection_validate] Invalid local_addr specified");
      return -1;
    }
    has_local_addr = 1;
  }

  if (connection->local_port != 0) {
    if (!IS_VALID_PORT(connection->local_port)) {
      ERROR("[hc_connection_validate] Invalid local_port specified");
      return -1;
    }
    has_local_port = 1;
  }

  if (!hicn_ip_address_empty(&connection->remote_addr)) {
    if (!IS_VALID_ADDRESS(connection->remote_addr)) {
      ERROR("[hc_connection_validate] Invalid remote_addr specified");
      return -1;
    }
    has_remote_addr = 1;
  }

  if (connection->remote_port != 0) {
    if (!IS_VALID_PORT(connection->remote_port)) {
      ERROR("[hc_connection_validate] Invalid remote_port specified");
      return -1;
    }
    has_remote_port = 1;
  }

  int has_key = has_id || has_name;
  int has_mandatory_attributes = has_interface_name && has_type && has_family &&
                                 has_local_addr && has_local_port &&
                                 has_remote_addr && has_remote_port;
  int has_optional_attributes =
      has_netdevice_type && has_admin_state && has_state;
  has_optional_attributes = has_optional_attributes && has_priority && has_tags;

  if (allow_partial) {
    if (has_key && !has_mandatory_attributes && !has_optional_attributes)
      return 0;
    else if (has_mandatory_attributes)
      return 0;
    else
      return -1;
  } else {
    if (has_key && has_mandatory_attributes) return 0;
    return -1;
  }
}

int _hc_connection_validate(const hc_object_t *object, bool allow_partial) {
  return hc_connection_validate(&object->connection, allow_partial);
}

/* CONNECTION CMP */

/*
 * hICN light uses ports even for hICN connections, but their value is
 * ignored. As connections are specific to hicn-light, we can safely use IP
 * and ports for comparison independently of the face type.
 */
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2) {
  int rc;

  rc = INT_CMP(c1->type, c2->type);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->family, c2->family);
  if (rc != 0) return rc;

  rc = strncmp(c1->interface_name, c2->interface_name, INTERFACE_LEN);
  if (rc != 0) return rc;

  rc = hicn_ip_address_cmp(&c1->local_addr, &c2->local_addr);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->local_port, c2->local_port);
  if (rc != 0) return rc;

  rc = hicn_ip_address_cmp(&c1->remote_addr, &c2->remote_addr);
  if (rc != 0) return rc;

  rc = INT_CMP(c1->remote_port, c2->remote_port);
  if (rc != 0) return rc;

  return rc;
}

int _hc_connection_cmp(const hc_object_t *object1, const hc_object_t *object2) {
  return hc_connection_cmp(&object1->connection, &object2->connection);
}

/* CONNECTION SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_connection_snprintf(char *s, size_t size,
                           const hc_connection_t *connection) {
  char local[MAXSZ_URL];
  char remote[MAXSZ_URL];
  int rc;

  // assert(connection->connection_state)
  if (strcmp(connection->name, "SELF") == 0) {
    return snprintf(s, size, "%s", connection->name);
  }

  rc = url_snprintf(local, MAXSZ_URL, &connection->local_addr,
                    connection->local_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_connection_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;
  rc = url_snprintf(remote, MAXSZ_URL, &connection->remote_addr,
                    connection->remote_port);
  if (rc >= MAXSZ_URL)
    WARN("[hc_connection_snprintf] Unexpected truncation of URL string");
  if (rc < 0) return rc;

  return snprintf(s, size, "%s %s %s %s", connection->name, local, remote,
                  face_type_str(connection->type));
}

int _hc_connection_snprintf(char *s, size_t size, const hc_object_t *object) {
  return hc_connection_snprintf(s, size, &object->connection);
}

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.connection = *connection;
  return hc_execute(s, ACTION_CREATE, OBJECT_TYPE_CONNECTION, &object, NULL);
}

int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_data_t **pdata) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.connection = *connection;
  return hc_execute(s, ACTION_GET, OBJECT_TYPE_CONNECTION, &object, pdata);
}

int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  object.connection = *connection;
  return hc_execute(s, ACTION_DELETE, OBJECT_TYPE_CONNECTION, &object, NULL);
}

int hc_connection_list(hc_sock_t *s, hc_data_t **pdata) {
  return hc_execute(s, ACTION_LIST, OBJECT_TYPE_CONNECTION, NULL, pdata);
}

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  int rc = snprintf(object.connection.name, SYMBOLIC_NAME_LEN, "%s",
                    conn_id_or_name);
  if (rc < 0 || rc >= SYMBOLIC_NAME_LEN) return -1;
  object.connection.admin_state = state;
  return hc_execute(s, ACTION_UPDATE, OBJECT_TYPE_CONNECTION, &object, NULL);
}

int hc_connection_set_priority(hc_sock_t *s, const char *conn_id_or_name,
                               uint32_t priority) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  int rc = snprintf(object.connection.name, SYMBOLIC_NAME_LEN, "%s",
                    conn_id_or_name);
  if (rc < 0 || rc >= SYMBOLIC_NAME_LEN) return -1;
  object.connection.priority = priority;
  return hc_execute(s, ACTION_UPDATE, OBJECT_TYPE_CONNECTION, &object, NULL);
}

int hc_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,

                           policy_tags_t tags) {
  hc_object_t object;
  memset(&object, 0, sizeof(hc_object_t));
  int rc = snprintf(object.connection.name, SYMBOLIC_NAME_LEN, "%s",
                    conn_id_or_name);
  if (rc < 0 || rc >= SYMBOLIC_NAME_LEN) return -1;
  object.connection.tags = tags;
  return hc_execute(s, ACTION_UPDATE, OBJECT_TYPE_CONNECTION, &object, NULL);
}

GENERATE_FIND(connection);

DECLARE_OBJECT_OPS(OBJECT_TYPE_CONNECTION, connection);
