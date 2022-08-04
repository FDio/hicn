/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <assert.h>
#include <stdint.h>

#include <hicn/util/log.h>

#include "base.h"
#include "connection.h"
#include "../../object_private.h"

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener) {
  int rc;

  face_type_t listener_type;
  switch (connection->type) {
    case FACE_TYPE_UDP:
      listener_type = FACE_TYPE_UDP_LISTENER;
      break;
    case FACE_TYPE_TCP:
      listener_type = FACE_TYPE_TCP_LISTENER;
      break;
    default:
      return -1;
  }

  *listener = (hc_listener_t){
      .id = ~0,
      .type = listener_type,
      .family = connection->family,
      .local_addr = connection->local_addr,
      .local_port = connection->local_port,
  };
  rc = snprintf(listener->name, SYMBOLIC_NAME_LEN, "lst%u",
                RANDBYTE());  // generate name
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[hc_connection_to_local_listener] Unexpected truncation of "
        "symbolic name string");
  rc = snprintf(listener->interface_name, INTERFACE_LEN, "%s",
                connection->interface_name);
  if (rc >= INTERFACE_LEN)
    WARN(
        "[hc_connection_to_local_listener] Unexpected truncation of "
        "interface name string");

  return 0;
}

/* CONNECTION PARSE */

static int hicnlight_connection_parse(const uint8_t *buffer, size_t size,
                                      hc_connection_t *connection) {
  int rc;

  if (size != sizeof(cmd_connection_list_item_t)) return -1;
  cmd_connection_list_item_t *item = (cmd_connection_list_item_t *)buffer;

  if (!IS_VALID_ID(item->id)) {
    ERROR("[hc_connection_parse] Invalid id received");
    return -1;
  }

  if (!IS_VALID_NAME(item->name)) {
    ERROR("[hc_connection_parse] Invalid name received");
    return -1;
  }
  if (!IS_VALID_INTERFACE_NAME(item->interface_name)) {
    ERROR("[hc_connection_parse] Invalid interface_name received");
    return -1;
  }

  if (!IS_VALID_TYPE(item->type)) {
    ERROR("[hc_connection_parse] Invalid type received");
    return -1;
  }

  if (!IS_VALID_FAMILY(item->family)) {
    ERROR("[hc_connection_parse] Invalid family received");
    return -1;
  }

  if (!IS_VALID_ADDRESS(item->local_address)) {
    ERROR("[hc_connection_parse] Invalid address received");
    return -1;
  }

  if (!IS_VALID_PORT(ntohs(item->local_port))) {
    ERROR("[hc_connection_parse] Invalid port received");
    return -1;
  }

  if (!IS_VALID_ADDRESS(item->remote_address)) {
    ERROR("[hc_connection_parse] Invalid address received");
    return -1;
  }

  if (!IS_VALID_PORT(ntohs(item->remote_port))) {
    ERROR("[hc_connection_parse] Invalid port received");
    return -1;
  }

  if (!IS_VALID_FACE_STATE(item->admin_state)) {
    ERROR("[hc_connection_parse] Invalid admin_state received");
    return -1;
  }

  // PRIORITY
  // TAGS

  if (!IS_VALID_FACE_STATE(item->state)) {
    ERROR("[hc_connection_parse] Invalid state received");
    return -1;
  }

  *connection = (hc_connection_t){
      .id = item->id,
      .type = (face_type_t)item->type,
      .family = (int)item->family,
      .local_addr = item->local_addr,
      .local_port = ntohs(item->local_port),
      .remote_addr = item->remote_addr,
      .remote_port = ntohs(item->remote_port),
      .admin_state = (face_state_t)item->admin_state,
      .priority = item->priority,
      .tags = item->tags,
      .state = (face_state_t)item->state,
  };
  rc = snprintf(connection->name, SYMBOLIC_NAME_LEN, "%s", item->name);
  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  rc = snprintf(connection->interface_name, INTERFACE_LEN, "%s",
                item->interface_name);
  if ((rc < 0) || (rc >= INTERFACE_LEN)) return -1;

  if (hc_connection_validate(connection, false) < 0) return -1;
  return 0;
}

int _hicnlight_connection_parse(const uint8_t *buffer, size_t size,
                                hc_object_t *object) {
  return hicnlight_connection_parse(buffer, size, &object->connection);
}

/* CONNECTION CREATE */

int hicnlight_connection_serialize_create(const hc_object_t *object,
                                          uint8_t *packet) {
  int rc;
  const hc_connection_t *connection = &object->connection;

  msg_connection_add_t *msg = (msg_connection_add_t *)packet;
  *msg = (msg_connection_add_t){
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_ADD,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          .remote_ip = connection->remote_addr,
          .local_ip = connection->local_addr,
          .remote_port = htons(connection->remote_port),
          .local_port = htons(connection->local_port),
          .family = (uint8_t)connection->family,
          .type = (uint8_t)connection->type,
          .admin_state = (uint8_t)connection->admin_state,
          .__pad = 0,
          .priority = connection->priority,
          .tags = connection->tags,
      }};

  rc = snprintf(msg->payload.symbolic, SYMBOLIC_NAME_LEN, "%s",
                connection->name);
  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  return sizeof(msg_connection_add_t);
}

/* CONNECTION DELETE */

int hicnlight_connection_serialize_delete(const hc_object_t *object,
                                          uint8_t *packet) {
  int rc;
  const hc_connection_t *connection = &object->connection;

  msg_connection_remove_t *msg = (msg_connection_remove_t *)packet;
  *msg = (msg_connection_remove_t){
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_REMOVE,
              .length = 1,
              .seq_num = 0,
          },
  };

  if (connection->id) {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  connection->id);
    // XXX
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
  } else if (*connection->name) {
    rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                  connection->name);
    // XXX
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
#if 0
  } else {
    hc_connection_t *connection_found;
    if (hc_connection_get(socket, connection, &connection_found) < 0)
      return res;
    if (!connection_found) return res;
    rc = snprintf(payload->symbolic_or_connid, SYMBOLIC_NAME_LEN, "%d",
                  connection_found->id);
    // XXX
    if (rc >= SYMBOLIC_NAME_LEN)
      WARN(
          "[_hc_connection_delete] Unexpected truncation of symbolic name "
          "string");
    free(connection_found);
#endif
  }

  return sizeof(msg_connection_remove_t);
}

// XXX How to update a connection XXX
// Key attributes are mandatory
// Enum can be undefined
// family UNSPEC
// ip address NULL
// port NULL
// priority = int ????????? specific negative value == unspec
// tags = bitmap ????????? 0xFFFFFF special value == unspec

//  u32 id;                             /* Kr. */
//  char name[SYMBOLIC_NAME_LEN];       /* K.w */
//  char interface_name[INTERFACE_LEN]; /* Kr. */
//
//  netdevice_type_t netdevice_type; undefined
//  face_type_t type;
//  int family;
//  ip_address_t local_addr;
//  u16 local_port;
//  ip_address_t remote_addr;
//  u16 remote_port;
//  face_state_t admin_state;
//  uint32_t priority;  /* .rw */
//  policy_tags_t tags; /* .rw */
//  face_state_t state; /* .r. */
int hicnlight_connection_serialize_update(const hc_object_t *object,
                                          uint8_t *packet) {
  int rc;
  const hc_connection_t *connection = &object->connection;

  msg_connection_update_t *msg = (msg_connection_update_t *)packet;
  *msg = (msg_connection_update_t){
      .header =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_UPDATE,
              .length = 1,
              .seq_num = 0,
          },
      .payload = {
          //.remote_ip = connection->remote_updater,
          //.local_ip = connection->local_updater,
          //.remote_port = htons(connection->remote_port),
          //.local_port = htons(connection->local_port),
          //.family = connection->family,
          //.type = connection->type,
          .admin_state = connection->admin_state,
          .priority = connection->priority,
          .tags = connection->tags,
      }};

  rc = snprintf(msg->payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                connection->name);
  if ((rc < 0) || (rc >= SYMBOLIC_NAME_LEN)) return -1;

  // snprintf(msg.payload.interface_name, INTERFACE_NAME_LEN, "%s",
  // connection->interface_name);

  return sizeof(msg_connection_update_t);
}

#if 0
/* CONNECTION SET ADMIN STATE */

static int _hicnlight_connection_set_admin_state_internal(
    hc_sock_t *socket, const char *conn_id_or_name, face_state_t state,
    bool async) {
  int rc;
  DEBUG(
      "[hc_connection_set_admin_state] connection_id/name=%s admin_state=%s "
      "async=%s",
      conn_id_or_name, face_state_str(state), BOOLSTR(async));

  struct {
    cmd_header_t hdr;
    cmd_connection_set_admin_state_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_ADMIN_STATE,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .admin_state = state,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_admin_state] Unexpected truncation of symbolic "
        "name string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_ADMIN_STATE,
      .size_in = sizeof(cmd_connection_set_admin_state_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hicnlight_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hicnlight_connection_set_admin_state(hc_sock_t *s,
                                            const char *conn_id_or_name,
                                            face_state_t state) {
  return _hicnlight_connection_set_admin_state_internal(s, conn_id_or_name, state,
                                                   false);
}

static int _hicnlight_connection_set_admin_state_async(hc_sock_t *s,
                                                  const char *conn_id_or_name,
                                                  face_state_t state) {
  return _hicnlight_connection_set_admin_state_internal(s, conn_id_or_name, state,
                                                   true);
}


static int _hicnlight_connection_set_priority_internal(hc_sock_t *socket,
                                                  const char *conn_id_or_name,
                                                  uint32_t priority,
                                                  bool async) {
  int rc;
  DEBUG(
      "[hc_connection_set_priority] connection_id/name=%s priority=%d "
      "async=%s",
      conn_id_or_name, priority, BOOLSTR(async));
  struct {
    cmd_header_t hdr;
    cmd_connection_set_priority_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_PRIORITY,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .priority = priority,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_priority] Unexpected truncation of symbolic "
        "name "
        "string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_PRIORITY,
      .size_in = sizeof(cmd_connection_set_priority_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hicnlight_execute_command(socket, (hc_msg_t *)&msg, sizeof(msg), &params,
                               NULL, async);
}

static int _hicnlight_connection_set_priority(hc_sock_t *s,
                                         const char *conn_id_or_name,
                                         uint32_t priority) {
  return _hicnlight_connection_set_priority_internal(s, conn_id_or_name, priority,
                                                false);
}

static int _hicnlight_connection_set_priority_async(hc_sock_t *s,
                                               const char *conn_id_or_name,
                                               uint32_t priority) {
  return _hicnlight_connection_set_priority_internal(s, conn_id_or_name, priority,
                                                true);
}


static int _hicnlight_connection_set_tags_internal(hc_sock_t *s,
                                              const char *conn_id_or_name,
                                              policy_tags_t tags, bool async) {
  int rc;
  DEBUG("[hc_connection_set_tags] connection_id/name=%s tags=%d async=%s",
        conn_id_or_name, tags, BOOLSTR(async));
  struct {
    cmd_header_t hdr;
    cmd_connection_set_tags_t payload;
  } msg = {
      .hdr =
          {
              .message_type = REQUEST_LIGHT,
              .command_id = COMMAND_TYPE_CONNECTION_SET_TAGS,
              .length = 1,
              .seq_num = 0,
          },
      .payload =
          {
              .tags = tags,
          },
  };
  rc = snprintf(msg.payload.symbolic_or_connid, SYMBOLIC_NAME_LEN, "%s",
                conn_id_or_name);
  if (rc >= SYMBOLIC_NAME_LEN)
    WARN(
        "[_hc_connection_set_tags] Unexpected truncation of symbolic name "
        "string");

  hc_command_params_t params = {
      .cmd = ACTION_SET,
      .cmd_id = COMMAND_TYPE_CONNECTION_SET_TAGS,
      .size_in = sizeof(cmd_connection_set_tags_t),
      .size_out = 0,
      .parse = NULL,
  };

  return _hicnlight_execute_command(s, (hc_msg_t *)&msg, sizeof(msg), &params, NULL,
                               async);
}

static int _hicnlight_connection_set_tags(hc_sock_t *s, const char *conn_id_or_name,
                                     policy_tags_t tags) {
  return _hicnlight_connection_set_tags_internal(s, conn_id_or_name, tags, false);
}

static int _hicnlight_connection_set_tags_async(hc_sock_t *s,
                                           const char *conn_id_or_name,
                                           policy_tags_t tags) {
  return _hicnlight_connection_set_tags_internal(s, conn_id_or_name, tags, true);
}
#endif

/* CONNECTION LIST */

int hicnlight_connection_serialize_list(const hc_object_t *object,
                                        uint8_t *packet) {
  msg_connection_list_t *msg = (msg_connection_list_t *)packet;
  *msg = (msg_connection_list_t){.header = {
                                     .message_type = REQUEST_LIGHT,
                                     .command_id = COMMAND_TYPE_CONNECTION_LIST,
                                     .length = 0,
                                     .seq_num = 0,
                                 }};
  return sizeof(msg_header_t);  // Do not use msg_connection_list_t
}

DECLARE_MODULE_OBJECT_OPS(hicnlight, connection);
