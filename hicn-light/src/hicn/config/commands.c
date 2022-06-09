/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <ctype.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hicn/core/connection.h>
#include <hicn/core/connection_table.h>
#include <hicn/core/forwarder.h>
//#include <hicn/core/system.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#include <hicn/core/listener.h>  //the listener list
#include <hicn/core/listener_table.h>
#include <hicn/core/subscription.h>
#include <hicn/ctrl/hicn-light-ng.h>
#include <hicn/utils/punting.h>
#include <hicn/util/log.h>
#include <hicn/validation.h>
#include <hicn/face.h>

#include "commands.h"
#include "configuration.h"

#define ETHERTYPE 0x0801
#define DEFAULT_COST 1
#define DEFAULT_PORT 1234

#define make_ack(msg) ((msg_header_t *)msg)->header.message_type = ACK_LIGHT
#define make_nack(msg) ((msg_header_t *)msg)->header.message_type = NACK_LIGHT

#define msg_malloc_list(msg, COMMAND_ID, N, seq_number)                  \
  do {                                                                   \
    msg = calloc(1, sizeof((msg)->header) + N * sizeof((msg)->payload)); \
    (msg)->header.message_type = RESPONSE_LIGHT;                         \
    (msg)->header.command_id = (COMMAND_ID);                             \
    (msg)->header.length = (uint16_t)(N);                                \
    (msg)->header.seq_num = (seq_number);                                \
  } while (0);

// conn_id = UINT_MAX when symbolic_name is not found
static inline unsigned _symbolic_to_conn_id(forwarder_t *forwarder,
                                            const char *symbolic_or_connid,
                                            bool allow_self,
                                            unsigned ingress_id) {
  unsigned conn_id;
  const connection_table_t *table = forwarder_get_connection_table(forwarder);

  if (allow_self && strcmp(symbolic_or_connid, "SELF") == 0) {
    conn_id = ingress_id;
  } else if (is_number(symbolic_or_connid, SYMBOLIC_NAME_LEN)) {
    // case for conn_id as input
    // XXX type issue ! XXX No check, see man
    unsigned id = atoi(symbolic_or_connid);
    if (id < 0) return CONNECTION_ID_UNDEFINED;
    conn_id = id;

    if (!connection_table_validate_id(table, conn_id)) {
      ERROR("ConnID not found, check list connections");
      conn_id = CONNECTION_ID_UNDEFINED;
    }
  } else {
    // case for symbolic as input: check if symbolic name can be resolved
    conn_id = (unsigned int)connection_table_get_id_by_name(table,
                                                            symbolic_or_connid);
    if (connection_id_is_valid(conn_id)) {
      DEBUG("Resolved symbolic name '%s' to conn_id %u", symbolic_or_connid,
            conn_id);
    } else {
      WARN("Symbolic name '%s' could not be resolved", symbolic_or_connid);
    }
  }

  return conn_id;
}

#define symbolic_to_conn_id(forwarder, symbolic) \
  _symbolic_to_conn_id(forwarder, symbolic, false, 0)

#define symbolic_to_conn_id_self(forwarder, symbolic, ingress_id) \
  _symbolic_to_conn_id(forwarder, symbolic, true, ingress_id)

connection_t *getConnectionBySymbolicOrId(forwarder_t *forwarder,
                                          const char *symbolic_or_connid) {
  connection_table_t *table = forwarder_get_connection_table(forwarder);
  unsigned conn_id = symbolic_to_conn_id(forwarder, symbolic_or_connid);
  if (!connection_id_is_valid(conn_id)) return NULL;

  /* conn_id is assumed validated here */
  return connection_table_at(table, conn_id);
}

/* Listener */

uint8_t *configuration_on_listener_add(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id,
                                       size_t *reply_size) {
  INFO("CMD: listener add (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_listener_add_t *msg = (msg_listener_add_t *)packet;
  cmd_listener_add_t *control = &msg->payload;

  switch (control->type) {
    case FACE_TYPE_UDP_LISTENER:
    case FACE_TYPE_TCP_LISTENER:
    case FACE_TYPE_HICN_LISTENER:
      break;
    default:
      goto NACK;
  }

  listener_table_t *table = forwarder_get_listener_table(forwarder);
  assert(table);

  /* Verify that the listener DOES NOT exist */
  listener_t *listener = listener_table_get_by_name(table, control->symbolic);
  if (listener) {
    ERROR("Listener with name=%s already exists", control->symbolic);
    goto NACK;
  }

  address_t address;
  memset(&address, 0, sizeof(address_t));
  if (address_from_ip_port(&address, control->family, &control->address,
                           control->port) < 0) {
    WARN(
        "Unsupported address type for HICN (ingress id %u): "
        "must be either IPV4 or IPV6",
        ingress_id);
    goto NACK;
  }

  if (!face_type_is_defined(control->type)) {
    WARN("[configuration_on_listener_add] Invalid listener type");
    goto NACK;
  }

  listener = listener_table_get_by_address(table, control->type, &address);
  if (listener) {
    char addr_str[NI_MAXHOST];
    int port;
    address_to_string(&address, addr_str, &port);
    ERROR("Listener for address=%s, type=%s already exists", addr_str,
          face_type_str(control->type));
    goto NACK;
  }

  // NOTE: interface_name is expected NULL for hICN listener

  listener = listener_create(control->type, &address, control->interface_name,
                             control->symbolic, forwarder);
  if (!listener) goto NACK;

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

unsigned symbolic_to_listener_id(forwarder_t *forwarder,
                                 const char *symbolic_or_listener_id) {
  unsigned listener_id;
  const listener_table_t *table = forwarder_get_listener_table(forwarder);

  if (is_number(symbolic_or_listener_id, SYMBOLIC_NAME_LEN)) {
    // XXX type issue ! XXX No check, see man
    unsigned id = atoi(symbolic_or_listener_id);
    if (id < 0) return LISTENER_ID_UNDEFINED;
    listener_id = id;

    if (!listener_table_validate_id(table, listener_id)) {
      ERROR("Listener ID %d not found", id);
      listener_id = LISTENER_ID_UNDEFINED;
    }
  } else {
    // case for symbolic as input: check if symbolic name can be resolved
    listener_id = (unsigned int)listener_table_get_id_by_name(
        table, symbolic_or_listener_id);
    if (listener_id_is_valid(listener_id)) {
      DEBUG("Resolved symbolic name '%s' to conn_id %u",
            symbolic_or_listener_id, listener_id);
    } else {
      WARN("Symbolic name '%s' could not be resolved", symbolic_or_listener_id);
    }
  }

  return listener_id;
}

uint8_t *configuration_on_listener_remove(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size) {
  INFO("CMD: listener remove (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_listener_remove_t *msg = (msg_listener_remove_t *)packet;
  cmd_listener_remove_t *control = &msg->payload;

  unsigned listener_id =
      symbolic_to_listener_id(forwarder, control->symbolicOrListenerid);
  if (!listener_id_is_valid(listener_id)) {
    ERROR("Invalid listener id=%u", listener_id);
    goto NACK;
  }

  listener_table_t *listener_table = forwarder_get_listener_table(forwarder);
  listener_t *listener = listener_table_get_by_id(listener_table, listener_id);
  if (!listener) {
    ERROR("Listener ID not found, check list listeners");
    goto NACK;
  }

  // Do not remove listener if it is the one curretly used to send the command
  connection_table_t *conn_table = forwarder_get_connection_table(forwarder);
  connection_t *curr_connection =
      connection_table_get_by_id(conn_table, ingress_id);
  const address_pair_t *pair = connection_get_pair(curr_connection);
  if (address_equals(listener_get_address(listener),
                     address_pair_get_local(pair))) {
    ERROR("Cannot remove current listener");
    goto NACK;
  }

  connection_table_t *table = forwarder_get_connection_table(forwarder);
  connection_t *connection;
  connection_table_foreach(table, connection, {
    const address_pair_t *pair = connection_get_pair(connection);
    if (!address_equals(listener_get_address(listener),
                        address_pair_get_local(pair)))
      continue;

    unsigned conn_id =
        (unsigned int)connection_table_get_connection_id(table, connection);
    /* Remove connection from the FIB */
    forwarder_remove_connection_id_from_routes(forwarder, conn_id);

    /* Remove connection */
    connection_table_remove_by_id(table, conn_id);
  });

  /* Remove listener */
  listener_table_remove_by_id(listener_table, listener_id);
  listener_finalize(listener);
  WITH_DEBUG(listener_table_print_by_key(listener_table);)

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

// TODO(eloparco): Unused forwarder param
static inline void fill_listener_command(forwarder_t *forwarder,
                                         listener_t *listener,
                                         cmd_listener_list_item_t *cmd) {
  assert(forwarder);
  assert(listener);
  assert(cmd);

  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  const address_t *addr = listener_get_address(listener);

  cmd->id = (uint32_t)listener_get_id(listener);
  cmd->type = (uint8_t)listener_get_type(listener);

  switch (addr->as_ss.ss_family) {
    case AF_INET:
      sin = (struct sockaddr_in *)addr;
      cmd->family = AF_INET;
      cmd->address.v4.as_inaddr = sin->sin_addr;
      cmd->port = sin->sin_port;
      break;
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)addr;
      cmd->family = AF_INET6;
      cmd->address.v6.as_in6addr = sin6->sin6_addr;
      cmd->port = sin6->sin6_port;
      break;
    default:
      break;
  }

  const char *name = listener_get_name(listener);
  snprintf(cmd->name, SYMBOLIC_NAME_LEN, "%s", name);
  const char *interface_name = listener_get_interface_name(listener);
  snprintf(cmd->interface_name, SYMBOLIC_NAME_LEN, "%s", interface_name);
}

uint8_t *configuration_on_listener_list(forwarder_t *forwarder, uint8_t *packet,
                                        unsigned ingress_id,
                                        size_t *reply_size) {
  INFO("CMD: listener list (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  listener_table_t *table = forwarder_get_listener_table(forwarder);
  size_t n = listener_table_len(table);
  msg_listener_list_t *msg_received = (msg_listener_list_t *)packet;
  uint8_t command_id = msg_received->header.command_id;
  uint32_t seq_num = msg_received->header.seq_num;

  msg_listener_list_reply_t *msg;
  msg_malloc_list(msg, command_id, n, seq_num) if (!msg) goto NACK;

  cmd_listener_list_item_t *payload = &msg->payload;
  listener_t *listener;
  listener_table_foreach(table, listener, {
    fill_listener_command(forwarder, listener, payload);
    payload++;
  });

  *reply_size = sizeof(msg->header) + n * sizeof(msg->payload);
  return (uint8_t *)msg;

NACK:
  *reply_size = sizeof(msg_header_t);
  make_nack(msg);
  return (uint8_t *)msg;
}

/* Connection */

uint8_t *configuration_on_connection_add(forwarder_t *forwarder,
                                         uint8_t *packet, unsigned ingress_id,
                                         size_t *reply_size) {
  INFO("CMD: connection add (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_connection_add_t *msg = (msg_connection_add_t *)packet;
  cmd_connection_add_t *control = &msg->payload;

  switch (control->type) {
    case FACE_TYPE_UDP:
    case FACE_TYPE_TCP:
    case FACE_TYPE_HICN:
      break;
    default:
      goto NACK;
  }

  if (!face_type_is_defined(control->type)) goto NACK;

  connection_table_t *table = forwarder_get_connection_table(forwarder);
  char *symbolic_name = control->symbolic;

  // Generate connection name if not specified
  if (symbolic_name[0] == '\0') {
    int rc = connection_table_get_random_name(table, symbolic_name);
    if (rc < 0) {
      ERROR("Unable to generate new connection name");
      goto NACK;
    }
  } else {
    if (connection_table_get_by_name(table, symbolic_name)) {
      ERROR("Connection symbolic name already exists");
      goto NACK;
    }
  }

  address_pair_t pair;
  if (address_pair_from_ip_port(&pair, control->family, &control->local_ip,
                                control->local_port, &control->remote_ip,
                                control->remote_port) < 0)
    goto NACK;

  connection_t *connection = connection_table_get_by_pair(table, &pair);
#ifdef WITH_MAPME
  connection_event_t event;
#endif /* WITH_MAPME */

  if (!connection) {
    connection =
        connection_create(control->type, symbolic_name, &pair, forwarder);
    if (!connection) {
      ERROR("Failed to create %s connection", face_type_str(control->type));
      goto NACK;
    }

#ifdef WITH_MAPME
    event = CONNECTION_EVENT_CREATE;
#endif /* WITH_MAPME */
  } else {
    WARN("Connection already exists");

#ifdef WITH_MAPME
    event = CONNECTION_EVENT_UPDATE;
#endif /* WITH_MAPME */
  }

#ifdef WITH_POLICY
  connection_set_tags(connection, control->tags);
  connection_set_priority(connection, control->priority);
#endif /* WITH_POLICY */

  connection_set_admin_state(connection, control->admin_state);

#ifdef WITH_MAPME
  /* Hook: new connection created through the control protocol */
  forwarder_on_connection_event(forwarder, connection, event);
#endif /* WITH_MAPME */

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

/**
 * Add an IP-based tunnel.
 *
 * The call can fail if the symbolic name is a duplicate.  It could also fail if
 * there's an problem creating the local side of the tunnel (i.e. the local
 * socket address is not usable).
 *
 * @return true Tunnel added
 * @return false Tunnel not added (an error)
 */

uint8_t *configuration_on_connection_remove(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size) {
  INFO("CMD: connection remove (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_connection_remove_t *msg = (msg_connection_remove_t *)packet;
  cmd_connection_remove_t *control = &msg->payload;

  unsigned conn_id = symbolic_to_conn_id_self(
      forwarder, control->symbolic_or_connid, ingress_id);
  if (!connection_id_is_valid(conn_id)) {
    ERROR("Invalid connection id=%u", conn_id);
    goto NACK;
  }

  if (strcmp(control->symbolic_or_connid, "SELF") != 0 &&
      conn_id == ingress_id) {
    ERROR("Cannot remove current connection");
    goto NACK;
  }

  /* Remove connection from the FIB */
  forwarder_remove_connection_id_from_routes(forwarder, conn_id);

  /* Remove connection */
  connection_table_t *table = forwarder_get_connection_table(forwarder);
  connection_t *connection = connection_table_get_by_id(table, conn_id);
  connection_table_remove_by_id(table, conn_id);

  // Don't close the fd for SELF otherwise it won't be possible
  // to send the reply back
  if (strcmp(control->symbolic_or_connid, "SELF") != 0)
    connection_finalize(connection);
  WITH_DEBUG(connection_table_print_by_pair(table);)

#ifdef WITH_MAPME
  /* Hook: new connection created through the control protocol */
  forwarder_on_connection_event(forwarder, NULL, CONNECTION_EVENT_DELETE);
#endif /* WITH_MAPME */

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

static inline void tolower_str(char *str) {
  char *p = str;
  for (; *p; p++) *p = tolower(*p);
}

// TODO(eloparco): Forwarder param not used
static inline void fill_connections_command(forwarder_t *forwarder,
                                            connection_t *connection,
                                            cmd_connection_list_item_t *cmd) {
  assert(forwarder);
  assert(connection);
  assert(cmd);

  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;
  const address_pair_t *pair = connection_get_pair(connection);

  cmd->id = connection_get_id(connection),
  cmd->state = connection_get_state(connection),
  cmd->admin_state = connection_get_admin_state(connection),
  cmd->type = connection_get_type(connection),
#ifdef WITH_POLICY
  cmd->priority = connection_get_priority(connection),
  cmd->tags = connection_get_tags(connection),
#endif /* WITH_POLICY */

  snprintf(cmd->name, SYMBOLIC_NAME_LEN, "%s", connection_get_name(connection));
  tolower_str(cmd->name);

  snprintf(cmd->interface_name, SYMBOLIC_NAME_LEN, "%s",
           connection_get_interface_name(connection));

  switch (pair->local.as_ss.ss_family) {
    case AF_INET:
      cmd->family = AF_INET;

      sin = (struct sockaddr_in *)(&pair->local);
      cmd->local_port = sin->sin_port;
      cmd->local_addr.v4.as_inaddr = sin->sin_addr;

      sin = (struct sockaddr_in *)(&pair->remote);
      cmd->remote_port = sin->sin_port;
      cmd->remote_addr.v4.as_inaddr = sin->sin_addr;
      break;

    case AF_INET6:
      cmd->family = AF_INET6;

      sin6 = (struct sockaddr_in6 *)(&pair->local);
      cmd->local_port = sin6->sin6_port;
      cmd->local_addr.v6.as_in6addr = sin6->sin6_addr;

      sin6 = (struct sockaddr_in6 *)(&pair->remote);
      cmd->remote_port = sin6->sin6_port;
      cmd->remote_addr.v6.as_in6addr = sin6->sin6_addr;
      break;

    default:
      break;
  }
}

uint8_t *configuration_on_connection_list(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size) {
  INFO("CMD: connection list (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  connection_table_t *table = forwarder_get_connection_table(forwarder);
  // -1 since current connection (i.e. the one used to send
  // the command) is not considered
  size_t n = connection_table_len(table) - 1;
  msg_connection_list_t *msg_received = (msg_connection_list_t *)packet;
  uint8_t command_id = msg_received->header.command_id;
  uint32_t seq_num = msg_received->header.seq_num;

  msg_connection_list_reply_t *msg;
  msg_malloc_list(msg, command_id, n, seq_num) if (!msg) goto NACK;

  cmd_connection_list_item_t *payload = &msg->payload;
  connection_t *connection;
  connection_table_foreach(table, connection, {
    if (connection->id == ingress_id) continue;
    fill_connections_command(forwarder, connection, payload);
    payload++;
  });

  *reply_size = sizeof(msg->header) + n * sizeof(msg->payload);
  return (uint8_t *)msg;

NACK:
  *reply_size = sizeof(msg_header_t);
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_connection_set_admin_state(forwarder_t *forwarder,
                                                     uint8_t *packet,
                                                     unsigned ingress_id,
                                                     size_t *reply_size) {
  assert(forwarder);
  assert(packet);

  msg_connection_set_admin_state_t *msg =
      (msg_connection_set_admin_state_t *)packet;
  cmd_connection_set_admin_state_t *control = &msg->payload;

  if ((control->admin_state != FACE_STATE_UP) &&
      (control->admin_state != FACE_STATE_DOWN))
    goto NACK;

  connection_t *conn =
      getConnectionBySymbolicOrId(forwarder, control->symbolic_or_connid);
  if (!conn) goto NACK;

  connection_set_admin_state(conn, control->admin_state);

#ifdef WITH_MAPME
  /* Hook: connection event */
  forwarder_on_connection_event(forwarder, conn,
                                control->admin_state == FACE_STATE_UP
                                    ? CONNECTION_EVENT_SET_UP
                                    : CONNECTION_EVENT_SET_DOWN);
#endif /* WITH_MAPME */

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_connection_update(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size) {
  assert(forwarder);
  assert(packet);

#ifdef WITH_POLICY
  msg_connection_update_t *msg = (msg_connection_update_t *)packet;
  cmd_connection_update_t *control = &msg->payload;

  connection_t *conn =
      getConnectionBySymbolicOrId(forwarder, control->symbolic_or_connid);
  if (!conn) goto NACK;

  connection_set_tags(conn, control->tags);
  connection_set_admin_state(conn, control->admin_state);
  if (control->priority > 0) connection_set_priority(conn, control->priority);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif /* WITH_POLICY */
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_connection_set_priority(forwarder_t *forwarder,
                                                  uint8_t *packet,
                                                  unsigned ingress_id,
                                                  size_t *reply_size) {
  assert(forwarder);
  assert(packet);

#ifdef WITH_POLICY
  msg_connection_set_priority_t *msg = (msg_connection_set_priority_t *)packet;
  cmd_connection_set_priority_t *control = &msg->payload;

  connection_t *conn =
      getConnectionBySymbolicOrId(forwarder, control->symbolic_or_connid);
  if (!conn) goto NACK;

  connection_set_priority(conn, control->priority);

#ifdef WITH_MAPME
  /* Hook: connection event */
  forwarder_on_connection_event(forwarder, conn,
                                CONNECTION_EVENT_PRIORITY_CHANGED);
#endif /* WITH_MAPME */

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif /* WITH_POLICY */
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_connection_set_tags(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size) {
  assert(forwarder);
  assert(packet);

#ifdef WITH_POLICY
  msg_connection_set_tags_t *msg = (msg_connection_set_tags_t *)packet;
  cmd_connection_set_tags_t *control = &msg->payload;

  connection_t *conn =
      getConnectionBySymbolicOrId(forwarder, control->symbolic_or_connid);
  if (!conn) goto NACK;

  connection_set_tags(conn, control->tags);

#ifdef WITH_MAPME
  /* Hook: connection event */
  forwarder_on_connection_event(forwarder, conn, CONNECTION_EVENT_TAGS_CHANGED);
#endif /* WITH_MAPME */

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif /* WITH_POLICY */
  make_nack(msg);
  return (uint8_t *)msg;
}

/* Route */

uint8_t *configuration_on_route_add(forwarder_t *forwarder, uint8_t *packet,
                                    unsigned ingress_id, size_t *reply_size) {
  INFO("CMD: route add (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_route_add_t *msg = (msg_route_add_t *)packet;
  cmd_route_add_t *control = &msg->payload;

  unsigned conn_id = symbolic_to_conn_id_self(
      forwarder, control->symbolic_or_connid, ingress_id);
  if (!connection_id_is_valid(conn_id)) goto NACK;

  ip_prefix_t prefix = {.family = control->family,
                        .address = control->address,
                        .len = control->len};

  if (!forwarder_add_or_update_route(forwarder, &prefix, conn_id)) goto NACK;

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_route_remove(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id,
                                       size_t *reply_size) {
  INFO("CMD: route remove (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_route_remove_t *msg = (msg_route_remove_t *)packet;
  cmd_route_remove_t *control = &msg->payload;

  unsigned conn_id =
      symbolic_to_conn_id(forwarder, control->symbolic_or_connid);
  if (!connection_id_is_valid(conn_id)) goto NACK;

  ip_prefix_t prefix = {.family = control->family,
                        .address = control->address,
                        .len = control->len};

  if (!forwarder_remove_route(forwarder, &prefix, conn_id)) goto NACK;

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_route_list(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size) {
  INFO("CMD: route list (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  msg_route_list_t *msg_received = (msg_route_list_t *)packet;
  uint8_t command_id = msg_received->header.command_id;
  uint32_t seq_num = msg_received->header.seq_num;
  const fib_t *fib = forwarder_get_fib(forwarder);
  fib_entry_t *entry;

  /*
   * Two step approach to precompute the number of entries to allocate
   *
   * NOTE: we might have routes with no or multiple next hops.
   */
  size_t n = 0;
  fib_foreach_entry(fib, entry, {
    const nexthops_t *nexthops = fib_entry_get_nexthops(entry);
    assert(nexthops_get_len(nexthops) == nexthops_get_curlen(nexthops));
    n += nexthops_get_len(nexthops);
  });

  msg_route_list_reply_t *msg;
  msg_malloc_list(msg, command_id, n, seq_num);
  if (!msg) goto NACK;

  cmd_route_list_item_t *payload = &msg->payload;
  fib_foreach_entry(fib, entry, {
    const nexthops_t *nexthops = fib_entry_get_nexthops(entry);
    assert(nexthops_get_len(nexthops) == nexthops_get_curlen(nexthops));
    size_t num_nexthops = nexthops_get_len(nexthops);

    if (num_nexthops == 0) continue;

    NameBitvector *prefix = name_GetContentName(fib_entry_get_prefix(entry));

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
      address_t address;
      nameBitvector_ToAddress(prefix, &address);
      switch (address_family(&address)) {
        case AF_INET:
          payload->family = AF_INET;
          payload->address.v4.as_inaddr = address4_ip(&address);
          break;
        case AF_INET6:
          payload->family = AF_INET6;
          payload->address.v6.as_in6addr = address6_ip(&address);
          break;
        default:
          break;
      }
      payload->connection_id = nexthop;
      payload->len = nameBitvector_GetLength(prefix);
      payload->cost = DEFAULT_COST;

      payload++;
    });
  });

  *reply_size = sizeof(msg->header) + n * sizeof(msg->payload);
  return (uint8_t *)msg;

NACK:
  *reply_size = sizeof(msg_header_t);
  make_nack(msg);
  return (uint8_t *)msg;
}

/* Cache */

uint8_t *configuration_on_cache_set_store(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size) {
  INFO("CMD: cache set store (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_cache_set_store_t *msg = (msg_cache_set_store_t *)packet;
  cmd_cache_set_store_t *control = &msg->payload;

  if ((control->activate != 0) && (control->activate != 1)) goto NACK;
  bool value = (bool)control->activate;

  forwarder_cs_set_store(forwarder, value);
  assert(forwarder_cs_get_store(forwarder) == value);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_cache_set_serve(forwarder_t *forwarder,
                                          uint8_t *packet, unsigned ingress_id,
                                          size_t *reply_size) {
  INFO("CMD: cache set serve (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_cache_set_serve_t *msg = (msg_cache_set_serve_t *)packet;
  cmd_cache_set_serve_t *control = &msg->payload;

  if ((control->activate != 0) && (control->activate != 1)) goto NACK;
  bool value = (bool)control->activate;

  forwarder_cs_set_serve(forwarder, value);
  assert(forwarder_cs_get_serve(forwarder) == value);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_cache_clear(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size) {
  INFO("CMD: cache clear (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_cache_clear_t *msg = (msg_cache_clear_t *)packet;

  forwarder_cs_clear(forwarder);

  make_ack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_cache_list(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size) {
  INFO("CMD: cache list (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  msg_cache_list_t *msg_received = (msg_cache_list_t *)packet;
  uint32_t seq_num = msg_received->header.seq_num;

  msg_cache_list_reply_t *msg = malloc(sizeof(*msg));
  *msg = (msg_cache_list_reply_t){
      .header = {.message_type = RESPONSE_LIGHT,
                 .length = 1,
                 .seq_num = seq_num},
      .payload = {
          .store_in_cs = forwarder_cs_get_store(forwarder),
          .serve_from_cs = forwarder_cs_get_serve(forwarder),
          .cs_size = (unsigned int)forwarder_cs_get_size(forwarder),
          .num_stale_entries =
              (unsigned int)forwarder_cs_get_num_stale_entries(forwarder)}};

  *reply_size = sizeof(*msg);
  return (uint8_t *)msg;
}

/* Strategy */

uint8_t *configuration_on_strategy_set(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id,
                                       size_t *reply_size) {
  INFO("CMD: strategy set (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_strategy_set_t *msg = (msg_strategy_set_t *)packet;
  cmd_strategy_set_t *control = &msg->payload;

  char prefix_s[MAXSZ_IP_PREFIX];
  ip_prefix_t prefix = {
      .family = control->family,
      .address = control->address,
      .len = control->len,
  };
  int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, &prefix);
  assert(rc < MAXSZ_IP_PREFIX);
  if (rc < 0) goto NACK;

  strategy_type_t strategy = control->type;
  configuration_t *config = forwarder_get_configuration(forwarder);
  strategy_type_t existingFwdStrategy =
      configuration_get_strategy(config, prefix_s);
  strategy_options_t *options = NULL;

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, control->family, control->address,
                         control->len);

  // The strategy is not present in the hash table
  // or has to be updated or to be restarted
  if (existingFwdStrategy == STRATEGY_TYPE_UNDEFINED ||
      strategy != existingFwdStrategy ||
      (strategy == existingFwdStrategy && strategy == STRATEGY_TYPE_BESTPATH)) {
    configuration_set_strategy(config, prefix_s, strategy);

    forwarder_set_strategy(forwarder, &name_prefix, strategy, options);
  } else {
    WITH_WARN({
      char *nameString = name_ToString(&name_prefix);
      WARN("Strategy for prefix %s not updated", nameString);
      free(nameString);
    })
  }

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_strategy_add_local_prefix(forwarder_t *forwarder,
                                                    uint8_t *packet,
                                                    unsigned ingress_id,
                                                    size_t *reply_size) {
  INFO("CMD: strategy add local prefix (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_strategy_add_local_prefix_t *msg =
      (msg_strategy_add_local_prefix_t *)packet;
  cmd_strategy_add_local_prefix_t *control = &msg->payload;

  char prefix_s[MAXSZ_IP_PREFIX];
  ip_prefix_t prefix = {
      .family = control->family,
      .address = control->address,
      .len = control->len,
  };
  int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, &prefix);
  assert(rc < MAXSZ_IP_PREFIX);
  if (rc < 0) goto NACK;

  strategy_type_t strategy = control->type;
  configuration_t *config = forwarder_get_configuration(forwarder);
  strategy_type_t existingFwdStrategy =
      configuration_get_strategy(config, prefix_s);

  if (strategy != existingFwdStrategy) goto NACK;

  if (strategy != STRATEGY_TYPE_BESTPATH &&
      strategy != STRATEGY_TYPE_REPLICATION)
    goto NACK;

  Name name_prefix = EMPTY_NAME;
  name_CreateFromAddress(&name_prefix, control->family, control->address,
                         control->len);

  strategy_options_t options;
  Name local_prefix = EMPTY_NAME;
  name_CreateFromAddress(&local_prefix, control->local_family,
                         control->local_address, control->local_len);

  // for the moment bestpath and replication are the same but we distinguish the
  // two in case they will diverge in the future
  if (strategy == STRATEGY_TYPE_BESTPATH) {
    options.bestpath.local_prefixes = create_local_prefixes();
    local_prefixes_add_prefix(options.bestpath.local_prefixes, &local_prefix);
  } else {
    options.replication.local_prefixes = create_local_prefixes();
    local_prefixes_add_prefix(options.replication.local_prefixes,
                              &local_prefix);
  }

  forwarder_add_strategy_options(forwarder, &name_prefix, strategy, &options);

  free_local_prefixes(options.bestpath.local_prefixes);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

/* WLDR */

uint8_t *configuration_on_wldr_set(forwarder_t *forwarder, uint8_t *packet,
                                   unsigned ingress_id, size_t *reply_size) {
  assert(forwarder);
  assert(packet);

  msg_wldr_set_t *msg = (msg_wldr_set_t *)packet;
  cmd_wldr_set_t *control = &msg->payload;

  if ((control->activate != 0) && (control->activate != 1)) goto NACK;
  bool value = (bool)control->activate;

  unsigned conn_id =
      symbolic_to_conn_id(forwarder, control->symbolic_or_connid);
  if (!connection_id_is_valid(conn_id)) goto NACK;

  connection_table_t *table = forwarder_get_connection_table(forwarder);
  connection_t *conn = connection_table_at(table, conn_id);

  if (value) connection_wldr_enable(conn, value);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

/* Punting */

uint8_t *configuration_on_punting_add(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size) {
  // #if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  msg_punting_add_t *msg = (msg_punting_add_t *)packet;

#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
  cmd_punting_add_t *control = &msg->payload;
  if (ip_address_empty(&control->address)) goto NACK;

  /* This is for hICN listeners only */
  // XXX add check !
  // comments:
  // EncapType: I use the Hicn encap since the punting is available only for
  // Hicn listeners LocalAddress: The only listern for which we need punting
  // rules is the main one, which has no address
  //              so I create a fake empty address. This need to be consistent
  //              with the address set at creation time
  address_t fakeaddr;
  memset(&fakeaddr, 0, sizeof(address_t));
  fakeaddr = ADDRESS_ANY(control->family, DEFAULT_PORT);

  listener_table_t *table = forwarder_get_listener_table(forwarder);
  listener_t *listener =
      listener_table_get_by_address(table, FACE_TYPE_HICN, &fakeaddr);
  if (!listener) {
    ERROR("the main listener does not exist");
    goto NACK;
  }

  ip_prefix_t prefix = {.family = control->family,
                        .address = control->address,
                        .len = control->len};
  char prefix_s[MAXSZ_IP_PREFIX];
  int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, &prefix);
  assert(rc < MAXSZ_IP_PREFIX);
  if (rc < 0) goto NACK;

  if (listener_punt(listener, prefix_s) < 0) {
    ERROR("error while adding the punting rule");
    goto NACK;
  }

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif
  make_nack(msg);
  return (uint8_t *)msg;
}

/* MAP-Me */

#ifdef WITH_MAPME
uint8_t *configuration_on_mapme_enable(forwarder_t *forwarder, uint8_t *packet,
                                       unsigned ingress_id,
                                       size_t *reply_size) {
  INFO("CMD: mapme enable (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_mapme_enable_t *msg = (msg_mapme_enable_t *)packet;
  cmd_mapme_enable_t *control = &msg->payload;

  if ((control->activate != 0) && (control->activate != 1)) goto NACK;
  bool value = (bool)control->activate;

  INFO("MAP-Me SET enable: %s", value ? "on" : "off");
  mapme_t *mapme = forwarder_get_mapme(forwarder);
  if (!mapme) goto NACK;
  mapme_set_enable(mapme, value);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_mapme_set_discovery(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size) {
  INFO("CMD: mapme discovery (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_mapme_set_discovery_t *msg = (msg_mapme_set_discovery_t *)packet;
  cmd_mapme_set_discovery_t *control = &msg->payload;

  if ((control->activate != 0) && (control->activate != 1)) goto NACK;
  bool value = (bool)control->activate;

  INFO("MAP-Me SET discovery: %s", value ? "on" : "off");
  mapme_t *mapme = forwarder_get_mapme(forwarder);
  if (!mapme) goto NACK;
  mapme_set_discovery(mapme, value);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_mapme_set_timescale(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size) {
  INFO("CMD: mapme timescale (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_mapme_set_timescale_t *msg = (msg_mapme_set_timescale_t *)packet;
  cmd_mapme_set_timescale_t *control = &msg->payload;

  INFO("MAP-Me SET timescale: %u", control->timePeriod);
  mapme_t *mapme = forwarder_get_mapme(forwarder);
  if (!mapme) goto NACK;
  mapme_set_timescale(mapme, control->timePeriod);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_mapme_set_retx(forwarder_t *forwarder,
                                         uint8_t *packet, unsigned ingress_id,
                                         size_t *reply_size) {
  INFO("CMD: mapme retransmission (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_mapme_set_retx_t *msg = (msg_mapme_set_retx_t *)packet;
  cmd_mapme_set_retx_t *control = &msg->payload;

  INFO("MAP-Me SET retx: %u", control->timePeriod);
  mapme_t *mapme = forwarder_get_mapme(forwarder);
  if (!mapme) goto NACK;
  mapme_set_retransmision(mapme, control->timePeriod);

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_mapme_send_update(forwarder_t *forwarder,
                                            uint8_t *packet,
                                            unsigned ingress_id,
                                            size_t *reply_size) {
  assert(forwarder);
  assert(packet);

  INFO("CMD: mapme send update (ingress=%d)", ingress_id);
  msg_mapme_send_update_t *msg = (msg_mapme_send_update_t *)packet;

  *reply_size = sizeof(msg_header_t);

  fib_t *fib = forwarder_get_fib(forwarder);
  if (!fib) goto NACK;

  mapme_t *mapme = forwarder_get_mapme(forwarder);

  /*
   * The command triggers a mapme update for all prefixes produced on this face
   * */
  fib_entry_t *entry;
  fib_foreach_entry(fib, entry, {
    const nexthops_t *nexthops = fib_entry_get_nexthops(entry);
    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
      if (nexthop != ingress_id) continue;
      /* This entry points to the producer face */
      mapme_set_all_adjacencies(mapme, entry);
      break;
    });
  });

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}
#endif /* WITH_MAPME */

/* Policy */

uint8_t *configuration_on_policy_add(forwarder_t *forwarder, uint8_t *packet,
                                     unsigned ingress_id, size_t *reply_size) {
  assert(forwarder);
  assert(packet);

#ifdef WITH_POLICY
  msg_policy_add_t *msg = (msg_policy_add_t *)packet;
  cmd_policy_add_t *control = &msg->payload;

  ip_prefix_t prefix = {.family = control->family,
                        .address = control->address,
                        .len = control->len};

  if (!forwarder_add_or_update_policy(forwarder, &prefix, &control->policy))
    goto NACK;

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif /* WITH_POLICY */
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_policy_remove(forwarder_t *forwarder, uint8_t *packet,
                                        unsigned ingress_id,
                                        size_t *reply_size) {
  assert(forwarder);
  assert(packet);

#ifdef WITH_POLICY
  msg_policy_remove_t *msg = (msg_policy_remove_t *)packet;
  cmd_policy_remove_t *control = &msg->payload;

  ip_prefix_t prefix = {.family = control->family,
                        .address = control->address,
                        .len = control->len};

  if (!forwarder_remove_policy(forwarder, &prefix)) goto NACK;

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
#endif /* WITH_POLICY */
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_policy_list(forwarder_t *forwarder, uint8_t *packet,
                                      unsigned ingress_id, size_t *reply_size) {
  assert(forwarder);
  assert(packet);

  const fib_t *fib = forwarder_get_fib(forwarder);
  assert(fib);
  size_t n = fib_get_size(fib);

#ifdef WITH_POLICY
  msg_policy_list_t *msg_received = (msg_policy_list_t *)packet;
  uint8_t command_id = msg_received->header.command_id;
  uint32_t seq_num = msg_received->header.seq_num;

  msg_policy_list_reply_t *msg;
  msg_malloc_list(msg, command_id, n, seq_num);
  if (!msg) goto NACK;

  cmd_policy_list_item_t *payload = &msg->payload;

  fib_entry_t *entry;

  fib_foreach_entry(fib, entry, {
    NameBitvector *prefix = name_GetContentName(fib_entry_get_prefix(entry));
    address_t address;
    nameBitvector_ToAddress(prefix, &address);

    switch (address_family(&address)) {
      case AF_INET:
        payload->family = AF_INET;
        payload->address.v4.as_inaddr = address4_ip(&address);
        break;

      case AF_INET6:
        payload->family = AF_INET6;
        payload->address.v6.as_in6addr = address6_ip(&address);
        break;

      default:
        break;
    }
    payload->len = nameBitvector_GetLength(prefix);
    payload->policy = fib_entry_get_policy(entry);

    payload++;
  });

  return (uint8_t *)msg;
#endif /* WITH_POLICY */

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

/* Subscription */

uint8_t *configuration_on_subscription_add(forwarder_t *forwarder,
                                           uint8_t *packet, unsigned ingress_id,
                                           size_t *reply_size) {
  INFO("CMD: subscription add (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_subscription_add_t *msg = (msg_subscription_add_t *)packet;
  cmd_subscription_add_t *control = &msg->payload;
  hc_topics_t topics = control->topics;

  subscription_table_t *subscriptions = forwarder_get_subscriptions(forwarder);
  assert(subscriptions);

  int ret = subscription_table_add_topics_for_connection(subscriptions, topics,
                                                         ingress_id);
  if (ret < 0) goto NACK;

  WITH_DEBUG(subscription_table_print(subscriptions);)

  make_ack(msg);
  return (uint8_t *)msg;

NACK:
  make_nack(msg);
  return (uint8_t *)msg;
}

uint8_t *configuration_on_subscription_remove(forwarder_t *forwarder,
                                              uint8_t *packet,
                                              unsigned ingress_id,
                                              size_t *reply_size) {
  INFO("CMD: subscription remove (ingress=%d)", ingress_id);
  assert(forwarder);
  assert(packet);

  *reply_size = sizeof(msg_header_t);
  msg_subscription_add_t *msg = (msg_subscription_add_t *)packet;
  cmd_subscription_add_t *control = &msg->payload;
  hc_topics_t topics = control->topics;

  subscription_table_t *subscriptions = forwarder_get_subscriptions(forwarder);
  assert(subscriptions);

  subscription_table_remove_topics_for_connection(subscriptions, topics,
                                                  ingress_id);
  WITH_DEBUG(subscription_table_print(subscriptions);)

  make_ack(msg);
  return (uint8_t *)msg;
}

uint8_t *command_process(forwarder_t *forwarder, uint8_t *packet,
                         command_type_t command_type, unsigned ingress_id,
                         size_t *reply_size) {
  uint8_t *reply = NULL;

  /*
   * For most commands, the packet will simply be transformed into an ack.
   * For list commands, a new message will be allocated, and the return value
   * might eventually be NULL in case of an error. That is why the free the
   * reply at the end in these circumstances.
   *
   * XXX rework this part.
   */
  switch (command_type) {
#define _(l, u)                                                              \
  case COMMAND_TYPE_##u:                                                     \
    reply = configuration_on_##l(forwarder, packet, ingress_id, reply_size); \
    assert(reply);                                                           \
    break;
    foreach_command_type
#undef _
        case COMMAND_TYPE_UNDEFINED : case COMMAND_TYPE_N
        : ERROR("Unexpected command type");
    reply = packet;
    make_nack(reply);
    if (reply_size) *reply_size = sizeof(msg_header_t);
    break;
  }

  return reply;
}

ssize_t command_process_msgbuf(forwarder_t *forwarder, msgbuf_t *msgbuf) {
  assert(forwarder);
  assert(msgbuf);

  uint8_t *packet = msgbuf_get_packet(msgbuf);
  unsigned ingress_id = msgbuf_get_connection_id(msgbuf);

  uint8_t *reply = NULL;
  size_t reply_size = 0;

  command_type_t command_type = msgbuf_get_command_type(msgbuf);

  reply =
      command_process(forwarder, packet, command_type, ingress_id, &reply_size);
  if (connection_id_is_valid(msgbuf->connection_id)) {
    connection_table_t *table = forwarder_get_connection_table(forwarder);
    const connection_t *connection = connection_table_at(table, ingress_id);
    connection_send_packet(connection, reply, reply_size);
  }

  switch (msgbuf->command.type) {
    case COMMAND_TYPE_LISTENER_LIST:
    case COMMAND_TYPE_CONNECTION_LIST:
    case COMMAND_TYPE_ROUTE_LIST:
    case COMMAND_TYPE_POLICY_LIST:
      /* Free replies that have been allocated (not NACK's) */
      if (((msg_header_t *)reply)->header.message_type != NACK_LIGHT)
        free(reply);
      break;
    default:
      break;
  }

  return msgbuf_get_len(msgbuf);
}
