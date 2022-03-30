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
 * @file connection.c
 * @brief Implementation of hICN connections
 */

#include <assert.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/listener.h>
#include <hicn/util/log.h>
#include <hicn/core/wldr.h>

#include "connection.h"
#include "connection_vft.h"

#define _conn_var(x) _connection_##x

// This is called by configuration
connection_t *connection_create(face_type_t type, const char *name,
                                const address_pair_t *pair,
                                forwarder_t *forwarder) {
  assert(face_type_is_valid(type));
  assert(pair);
  assert(forwarder);

  face_type_t listener_type;
  switch (type) {
    case FACE_TYPE_UDP:
      listener_type = FACE_TYPE_UDP_LISTENER;
      break;
    case FACE_TYPE_TCP:
      listener_type = FACE_TYPE_TCP_LISTENER;
      break;
    default:
      return NULL;
  }

  listener_table_t *ltable = forwarder_get_listener_table(forwarder);
  listener_key_t key = listener_key_factory(pair->local, listener_type);

  listener_t *listener = listener_table_get_by_key(ltable, &key);
  if (!listener) {
    WITH_ERROR({
      char addr_str[NI_MAXHOST];
      int port;
      address_to_string(&pair->local, addr_str, &port);
      ERROR("Could not find listener to match address %s:%d", addr_str, port);
    })

    return NULL;
  }

  connection_table_t *table =
      forwarder_get_connection_table(listener->forwarder);
  unsigned connection_id = listener_create_connection(listener, name, pair);
  if (!connection_id_is_valid(connection_id)) return NULL;
  return connection_table_at(table, connection_id);
}

/**
 * @brief Initializes a connection
 *
 * @param [out] connection - Allocated connection buffer (eg. from pool) to be
 *      initialized.
 * @param [in] forwarder - forwarder_t to which the connection is associated.
 * This parameter needs to be non-NULL for connections receiving packets, such
 *      as TCP connections which are very close to UDP listeners, and unlike
 *      bound UDP connections).
 * @param [in] fd - A fd specific to the connection, or 0 if the connection
 *      should inherit the fd of the listener.
 * @return 0 if no error, -1 otherwise
 */
int connection_initialize(connection_t *connection, face_type_t type,
                          const char *name, const char *interface_name, int fd,
                          const address_pair_t *pair, bool local,
                          unsigned connection_id, listener_t *listener) {
  int rc;

  assert(connection);
  /* Interface name can be NULL eg always for TCP connnections */
  assert(pair);
  // assert(address_pair_is_valid(pair)); TODO: local addr in the pair is not
  // initialized for now

  if (fd == 0) WARN("Connection is not connected");

  *connection = (connection_t){
      .id = connection_id,
      .name = strdup(name),
      .type = type,
      .interface_name = strdup(interface_name),
      .pair = *pair,
      .fd = ((fd != 0) ? fd : listener_get_fd(listener)),
      .connected = (fd != 0),
      //        .up = true,
      .local = local,
      // XXX UDP should start UP, TCP DOWN until remove side answer ?
      .state = FACE_STATE_UNDEFINED,
      .admin_state = FACE_STATE_UP,
#ifdef WITH_POLICY
      .priority = 0,
#endif /* WITH_POLICY */

      .listener = listener,
      .closed = false,

      /* WLDR */
      .wldr = NULL,
      .wldr_autostart = true,
  };

  connection->data =
      malloc(connection_vft[get_protocol(connection->type)]->data_size);
  if (!connection->data) goto ERR_DATA;

  assert(connection_has_valid_id(connection));

  rc = connection_vft[get_protocol(connection->type)]->initialize(connection);
  if (rc < 0) {
    goto ERR_VFT;
  }

  if (connection->connected) {
    /*
     * The file descriptor is created by the listener. We assume for now that
     * all connections get their own fd, and we have to register it.
     *
     * TODO the connection has no more read callback, so we call the one from
     * the listener.
     */
    loop_fd_event_create(&connection->event_data, MAIN_LOOP, fd, listener,
                         (fd_callback_t)listener_read_callback, NULL);

    if (!connection->event_data) {
      goto ERR_REGISTER_FD;
    }

    if (loop_fd_event_register(connection->event_data) < 0) {
      goto ERR_REGISTER_FD;
    }
  }

  return 0;

ERR_REGISTER_FD:
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
ERR_VFT:
  free(connection->data);
ERR_DATA:
  free(connection->interface_name);
  free(connection->name);
  return -1;
}

int connection_finalize(connection_t *connection) {
  assert(connection);
  assert(connection_has_valid_type(connection));

  if (connection->connected) {
    loop_event_unregister(connection->event_data);
    loop_event_free(connection->event_data);
  }

  if (connection->fd != 0) {  // Only if connected socket
#ifndef _WIN32
    close(connection->fd);
#else
    closesocket(connection->fd);
#endif
  }

  if (connection->wldr) wldr_free(connection->wldr);

  connection_vft[get_protocol(connection->type)]->finalize(connection);

  if (connection->data) free(connection->data);
  connection->data = NULL;
  if (connection->interface_name) free(connection->interface_name);
  connection->interface_name = NULL;
  if (connection->name) free(connection->name);
  connection->name = NULL;

  return 0;
}

int connection_send_packet(const connection_t *connection,
                           const uint8_t *packet, size_t size) {
  assert(connection);
  assert(face_type_is_valid(connection->type));
  assert(packet);

  return connection_vft[get_protocol(connection->type)]->send_packet(
      connection, packet, size);
}

bool _connection_send(const connection_t *connection, msgbuf_t *msgbuf,
                      bool queue) {
  return connection_vft[get_protocol(connection->type)]->send(connection,
                                                              msgbuf, queue);
}

bool connection_flush(const connection_t *connection) {
  return connection_vft[get_protocol(connection->type)]->flush(connection);
}

bool connection_send(const connection_t *connection, off_t msgbuf_id,
                     bool queue) {
  assert(connection);
  assert(msgbuf_id_is_valid(msgbuf_id));

  // if (!connection_is_up(connection))
  //     return false;

  const listener_t *listener = connection_get_listener(connection);
  const forwarder_t *forwarder = listener_get_forwarder(listener);
  const msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  if (connection->wldr)
    wldr_set_label(connection->wldr, msgbuf);
  else
    msgbuf_reset_wldr_label(msgbuf);

  return _connection_send(connection, msgbuf, queue);
}

/*
 * here the wldr header is alreay set: this message is a retransmission or a
 * notification
 *
 * we need to recompute the path label since we always store a pointer to
 * the same message if this message will be sent again to someone else, the
 * new path label must be computed starting from the orignal label. Note
 * that we heve the same problem in case of PIT aggregation. That case is
 * handled inside the MessageProcessor. This is specific to WLDR
 * retransmittions. This is done only for data packets
 */
bool connection_resend(const connection_t *connection, msgbuf_t *msgbuf,
                       bool notification) {
  assert(connection);
  assert(msgbuf);

  bool ret = false;

  if (!connection_is_up(connection)) return ret;

  ret = _connection_send(connection, msgbuf, false); /* no queueing */

  return ret;
}

/* WLDR */

void connection_wldr_allow_autostart(connection_t *connection, bool value) {
  connection->wldr_autostart = value;
}

bool connection_wldr_autostart_is_allowed(const connection_t *connection) {
  return connection->wldr_autostart;
}

void connection_wldr_enable(connection_t *connection, bool value) {
  if (connection_is_local(connection)) return;
  if (value) {
    if (connection->wldr) return;
    connection->wldr = wldr_create();
  } else {
    if (!connection->wldr) return;
    wldr_free(connection->wldr);
  }
}

bool connection_has_wldr(const connection_t *connection) {
  return !!connection->wldr;
}

void connection_wldr_detect_losses(const connection_t *connection,
                                   const msgbuf_t *msgbuf) {
  if (!connection->wldr) return;
  wldr_detect_losses(connection->wldr, connection, msgbuf);
}

void connection_wldr_handle_notification(const connection_t *connection,
                                         const msgbuf_t *msgbuf) {
  if (!connection->wldr) return;
  wldr_handle_notification(connection->wldr, connection, msgbuf);
}
