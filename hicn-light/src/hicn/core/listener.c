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
 * @file listener.c
 * @brief Implementation of hICN listeners
 */

#include <string.h>  // strdup

#include <hicn/util/log.h>

#include "forwarder.h"
#include "listener_vft.h"
#include "../io/base.h"

listener_key_t listener_key_factory(address_t address, face_type_t type) {
  listener_key_t key;
  memset(&key, 0, sizeof(listener_key_t));

  key.address = address;
  key.type = type;
  return key;
}

listener_t *listener_create(face_type_t type, const address_t *address,
                            const char *interface_name, const char *name,
                            forwarder_t *forwarder) {
  listener_table_t *table = forwarder_get_listener_table(forwarder);

  listener_key_t key = listener_key_factory(*address, type);

  listener_t *listener = listener_table_allocate(table, &key, name);
  unsigned listener_id =
      (unsigned int)listener_table_get_listener_id(table, listener);

  int ret = listener_initialize(listener, type, name, listener_id, address,
                                interface_name, forwarder);
  if (ret < 0) {
    listener_table_remove_by_id(table, listener_id);
    listener_finalize(listener);
    return NULL;
  }

  WITH_INFO({
    char addr_str[NI_MAXHOST];
    int port;
    address_to_string(address, addr_str, &port);
    INFO("LISTENER CREATE (%s) %p created for address %s:%d",
         face_type_str(listener->type), listener, addr_str, port);
    listener_table_print_by_key(table);
  })

  return listener;
}

int listener_initialize(listener_t *listener, face_type_t type,
                        const char *name, unsigned listener_id,
                        const address_t *address, const char *interface_name,
                        forwarder_t *forwarder) {
  int rc;

  assert(listener);
  assert(forwarder);

  *listener = (listener_t){
      .id = listener_id,
      .name = strdup(name),
      .key = listener_key_factory(*address, type),
      .interface_name = strdup(interface_name),
      .family = address->as_ss.ss_family,
      .fd = 0,
      .forwarder = forwarder,
  };

  face_protocol_t face_protocol = get_protocol(listener->type);
  if (face_protocol == FACE_PROTOCOL_UNKNOWN) goto ERR_VFT;

  listener->data = malloc(listener_vft[face_protocol]->data_size);
  if (!listener->data) goto ERR_DATA;

  assert(listener_has_valid_type(listener));

  rc = listener_vft[face_protocol]->initialize(listener);
  if (rc < 0) goto ERR_VFT;

  listener->fd = listener_vft[face_protocol]->get_socket(listener, address,
                                                         NULL, interface_name);
  if (listener->fd < 0) {
    char addr_str[NI_MAXHOST];
    int port;
    address_to_string(address, addr_str, &port);
    ERROR("Error creating listener %s fd: (%d) %s", addr_str, errno,
          strerror(errno));
    goto ERR_FD;
  }
  assert(listener->fd > 0);

  // XXX data should be pre-allocated here

  loop_fd_event_create(&listener->event_data, MAIN_LOOP, listener->fd, listener,
                       (fd_callback_t)listener_read_callback, NULL);

  if (!listener->event_data) {
    goto ERR_REGISTER_FD;
  }

  if (loop_fd_event_register(listener->event_data) < 0) {
    goto ERR_REGISTER_FD;
  }

  return 0;

ERR_REGISTER_FD:
#ifndef _WIN32
  close(listener->fd);
#else
  closesocket(listener->fd);
#endif
ERR_FD:
ERR_VFT:
ERR_DATA:
  return -1;
}

int listener_finalize(listener_t *listener) {
  assert(listener);
  assert(listener_has_valid_type(listener));

  if (listener->event_data) {
    loop_event_unregister(listener->event_data);
    loop_event_free(listener->event_data);
  }

  if (listener->fd != -1) {
#ifndef _WIN32
    close(listener->fd);
#else
    closesocket(listener->fd);
#endif
  }

  listener_vft[get_protocol(listener->type)]->finalize(listener);

  if (listener->data) free(listener->data);
  listener->data = NULL;
  if (listener->interface_name) free(listener->interface_name);
  listener->interface_name = NULL;
  if (listener->name) free(listener->name);
  listener->name = NULL;

  return 0;
}

int listener_get_socket(const listener_t *listener, const address_t *local,
                        const address_t *remote, const char *interface_name) {
  assert(listener);
  assert(listener_has_valid_type(listener));
  assert(local);
  // assert(remote); TODO: can it be null?

  // DEBUG("[listener_get_socket]");

  return listener_vft[get_protocol(listener->type)]->get_socket(
      listener, local, remote, interface_name);
}

/*
 * This is called from the forwarder to dynamially create new connections on the
 * listener, in that case, name is NULL. It is also called from
 * connection_create, which is itself called from the configuration part.
 */
unsigned listener_create_connection(listener_t *listener,
                                    const char *connection_name,
                                    const address_pair_t *pair) {
  assert(listener);
  assert(listener_has_valid_type(listener));
  assert(pair);

  connection_table_t *table =
      forwarder_get_connection_table(listener->forwarder);
  connection_t *connection =
      connection_table_allocate(table, pair, connection_name);
  unsigned connection_id =
      (unsigned int)connection_table_get_connection_id(table, connection);

  /*
   * We create a connected connection with its own fd, instead of returning
   * the fd of the listener. This will allow to avoid specifying the
   * destination address when sending packets, and will increase performance
   * by avoiding a FIB lookup for each packet.
   */
#ifdef USE_CONNECTED_SOCKETS
  int fd = listener_get_socket(listener, address_pair_get_local(pair),
                               address_pair_get_remote(pair),
                               listener->interface_name);
#else
  int fd = 0;  // means listener->fd;
#endif
  bool local = address_is_local(address_pair_get_local(pair));

  face_type_t connection_type;
  switch (listener->type) {
    case FACE_TYPE_UDP_LISTENER:
      connection_type = FACE_TYPE_UDP;
      break;
    case FACE_TYPE_TCP_LISTENER:
      connection_type = FACE_TYPE_TCP;
      break;
    default:
      connection_table_remove_by_id(table, connection_id);
      return CONNECTION_ID_UNDEFINED;
  }

  int rc = connection_initialize(connection, connection_type, connection_name,
                                 listener->interface_name, fd, pair, local,
                                 connection_id, listener);
  if (rc < 0) {
    connection_table_remove_by_id(table, connection_id);
    connection_finalize(connection);
    return CONNECTION_ID_UNDEFINED;
  }

  WITH_INFO({
    char local_addr_str[NI_MAXHOST];
    char remote_addr_str[NI_MAXHOST];
    int local_port;
    int remote_port;
    address_to_string(&(pair->local), local_addr_str, &local_port);
    address_to_string(&(pair->remote), remote_addr_str, &remote_port);
    INFO("%s connection %p created for address pair %s:%d (local=%s) - %s:%d",
         face_type_str(connection->type), connection, local_addr_str,
         local_port, connection_is_local(connection) ? "true" : "false",
         remote_addr_str, remote_port);
    connection_table_print_by_pair(table);
  })

#if 0
  DEBUG("Notification for new connections");
  // Generate notification message
  flag_interface_type_t interface_type =
      FLAG_INTERFACE_TYPE_WIRED | FLAG_INTERFACE_TYPE_CELLULAR;
  struct {
    cmd_header_t header;
    hc_event_interface_update_t payload;
  } msg = {.header =
               {
                   .message_type = NOTIFICATION_LIGHT,
                   .command_id = EVENT_INTERFACE_UPDATE,
                   .length = 0,
                   .seq_num = 0,
               },
           .payload = {.interface_type = interface_type}};
  size_t size = sizeof(msg);

  // Retrieve subscribed connections
  subscription_table_t *subscriptions =
      forwarder_get_subscriptions(listener->forwarder);
  unsigned *subscribed_conn_ids = subscription_table_get_connections_for_topic(
      subscriptions, TOPIC_CONNECTION);

  // Send notification to subscribed connections
  for (int i = 0; i < vector_len(subscribed_conn_ids); i++) {
    DEBUG("Sending notification to connection: %u", subscribed_conn_ids[i]);
    const connection_t *conn =
        connection_table_at(table, subscribed_conn_ids[i]);
    connection_send_packet(conn, (uint8_t *)&msg, size);
  }
#endif

  return connection_id;
}

int listener_punt(const listener_t *listener, const char *prefix_s) {
  assert(listener);
  assert(listener_get_type(listener) == FACE_TYPE_HICN);
  assert(prefix_s);

  return listener_vft[get_protocol(listener->type)]->punt(listener, prefix_s);
}

ssize_t listener_read_single(listener_t *listener, int fd) {
  assert(listener);

  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(listener->forwarder);

  // Preapare the msgbuf
  msgbuf_t *msgbuf = NULL;
  off_t msgbuf_id = msgbuf_pool_get(msgbuf_pool, &msgbuf);
  if (!msgbuf_id_is_valid(msgbuf_id)) return -1;

  // Prepare the address pair
  address_pair_t pair;
  memset(&pair, 0, sizeof(address_pair_t));
  pair.local = listener->address;

  // Read message and populate the remote address
  ssize_t n = listener_vft[get_protocol(listener->type)]->read_single(
      fd, msgbuf, address_pair_get_remote(&pair));
  if (n <= 0) {
    msgbuf_pool_put(msgbuf_pool, msgbuf);
    return -1;
  }

  msgbuf_pool_acquire(msgbuf);

  // Process received packet
  size_t processed_bytes = forwarder_receive(listener->forwarder, listener,
                                             msgbuf_id, &pair, ticks_now());
  forwarder_log(listener->forwarder);
  if (processed_bytes <= 0) ERROR("Unable to handle message");

  /*
   * The connection on which we went packets might do batching (even without
   * sendmmsg), and we need to inform the system that we want to proceed to
   * sending packets.
   */
  forwarder_flush_connections(listener->forwarder);
  msgbuf_pool_release(msgbuf_pool, &msgbuf);
  return processed_bytes;
}

ssize_t listener_read_batch(listener_t *listener, int fd) {
  assert(listener);

  size_t total_processed_bytes = 0;
  ssize_t num_msg_received = 0;

  forwarder_t *forwarder = listener->forwarder;
  msgbuf_pool_t *msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
  forwarder_acquired_msgbuf_ids_reset(forwarder);

  /* Receive messages in the loop as long as we manage to fill the buffers */
  do {
    /* Prepare the msgbuf and address pair arrays */
    msgbuf_t *msgbufs[MAX_MSG];
    if (msgbuf_pool_getn(msgbuf_pool, msgbufs, MAX_MSG) < 0) {
      ERROR("Unable to get message buffers");
      break;
    }

    address_pair_t pair[MAX_MSG];
    address_t *address_remote[MAX_MSG];
    memset(&pair, 0, MAX_MSG * sizeof(address_pair_t));

    off_t msgbuf_ids[MAX_MSG];
    for (unsigned i = 0; i < MAX_MSG; i++) {
      // Copy the pointers to the remote addresses
      address_remote[i] = address_pair_get_remote(&pair[i]);

      // Populate local addresses
      pair[i].local = listener->address;

      // Do NOT rely on msgbuf pointers since a msgbuf pool rezise event may
      // make them invalid, use msgbuf ids instead
      msgbuf_ids[i] = msgbuf_pool_get_id(msgbuf_pool, msgbufs[i]);
    }

    // Read batch and populate remote addresses
    num_msg_received = listener_vft[get_protocol(listener->type)]->read_batch(
        fd, msgbufs, address_remote, MAX_MSG);

    for (int i = 0; i < MAX_MSG; i++) {
      // Release unused msg buffers
      if (i >= num_msg_received) {
        msgbuf_pool_put(msgbuf_pool, msgbufs[i]);
        continue;
      }

      msgbuf_pool_acquire(msgbufs[i]);
      forwarder_acquired_msgbuf_ids_push(forwarder, msgbuf_ids[i]);
    }

    if (num_msg_received < 0) break;
    TRACE("[listener_read_batch] batch size = %d", num_msg_received);

    for (unsigned i = 0; i < num_msg_received; i++) {
      size_t processed_bytes = forwarder_receive(
          forwarder, listener, msgbuf_ids[i], &pair[i], ticks_now());
      forwarder_log(listener->forwarder);

      total_processed_bytes += processed_bytes;
    }
  } while (num_msg_received ==
           MAX_MSG); /* backpressure based on queue size ? */

  /*
   * Signal to the forwarder that we reached the end of a batch and we need to
   * flush connections out
   */
  forwarder_flush_connections(forwarder);

  const off_t *acquired_msgbuf_ids =
      forwarder_get_acquired_msgbuf_ids(forwarder);
  for (int i = 0; i < vector_len(acquired_msgbuf_ids); i++) {
    msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, acquired_msgbuf_ids[i]);
    msgbuf_pool_release(msgbuf_pool, &msgbuf);
  }

  return total_processed_bytes;
}

/*
 * This might be called for a connection on the listener too. The listener is
 * the entity that owns the buffers used for reading.
 */
ssize_t listener_read_callback(listener_t *listener, int fd, void *user_data) {
  // DEBUG("[listener_read_callback]");
  // XXX make a single callback and arbitrate between read and readbatch
  assert(listener);

  /*
   * As the listener callback is shared between the listener and the different
   * connections created on top of it, the fd might be either of them.
   */
  // assert(fd == listener->fd);

  if (listener_vft[get_protocol(listener->type)]->read_batch)
    return listener_read_batch(listener, fd);

  return listener_read_single(listener, fd);
}

void listener_setup_local(forwarder_t *forwarder, uint16_t port) {
  address_t localhost_ipv4_addr = ADDRESS4_LOCALHOST(port);
  listener_create(FACE_TYPE_UDP_LISTENER, &localhost_ipv4_addr, "lo", "lo_udp4",
                  forwarder);

  address_t localhost_ipv6_addr = ADDRESS6_LOCALHOST(port);
  listener_create(FACE_TYPE_UDP_LISTENER, &localhost_ipv6_addr, "lo", "lo_udp6",
                  forwarder);
}