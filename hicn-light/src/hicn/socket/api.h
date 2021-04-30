/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 *
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
 * @file hicn_face.h
 * @brief hICN socket library
 *
 * This module provides an interface to managing so-called hICN sockets,
 * realizing punting of interest and data packets using a TUN device.
 */

#ifndef HICN_SOCKET_API_H
#define HICN_SOCKET_API_H

#include <stdint.h>  // uint*_t
#include <stdlib.h>

#include <hicn/hicn.h>
#include "error.h"

#define BUFSIZE 4096
#define MAX_CONNECTIONS \
  255  // We currently limit the number of connections we can establish
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif
/* hICN socket helper */

/** hICN configuration options */
typedef struct {
  // uint32_t interval;

  /* Identifier used to name hICN TUN interfaces (should be unique) */
  char *identifier;
  // hicn_format_t format;

} hicn_conf_t;

/**
 * hICN adjacency
 */
typedef struct {
  char *local_ip_address;
  char *gateway_ip_address;
} hicn_adjacency_t;

#define EMPTY_HICN_ADJACENCY \
  (hicn_adjacency_t) { 0, 0 }

/* hICN socket operations */

typedef struct {
  uint8_t pkbuf[BUFSIZE];
  uint32_t rb_pkbuf_r;
  uint32_t rb_pkbuf_w;
} hicn_buffer_t;

typedef enum { HS_UNSPEC, HS_LISTENER, HS_CONNECTION } hicn_socket_type_t;

typedef struct hicn_socket_s {
  hicn_socket_type_t type;
  int fd;

  /* Implementation specific state follows */
  char tun_name[IF_NAMESIZE];
  uint32_t tun_id;

  hicn_buffer_t buffer;
  void (*cb)(struct hicn_socket_s *, void *, uint8_t *, size_t);
  void *cb_data;

  union {
    struct {
      ip_prefix_t tun_ip_address;
      uint32_t interface_id;

      /* ID of the corresponding table : avoid default values of 0, 32766 and
       * 32767 */
      uint8_t table_id;
    } connection;
  };
} hicn_socket_t;

/**
 * hICN global state
 */
typedef struct {
  /* Configuration data */
  hicn_conf_t *conf;

  // We need state associate to each FD, to know what type of socket it is and
  // its state.
  void *socket_root; /**< A tree of socket indexed by their fd */

} hicn_socket_helper_t;

/**
 * Create an hICN instance.
 *
 * This is used to configure the state of an hICN router consistently between
 * a listener and the different connections. It also regroups all the state
 * related to hICN functionalities.
 *
 * @return A pointer to an hICN instance.
 */
hicn_socket_helper_t *hicn_create();

void hicn_destroy();

/**
 * Retrieve hICN configuration.
 *
 * Gets the current configuration of an hICN instance for information purposes,
 * or later update it.
 *
 * TODO
 *  - We might want to prevent configuration updates while the hICN instance is
 *  running. Define running...
 *
 * @param [in] hicn Pointer to hICN instance.
 * @return Pointer to an hICN configuration data structure.
 *
 * @see hicn_set_conf
 */
hicn_conf_t *hicn_get_conf(hicn_socket_helper_t *hicn);

/**
 * Update hICN configuration.
 *
 * @param [in] hicn Pointer to an hICN instance.
 * @param [in] hicn_conf Pointer to an hICN configuration data structure.
 * @return 0 in case of success, -1 otherwise.
 *
 * @see hicn_get_conf
 */
int hicn_set_conf(hicn_socket_helper_t *hicn, hicn_conf_t *hicn_conf);

/**
 * Release hICN state.
 *
 * @param [in] hicn Pointer to an hICN instance.
 */
void hicn_free(hicn_socket_helper_t *hicn);

/**
 * Returns the local address used to reach the remote address
 *
 * @param [in] remote_address
 * @param [out] local address
 *
 * @return 0 in case of success, -1 otherwise.
 */
int hicn_get_local_address(const ip_prefix_t *remote_address,
                           ip_prefix_t *local_address);

/* hICN socket */

/**
 * Create an hICN socket.
 *
 * An hICN socket abstracts the underlying implementation and allows hICN
 * packets to be sent and received independently of the underlying
 * implementation.
 *
 * It is possible to further specialize the socket in a listener socket, and a
 * connection socket.
 *
 * @param [in] hicn Pointer to an hICN instance.
 * @param [in] identifier Unique identifier for this socket, used to named the
 *      TUN device
 * @param [in] local_ip_address IP address used locally by the socket (or NULL
 *      for letting the library decide automatically).
 * @return File descriptor (>0) in case of success, -1 otherwise.
 *
 * @see hicn_listen
 * @see hicn_bind
 */
int hicn_socket(hicn_socket_helper_t *hicn, const char *identifier,
                const char *local_ip_address);

/**
 * Packet punting.
 *
 * Note that we cannot listen on a socket that is already bound.
 *
 * @param [in] hicn Pointer to an hICN instance.
 * @param [in] fd File descriptor identifying the hICN socket.
 * @param [in] prefix Prefix (IPv4 or IPv6) to be bound to hICN in
 *    RFC-compliant presentation format.
 * @return 0 in case of success, -1 otherwise.
 *
 * @see hicn_socket
 */
int hicn_listen(hicn_socket_helper_t *hicn, int fd, const char *prefix);

/**
 * Packet forwarding
 * @param [in] hicn Pointer to an hICN instance.
 * @param [in] fd File descriptor identifying the hICN socket.
 * @param [in] prefix Prefix (IPv4 or IPv6) to be bound to hICN in
 *    RFC-compliant presentation format.
 * @return 0 in case of success, -1 otherwise.
 *
 * @see hicn_socket
 */
int hicn_bind(hicn_socket_helper_t *hicn, int fd,
              const char *remote_ip_address);

#endif /* HICN_SOCKET_API_H */
