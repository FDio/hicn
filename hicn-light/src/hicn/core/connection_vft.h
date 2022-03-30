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
 * @file connection_vft.h
 * @brief Connection VFT
 */

#ifndef HICNLIGHT_CONNECTION_VFT_H
#define HICNLIGHT_CONNECTION_VFT_H

#include "connection.h"

typedef struct {
  int (*initialize)(connection_t* connection);
  void (*finalize)(connection_t* connection);
  int (*get_socket)(const listener_t* listener, const address_t* local,
                    const address_t* remote, const char* interface_name);
  bool (*flush)(const connection_t* connection);
  bool (*send)(const connection_t* connection, msgbuf_t* msgbuf, bool queue);
  int (*send_packet)(const connection_t* connection, const uint8_t* packet,
                     size_t size);
  // void (*read_callback)(connection_t * connection, int fd, void * data);
  size_t data_size;
} connection_ops_t;

#define DECLARE_CONNECTION(NAME)                       \
  const connection_ops_t connection_##NAME = {         \
      .initialize = connection_##NAME##_initialize,    \
      .finalize = connection_##NAME##_finalize,        \
      .get_socket = listener_##NAME##_get_socket,      \
      .flush = connection_##NAME##_flush,              \
      .send = connection_##NAME##_send,                \
      .send_packet = connection_##NAME##_send_packet,  \
      .data_size = sizeof(connection_##NAME##_data_t), \
  };

//    .read_callback = connection_ ## NAME ## _read_callback,

extern const connection_ops_t* connection_vft[];

#endif /* HICNLIGHT_CONNECTION_VFT_H */
