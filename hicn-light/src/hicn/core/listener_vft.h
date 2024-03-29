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
 * @file listener_vft.h
 * @brief Listener VFT
 */

#ifndef HICNLIGHT_LISTENER_VFT_H
#define HICNLIGHT_LISTENER_VFT_H

#include <hicn/core/address_pair.h>
#include <hicn/core/connection.h>
#include <hicn/core/listener.h>
#include <hicn/face.h>

typedef struct {
  int (*initialize)(listener_t* listener);
  void (*finalize)(listener_t* listener);
  int (*punt)(const listener_t* listener, const char* prefix_s);
  int (*get_socket)(const listener_t* listener, const address_t* local,
                    const address_t* remote, const char* interface_name);
  int (*send)(const connection_t* connection, const address_t* dummy,
              msgbuf_t* msgbuf, bool queue);
  int (*send_packet)(const connection_t* connection, const uint8_t* packet,
                     size_t size);
  ssize_t (*read_single)(int fd, msgbuf_t* msgbuf, address_t* address);
  ssize_t (*read_batch)(int fd, msgbuf_t** msgbuf, address_t** address,
                        size_t len);
  size_t data_size;
} listener_ops_t;

#define DECLARE_LISTENER(NAME)                       \
  const listener_ops_t listener_##NAME = {           \
      .initialize = listener_##NAME##_initialize,    \
      .finalize = listener_##NAME##_finalize,        \
      .punt = listener_##NAME##_punt,                \
      .get_socket = listener_##NAME##_get_socket,    \
      .read_single = listener_##NAME##_read_single,  \
      .read_batch = listener_##NAME##_read_batch,    \
      .data_size = sizeof(listener_##NAME##_data_t), \
  }

extern const listener_ops_t* listener_vft[];

#endif /* HICNLIGHT_LISTENER_VFT_H */
