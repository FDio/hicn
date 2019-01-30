/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#pragma once

#include <hicn/transport/config.h>

#ifdef __vpp__

#ifdef __cplusplus
extern "C" {
#endif

#include <semaphore.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <stdint.h>

typedef struct vpp_binary_api vpp_binary_api_t;

struct vpp_plugin_binary_api {
  vpp_binary_api_t *vpp_api;
  u16 msg_id_base;
  u32 my_client_index;
};

#define POINTER_MAP_SIZE 32
typedef struct {
  void *global_pointers_map[POINTER_MAP_SIZE];
  uint8_t global_pointers_map_index;
} context_store_t;

#define CONTEXT_SAVE(context_store, pointer, mp)                        \
  do {                                                                  \
    context_store                                                       \
        .global_pointers_map[context_store.global_pointers_map_index] = \
        pointer;                                                        \
    mp->context = context_store.global_pointers_map_index++;            \
    context_store.global_pointers_map_index %= POINTER_MAP_SIZE;        \
  } while (0);

#define CONTEXT_GET(context_store, mp, pointer)               \
  do {                                                        \
    pointer = context_store.global_pointers_map[mp->context]; \
  } while (0);

#define M(T, mp)                                          \
  do {                                                    \
    mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));      \
    memset(mp, 0, sizeof(*mp));                           \
    mp->_vl_msg_id = ntohs(VL_API_##T + hm->msg_id_base); \
    mp->client_index = hm->my_client_index;               \
  } while (0);

#define S(api, mp) (vl_msg_api_send_shmem(api->vl_input_queue, (u8 *)&mp))

#ifdef __cplusplus
}
#endif

#endif  // __vpp__