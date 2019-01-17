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
#include <hicn/transport/core/vpp_binary_api.h>

#ifdef __vpp__

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"

typedef struct memif_create_params_s {
  uint8_t role;
  uint8_t mode;
  uint8_t rx_queues;
  uint8_t tx_queues;
  uint32_t id;
  uint32_t socket_id;
  uint8_t secret[24];
  uint32_t ring_size;
  uint16_t buffer_size;
  uint8_t hw_addr[6];
} memif_create_params_t;

typedef struct memif_output_params_s {
  uint32_t sw_if_index;
} memif_output_params_t;

vpp_plugin_binary_api_t* memif_binary_api_init(vpp_binary_api_t* api);

uint32_t memif_binary_api_get_next_memif_id(vpp_plugin_binary_api_t* api);

int memif_binary_api_create_memif(vpp_plugin_binary_api_t* api,
                                  memif_create_params_t* input_params,
                                  memif_output_params_t* output_params);

int memif_binary_api_delete_memif(vpp_plugin_binary_api_t* api,
                                  uint32_t sw_if_index);

#ifdef __cplusplus
}
#endif

#endif  // __vpp__