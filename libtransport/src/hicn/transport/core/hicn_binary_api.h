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

#include <hicn/transport/core/vpp_binary_api.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"

typedef union {
  uint8_t data[4];
  uint32_t data_u32;
  /* Aliases. */
  uint8_t as_u8[4];
  uint16_t as_u16[2];
  uint32_t as_u32;
} ip4_address;

typedef union {
  uint8_t as_u8[16];
  uint16_t as_u16[8];
  uint32_t as_u32[4];
  uint64_t as_u64[2];
} ip6_address;

typedef enum { IP_TYPE_ANY, IP_TYPE_IP4, IP_TYPE_IP6 } ip46_type;

typedef struct {
  ip46_type type;
  uint8_t prefix_length;
  union {
    ip4_address ip4;
    ip6_address ip6;
  };
} ip46_address;

typedef struct {
  ip46_address prefix;
  uint32_t swif;
  uint32_t cs_reserved;
} hicn_producer_input_params;

typedef struct {
  uint32_t swif;
} hicn_consumer_input_params;

typedef struct {
  uint32_t cs_reserved;
  ip46_address prod_addr;
  uint32_t face_id;
} hicn_producer_output_params;

typedef struct {
  ip46_address src4;
  ip46_address src6;
  uint32_t face_id;
} hicn_consumer_output_params;

typedef struct {
  ip46_address prefix;
  uint32_t face_id;
} hicn_producer_set_route_params;

vpp_plugin_binary_api_t* hicn_binary_api_init(vpp_binary_api_t* api);

int hicn_binary_api_register_prod_app(
    vpp_plugin_binary_api_t* api, hicn_producer_input_params* input_params,
    hicn_producer_output_params* output_params);

int hicn_binary_api_register_cons_app(
    vpp_plugin_binary_api_t* api, hicn_consumer_input_params* input_params,
    hicn_consumer_output_params* output_params);

int hicn_binary_api_register_route(
    vpp_plugin_binary_api_t* api, hicn_producer_set_route_params* input_params);

char* hicn_binary_api_get_error_string(int ret_val);

#ifdef __cplusplus
}
#endif

#endif  // __vpp__