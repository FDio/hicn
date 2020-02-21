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
#include <hicn/util/ip_address.h>

#ifdef __vpp__

#ifdef __cplusplus
extern "C" {
#endif

#include <vapi/vapi.h>

#include "stdint.h"

typedef struct {
  ip_prefix_t* prefix;
  uint32_t swif;
  uint32_t cs_reserved;
} hicn_producer_input_params;

typedef struct {
  uint32_t swif;
} hicn_consumer_input_params;

typedef struct {
  uint32_t face_id;
} hicn_del_face_app_input_params;

typedef struct {
  uint32_t cs_reserved;
  ip_address_t* prod_addr;
  uint32_t face_id;
} hicn_producer_output_params;

typedef struct {
  ip_address_t* src4;
  ip_address_t* src6;
  uint32_t face_id1;
  uint32_t face_id2;
} hicn_consumer_output_params;

typedef struct {
  ip_prefix_t* prefix;
  uint32_t face_id;
} hicn_producer_set_route_params;

int hicn_vapi_register_prod_app(
    vapi_ctx_t ctx, hicn_producer_input_params* input_params,
    hicn_producer_output_params* output_params);

int hicn_vapi_register_cons_app(
    vapi_ctx_t ctx, hicn_consumer_input_params* input_params,
    hicn_consumer_output_params* output_params);

int hicn_vapi_register_route(
    vapi_ctx_t ctx, hicn_producer_set_route_params* input_params);

int hicn_vapi_face_cons_del(
    vapi_ctx_t ctx, hicn_del_face_app_input_params *input_params);

int hicn_vapi_face_prod_del(
    vapi_ctx_t ctx, hicn_del_face_app_input_params *input_params);

char* hicn_vapi_get_error_string(int ret_val);

#ifdef __cplusplus
}
#endif

#endif  // __vpp__
