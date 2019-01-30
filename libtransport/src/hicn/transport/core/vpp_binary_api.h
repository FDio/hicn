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

#include <stdint.h>
#include <stdlib.h>

typedef struct vpp_binary_api vpp_binary_api_t;
typedef struct vpp_plugin_binary_api vpp_plugin_binary_api_t;

typedef enum link_state_s { UP = 1, DOWN = 0 } link_state_t;

/**
 * @brief Instantiate a new vpp_binary_api_t data structure and
 *        connect the application to the local VPP forwarder.
 */
vpp_binary_api_t *vpp_binary_api_init(const char *app_name);

/**
 * @brief Destroy the vpp_binary_api_t and disconnect from VPP.
 */
void vpp_binary_api_destroy(vpp_binary_api_t *api);

void vpp_binary_api_send_receive_ping(vpp_binary_api_t *api);

int vpp_binary_api_set_int_state(vpp_binary_api_t *api, uint32_t sw_index,
                                 link_state_t state);

/**
 * @brief Send request to VPP and wait for reply.
 */
int vpp_binary_api_send_request_wait_reply(vpp_binary_api_t *api,
                                           void *request);

void vpp_binary_api_unlock_waiting_thread(vpp_binary_api_t *api);

void vpp_binary_api_send_request(vpp_binary_api_t *api, void *request);

int vpp_binary_api_get_ret_value(vpp_binary_api_t *api);

void vpp_binary_api_set_ret_value(vpp_binary_api_t *api, int ret_val);

void *vpp_binary_api_get_user_param(vpp_binary_api_t *api);

void vpp_binary_api_set_user_param(vpp_binary_api_t *api, void *user_param);

uint32_t vpp_binary_api_get_client_index(vpp_binary_api_t *api);

void vpp_binary_api_set_client_index(vpp_binary_api_t *api,
                                     uint32_t client_index);

#ifdef __cplusplus
}
#endif

#endif  // __vpp__