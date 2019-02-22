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

#include <hicn/transport/config.h>

#ifdef __vpp__

#include <hicn/transport/core/memif_binary_api.h>
#include <hicn/transport/core/vpp_binary_api_internal.h>
#include <hicn/transport/utils/log.h>

#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <string.h>
#include <sys/stat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

// uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <memif/memif_msg_enum.h>

#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

#define vl_typedefs
#define vl_endianfun
#define vl_print(handle, ...)
#define vl_printfun
#define vl_api_version(n, v) static u32 api_version = (v);
#define vl_msg_name_crc_list
#include <memif/memif_all_api_h.h>
#undef vl_msg_name_crc_list
#undef vl_api_version
#undef vl_printfun
#undef vl_endianfun
#undef vl_typedefs

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

static context_store_t context_store = {
    .global_pointers_map_index = 0,
};

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_memif_api_reply_msg         \
  _(MEMIF_CREATE_REPLY, memif_create_reply) \
  _(MEMIF_DELETE_REPLY, memif_delete_reply) \
  _(MEMIF_DETAILS, memif_details)

int memif_binary_api_get_next_memif_id(vpp_plugin_binary_api_t *api,
                                       uint32_t *memif_id) {
  // Dump all the memif interfaces and return the next to the largest memif id
  vl_api_memif_dump_t *mp;
  vpp_plugin_binary_api_t *hm = api;

  M(MEMIF_DUMP, mp);
  uint32_t *user_param = malloc(sizeof(uint32_t));
  *user_param = 0;
  vpp_binary_api_set_user_param(api->vpp_api, user_param);

  CONTEXT_SAVE(context_store, api, mp);

  vpp_binary_api_send_request(api->vpp_api, mp);

  vpp_binary_api_send_receive_ping(api->vpp_api);

  user_param = vpp_binary_api_get_user_param(api->vpp_api);
  *memif_id = *(uint32_t *)(user_param);
  free(user_param);

  return vpp_binary_api_get_ret_value(api->vpp_api);
}

static void vl_api_memif_details_t_handler(vl_api_memif_details_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  uint32_t *last_memif_id = vpp_binary_api_get_user_param(binary_api->vpp_api);
  uint32_t current_memif_id = clib_net_to_host_u32(mp->id);
  if (current_memif_id >= *last_memif_id) {
    *last_memif_id = current_memif_id + 1;
  }
}

int memif_binary_api_create_memif(vpp_plugin_binary_api_t *api,
                                  memif_create_params_t *input_params,
                                  memif_output_params_t *output_params) {
  vl_api_memif_create_t *mp;
  vpp_plugin_binary_api_t *hm = api;

  if (input_params->socket_id == ~0) {
    // invalid socket-id
    return -1;
  }

  if (!is_pow2(input_params->ring_size)) {
    // ring size must be power of 2
    return -1;
  }

  if (input_params->rx_queues > 255 || input_params->rx_queues < 1) {
    // rx queue must be between 1 - 255
    return -1;
  }

  if (input_params->tx_queues > 255 || input_params->tx_queues < 1) {
    // tx queue must be between 1 - 255
    return -1;
  }

  vpp_binary_api_set_user_param(api->vpp_api, output_params);

  /* Construct the API message */
  M(MEMIF_CREATE, mp);

  CONTEXT_SAVE(context_store, api, mp)

  mp->role = input_params->role;
  mp->mode = input_params->mode;
  mp->rx_queues = input_params->rx_queues;
  mp->tx_queues = input_params->tx_queues;
  mp->id = clib_host_to_net_u32(input_params->id);
  mp->socket_id = clib_host_to_net_u32(input_params->socket_id);
  mp->ring_size = clib_host_to_net_u32(input_params->ring_size);
  mp->buffer_size = clib_host_to_net_u16(input_params->buffer_size);

  int ret = vpp_binary_api_send_request_wait_reply(api->vpp_api, mp);
  if (ret < 0) {
    return ret;
  }

  return vpp_binary_api_set_int_state(api->vpp_api, output_params->sw_if_index,
                                      UP);
}
int memif_binary_api_delete_memif(vpp_plugin_binary_api_t *api,
                                  uint32_t sw_if_index) {
  vl_api_memif_delete_t *mp;
  vpp_plugin_binary_api_t *hm = api;

  /* Construct the API message */            
  M(MEMIF_DELETE, mp);

  CONTEXT_SAVE(context_store, api, mp)

  mp->sw_if_index = htonl(sw_if_index);

  return vpp_binary_api_send_request_wait_reply(api->vpp_api, mp);
}

static void vl_api_memif_create_reply_t_handler(
    vl_api_memif_create_reply_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  memif_output_params_t *params =
      vpp_binary_api_get_user_param(binary_api->vpp_api);

  vpp_binary_api_set_ret_value(binary_api->vpp_api,
                               clib_net_to_host_u32(mp->retval));
  params->sw_if_index = clib_net_to_host_u32(mp->sw_if_index);

  vpp_binary_api_unlock_waiting_thread(binary_api->vpp_api);
}

static void vl_api_memif_delete_reply_t_handler(
    vl_api_memif_delete_reply_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);

  vpp_binary_api_set_ret_value(binary_api->vpp_api,
                               clib_net_to_host_u32(mp->retval));

  vpp_binary_api_unlock_waiting_thread(binary_api->vpp_api);
}

static int memif_binary_api_setup_handlers(
    vpp_plugin_binary_api_t *binary_api) {
  vpp_plugin_binary_api_t *sm __attribute__((unused)) = binary_api;
#define _(N, n)                                                        \
  vl_msg_api_set_handlers(VL_API_##N + sm->msg_id_base, #n,            \
                          vl_api_##n##_t_handler, vl_noop_handler,     \
                          vl_api_##n##_t_endian, vl_api_##n##_t_print, \
                          sizeof(vl_api_##n##_t), 1);
  foreach_memif_api_reply_msg;
#undef _
  return 0;
}

vpp_plugin_binary_api_t *memif_binary_api_init(vpp_binary_api_t *api) {
  vpp_plugin_binary_api_t *ret = malloc(sizeof(vpp_plugin_binary_api_t));
  u8 *name = format(0, "memif_%08x%c", api_version, 0);
  ret->msg_id_base = vl_client_get_first_plugin_msg_id((char *)name);
  ret->vpp_api = api;
  ret->my_client_index = vpp_binary_api_get_client_index(api);
  memif_binary_api_setup_handlers(ret);
  return ret;
}

#endif  // __vpp__