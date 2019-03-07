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

#include <hicn/transport/core/vpp_binary_api.h>
#include <hicn/transport/core/vpp_binary_api_internal.h>
#include <hicn/transport/utils/log.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/ip/ip.h>
#include <vppinfra/error.h>

#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>

#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

/* Get CRC codes of the messages */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

#include <semaphore.h>

struct vpp_binary_api {
  api_main_t *api_main;
  u32 my_client_index;
  unix_shared_memory_queue_t *vl_input_queue;
  vlib_main_t *vlib_main;
  sem_t *semaphore;
  u32 ping_id;
  int ret_val;
  void *user_param;
};

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

/**
 * @brief Generic VPP request structure.
 */
typedef struct __attribute__((packed)) vl_generic_request_s {
  u16 _vl_msg_id;
  u32 client_index;
  u32 context;
} vl_generic_request_t;

/**
 * @brief Generic VPP reply structure (response with a single message).
 */
typedef struct __attribute__((packed)) vl_generic_reply_s {
  u16 _vl_msg_id;
  u32 context;
  i32 retval;
} vl_generic_reply_t;

static void vl_api_control_ping_reply_t_handler(
    vl_api_control_ping_reply_t *mp) {
  // Just unblock main thread
  vpp_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  binary_api->ret_val = ntohl(mp->retval);
  vpp_binary_api_unlock_waiting_thread(binary_api);
}

static void vl_api_sw_interface_set_flags_reply_t_handler(
    vl_api_control_ping_reply_t *mp) {
  // Unblock main thread setting reply message status code
  vpp_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  binary_api->ret_val = ntohl(mp->retval);
  vpp_binary_api_unlock_waiting_thread(binary_api);
}

static int vpp_connect_to_vlib(vpp_binary_api_t *binary_api, char *name) {
  clib_mem_init_thread_safe(0, 256 << 20);
  if (vl_client_connect_to_vlib("/vpe-api", name, 32) < 0) {
    return -1;
  }

  binary_api->vl_input_queue = binary_api->api_main->shmem_hdr->vl_input_queue;
  binary_api->my_client_index = binary_api->api_main->my_client_index;

  return 0;
}

vpp_binary_api_t *vpp_binary_api_init(const char *app_name) {
  vpp_binary_api_t *ret = malloc(sizeof(vpp_binary_api_t));
  ret->api_main = &api_main;
  ret->vlib_main = &vlib_global_main;

  vpp_connect_to_vlib(ret, (char *)app_name);
  ret->semaphore = sem_open(app_name, O_CREAT, 0, 0);

  return ret;
}

void vpp_binary_api_destroy(vpp_binary_api_t *api) {
  sem_close(api->semaphore);
  free(api);
  vl_client_disconnect_from_vlib();
}

void vpp_binary_api_unlock_waiting_thread(vpp_binary_api_t *api) {
  sem_post(api->semaphore);
}

void vpp_binary_api_send_receive_ping(vpp_binary_api_t *api) {
  /* Use a control ping for synchronization */

  /* Get the control ping ID */
#define _(id, n, crc) \
  const char *id##_CRC __attribute__((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _

  int ping_reply_id =
      vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_REPLY_CRC));
  vl_msg_api_set_handlers(ping_reply_id, "control_ping_reply",
                          vl_api_control_ping_reply_t_handler, vl_noop_handler,
                          vl_api_control_ping_reply_t_endian,
                          vl_api_control_ping_reply_t_print,
                          sizeof(vl_api_control_ping_reply_t), 1);

  vl_api_control_ping_t *mp_ping;
  mp_ping = vl_msg_api_alloc_as_if_client(sizeof(*mp_ping));
  mp_ping->_vl_msg_id = clib_host_to_net_u16(
      vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_CRC)));
  mp_ping->client_index = api->my_client_index;

  CONTEXT_SAVE(context_store, api, mp_ping);

  TRANSPORT_LOGD("Sending ping id %u", mp_ping->_vl_msg_id);

  vpp_binary_api_send_request_wait_reply(api, mp_ping);
}

int vpp_binary_api_set_int_state(vpp_binary_api_t *api, uint32_t sw_index,
                                 link_state_t state) {
#define _(id, n, crc) \
  const char *id##_CRC __attribute__((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _

  int sw_interface_set_flags_reply_id = VL_API_SW_INTERFACE_SET_FLAGS_REPLY;
  vl_msg_api_set_handlers(
      sw_interface_set_flags_reply_id, "sw_interface_set_flags_reply",
      vl_api_sw_interface_set_flags_reply_t_handler, vl_noop_handler,
      vl_api_sw_interface_set_flags_reply_t_endian,
      vl_api_sw_interface_set_flags_reply_t_print,
      sizeof(vl_api_sw_interface_set_flags_reply_t), 1);

  vl_api_sw_interface_set_flags_t *mp;
  mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));
  mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SW_INTERFACE_SET_FLAGS);
  mp->client_index = api->my_client_index;
  mp->sw_if_index = clib_host_to_net_u32(sw_index);
  mp->admin_up_down = (u8)state;

  CONTEXT_SAVE(context_store, api, mp);

  TRANSPORT_LOGD("Sending set int flags id %u", mp->_vl_msg_id);

  return vpp_binary_api_send_request_wait_reply(api, mp);
}

void vpp_binary_api_send_request(vpp_binary_api_t *api, void *request) {
  vl_generic_request_t *req = NULL;

  req = (vl_generic_request_t *)request;
  TRANSPORT_LOGD("Sending a request to VPP (id=%d).\n", ntohs(req->_vl_msg_id));

  S(api, req);
}

int vpp_binary_api_get_ret_value(vpp_binary_api_t *api) { return api->ret_val; }

void vpp_binary_api_set_ret_value(vpp_binary_api_t *api, int ret_val) {
  api->ret_val = ret_val;
}

void *vpp_binary_api_get_user_param(vpp_binary_api_t *api) {
  return api->user_param;
}

void vpp_binary_api_set_user_param(vpp_binary_api_t *api, void *user_param) {
  api->user_param = user_param;
}

uint32_t vpp_binary_api_get_client_index(vpp_binary_api_t *api) {
  return api->my_client_index;
}

void vpp_binary_api_set_client_index(vpp_binary_api_t *api,
                                     uint32_t client_index) {
  api->my_client_index = client_index;
}

int vpp_binary_api_send_request_wait_reply(vpp_binary_api_t *api,
                                           void *request) {
  vpp_binary_api_send_request(api, request);

  sem_wait(api->semaphore);

  return api->ret_val;
}

#endif  // __vpp__