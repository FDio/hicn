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

#include <hicn/transport/core/hicn_binary_api.h>
#include <hicn/transport/core/vpp_binary_api_internal.h>
#include <hicn/transport/utils/log.h>

#define HICN_VPP_PLUGIN
#include <hicn/name.h>
#undef HICN_VPP_PLUGIN

#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <string.h>
#include <sys/stat.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/ip/format.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <vpp_plugins/hicn/error.h>
#include <vpp_plugins/hicn/hicn_api.h>

// uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <hicn/hicn_msg_enum.h>

#define vl_endianfun /* define message structures */
#define vl_print(handle, ...)
#define vl_printfun
#define vl_api_version(n, v) static u32 api_version = (v);
#define vl_msg_name_crc_list
#include <hicn/hicn_all_api_h.h>
#undef vl_msg_name_crc_list
#undef vl_api_version
#undef vl_printfun
#undef vl_endianfun

/////////////////////////////////////////////////////
const char *HICN_ERROR_STRING[] = {
#define _(a, b, c) c,
    foreach_hicn_error
#undef _
};
/////////////////////////////////////////////////////

static context_store_t context_store = {
    .global_pointers_map_index = 0,
};

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_hicn_api_reply_msg                                      \
  _(HICN_API_REGISTER_PROD_APP_REPLY, hicn_api_register_prod_app_reply) \
  _(HICN_API_REGISTER_CONS_APP_REPLY, hicn_api_register_cons_app_reply) \
  _(HICN_API_ROUTE_NHOPS_ADD_REPLY, hicn_api_route_nhops_add_reply)

int hicn_binary_api_register_prod_app(
    vpp_plugin_binary_api_t *api, hicn_producer_input_params *input_params,
    hicn_producer_output_params *output_params) {
  vl_api_hicn_api_register_prod_app_t *mp;
  vpp_plugin_binary_api_t *hm = api;
  vpp_binary_api_set_user_param(api->vpp_api, output_params);

  /* Construct the API message */
  M(HICN_API_REGISTER_PROD_APP, mp);

  CONTEXT_SAVE(context_store, api, mp)

  mp->len = (u8)input_params->prefix->prefix_len;
  mp->swif = clib_host_to_net_u32(input_params->swif);
  mp->cs_reserved = clib_host_to_net_u32(input_params->cs_reserved);

  mp->prefix[0] = clib_host_to_net_u64(input_params->prefix->as_u64[0]);
  mp->prefix[1] = clib_host_to_net_u64(input_params->prefix->as_u64[1]);

  return vpp_binary_api_send_request_wait_reply(api->vpp_api, mp);
}

static void vl_api_hicn_api_register_prod_app_reply_t_handler(
    vl_api_hicn_api_register_prod_app_reply_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  hicn_producer_output_params *params =
      vpp_binary_api_get_user_param(binary_api->vpp_api);

  vpp_binary_api_set_ret_value(binary_api->vpp_api,
                               clib_net_to_host_u32(mp->retval));
  params->cs_reserved = mp->cs_reserved;
  params->prod_addr->as_u64[0] = mp->prod_addr[0];
  params->prod_addr->as_u64[1] = mp->prod_addr[1];
  params->face_id = clib_net_to_host_u32(mp->faceid);

  vpp_binary_api_unlock_waiting_thread(binary_api->vpp_api);
}

int hicn_binary_api_register_cons_app(
    vpp_plugin_binary_api_t *api, hicn_consumer_input_params *input_params,
    hicn_consumer_output_params *output_params) {
  vl_api_hicn_api_register_cons_app_t *mp;
  vpp_plugin_binary_api_t *hm = api;

  vpp_binary_api_set_user_param(hm->vpp_api, output_params);

  /* Construct the API message */
  M(HICN_API_REGISTER_CONS_APP, mp);

  mp->swif = clib_host_to_net_u32(input_params->swif);

  CONTEXT_SAVE(context_store, api, mp)

  TRANSPORT_LOGI("Message created");

  return vpp_binary_api_send_request_wait_reply(api->vpp_api, mp);
}

static void vl_api_hicn_api_register_cons_app_reply_t_handler(
    vl_api_hicn_api_register_cons_app_reply_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);
  hicn_consumer_output_params *params =
      vpp_binary_api_get_user_param(binary_api->vpp_api);

  vpp_binary_api_set_ret_value(binary_api->vpp_api,
                               clib_net_to_host_u32(mp->retval));

  params->src4->as_ip46.ip4.as_u32 = clib_net_to_host_u32(mp->src_addr4);
  params->src6->as_u64[0] = clib_net_to_host_u64(mp->src_addr6[0]);
  params->src6->as_u64[1] = clib_net_to_host_u64(mp->src_addr6[1]);
  params->face_id = clib_host_to_net_u32(mp->faceid);

  vpp_binary_api_unlock_waiting_thread(binary_api->vpp_api);
}

int hicn_binary_api_register_route(
    vpp_plugin_binary_api_t *api,
    hicn_producer_set_route_params *input_params) {
  vl_api_hicn_api_route_nhops_add_t *mp;
  vpp_plugin_binary_api_t *hm = api;

  /* Construct the API message */
  M(HICN_API_ROUTE_NHOPS_ADD, mp);

  CONTEXT_SAVE(context_store, api, mp)

  mp->prefix[0] = input_params->prefix->as_u64[0];
  mp->prefix[1] = input_params->prefix->as_u64[1];
  mp->len = input_params->prefix->prefix_len;
  mp->face_ids[0] = input_params->face_id;
  mp->n_faces = 1;

  return vpp_binary_api_send_request_wait_reply(api->vpp_api, mp);
}

static void vl_api_hicn_api_route_nhops_add_reply_t_handler(
    vl_api_hicn_api_route_nhops_add_reply_t *mp) {
  vpp_plugin_binary_api_t *binary_api;
  CONTEXT_GET(context_store, mp, binary_api);

  vpp_binary_api_set_ret_value(binary_api->vpp_api,
                               clib_net_to_host_u32(mp->retval));

  vpp_binary_api_unlock_waiting_thread(binary_api->vpp_api);
}

static int hicn_binary_api_setup_handlers(vpp_plugin_binary_api_t *binary_api) {
  vpp_plugin_binary_api_t *sm __attribute__((unused)) = binary_api;
#define _(N, n)                                                        \
  vl_msg_api_set_handlers(VL_API_##N + sm->msg_id_base, #n,            \
                          vl_api_##n##_t_handler, vl_noop_handler,     \
                          vl_api_##n##_t_endian, vl_api_##n##_t_print, \
                          sizeof(vl_api_##n##_t), 1);
  foreach_hicn_api_reply_msg;
#undef _
  return 0;
}

char *hicn_binary_api_get_error_string(int ret_val) {
  return get_error_string(ret_val);
}

vpp_plugin_binary_api_t *hicn_binary_api_init(vpp_binary_api_t *api) {
  vpp_plugin_binary_api_t *ret = malloc(sizeof(vpp_plugin_binary_api_t));
  u8 *name = format(0, "hicn_%08x%c", api_version, 0);
  ret->msg_id_base = vl_client_get_first_plugin_msg_id((char *)name);
  ret->vpp_api = api;
  ret->my_client_index = vpp_binary_api_get_client_index(api);
  hicn_binary_api_setup_handlers(ret);
  return ret;
}

#endif  // __vpp__
