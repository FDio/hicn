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

#include <hicn/transport/utils/log.h>

#include <core/hicn_vapi.h>

#define HICN_VPP_PLUGIN
#include <hicn/name.h>
#undef HICN_VPP_PLUGIN

#include <vapi/vapi_safe.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/fib/fib_types.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <vapi/hicn.api.vapi.h>
#include <vpp_plugins/hicn/error.h>

/////////////////////////////////////////////////////
const char *HICN_ERROR_STRING[] = {
#define _(a, b, c) c,
    foreach_hicn_error
#undef _
};
/////////////////////////////////////////////////////

/*********************** Missing Symbol in vpp libraries
 * *************************/
u8 *format_vl_api_address_union(u8 *s, va_list *args) { return NULL; }

/*********************************************************************************/

DEFINE_VAPI_MSG_IDS_HICN_API_JSON

static vapi_error_e register_prod_app_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_register_prod_app_reply *reply) {
  hicn_producer_output_params *output_params =
      (hicn_producer_output_params *)callback_ctx;

  if (reply == NULL) return rv;

  output_params->cs_reserved = reply->cs_reserved;
  output_params->prod_addr = (ip_address_t *)malloc(sizeof(ip_address_t));
  memset(output_params->prod_addr, 0, sizeof(ip_address_t));
  if (reply->prod_addr.af == ADDRESS_IP6)
    memcpy(&output_params->prod_addr->v6, reply->prod_addr.un.ip6,
           sizeof(ip6_address_t));
  else
    memcpy(&output_params->prod_addr->v4, reply->prod_addr.un.ip4,
           sizeof(ip4_address_t));
  output_params->face_id = reply->faceid;

  return reply->retval;
}

int hicn_vapi_register_prod_app(vapi_ctx_t ctx,
                                hicn_producer_input_params *input_params,
                                hicn_producer_output_params *output_params) {
  vapi_lock();
  vapi_msg_hicn_api_register_prod_app *msg =
      vapi_alloc_hicn_api_register_prod_app(ctx);

  if (ip46_address_is_ip4((ip46_address_t *)&input_params->prefix->address)) {
    memcpy(&msg->payload.prefix.address.un.ip4, &input_params->prefix->address,
           sizeof(ip4_address_t));
    msg->payload.prefix.address.af = ADDRESS_IP4;
  } else {
    memcpy(&msg->payload.prefix.address.un.ip6, &input_params->prefix->address,
           sizeof(ip6_address_t));
    msg->payload.prefix.address.af = ADDRESS_IP6;
  }
  msg->payload.prefix.len = input_params->prefix->len;

  msg->payload.swif = input_params->swif;
  msg->payload.cs_reserved = input_params->cs_reserved;

  int ret = vapi_hicn_api_register_prod_app(ctx, msg, register_prod_app_cb,
                                            output_params);
  vapi_unlock();
  return ret;
}

static vapi_error_e face_prod_del_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_face_prod_del_reply *reply) {
  if (reply == NULL) return rv;

  return reply->retval;
}

int hicn_vapi_face_prod_del(vapi_ctx_t ctx,
                            hicn_del_face_app_input_params *input_params) {
  vapi_lock();
  vapi_msg_hicn_api_face_prod_del *msg = vapi_alloc_hicn_api_face_prod_del(ctx);

  msg->payload.faceid = input_params->face_id;

  int ret = vapi_hicn_api_face_prod_del(ctx, msg, face_prod_del_cb, NULL);
  vapi_unlock();
  return ret;
}

static vapi_error_e register_cons_app_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_register_cons_app_reply *reply) {
  hicn_consumer_output_params *output_params =
      (hicn_consumer_output_params *)callback_ctx;

  if (reply == NULL) return rv;

  output_params->src6 = (ip_address_t *)malloc(sizeof(ip_address_t));
  output_params->src4 = (ip_address_t *)malloc(sizeof(ip_address_t));
  memset(output_params->src6, 0, sizeof(ip_address_t));
  memset(output_params->src4, 0, sizeof(ip_address_t));
  memcpy(&output_params->src6->v6, &reply->src_addr6.un.ip6,
         sizeof(ip6_address_t));
  memcpy(&output_params->src4->v4, &reply->src_addr4.un.ip4,
         sizeof(ip4_address_t));

  output_params->face_id1 = reply->faceid1;
  output_params->face_id2 = reply->faceid2;

  return reply->retval;
}

int hicn_vapi_register_cons_app(vapi_ctx_t ctx,
                                hicn_consumer_input_params *input_params,
                                hicn_consumer_output_params *output_params) {
  vapi_lock();
  vapi_msg_hicn_api_register_cons_app *msg =
      vapi_alloc_hicn_api_register_cons_app(ctx);

  msg->payload.swif = input_params->swif;

  int ret = vapi_hicn_api_register_cons_app(ctx, msg, register_cons_app_cb,
                                            output_params);
  vapi_unlock();
  return ret;
}

static vapi_error_e face_cons_del_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_face_cons_del_reply *reply) {
  if (reply == NULL) return rv;

  return reply->retval;
}

int hicn_vapi_face_cons_del(vapi_ctx_t ctx,
                            hicn_del_face_app_input_params *input_params) {
  vapi_lock();
  vapi_msg_hicn_api_face_cons_del *msg = vapi_alloc_hicn_api_face_cons_del(ctx);

  msg->payload.faceid = input_params->face_id;

  int ret = vapi_hicn_api_face_cons_del(ctx, msg, face_cons_del_cb, NULL);
  vapi_unlock();
  return ret;
}

static vapi_error_e reigster_route_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_route_nhops_add_reply *reply) {
  if (reply == NULL) return rv;

  return reply->retval;
}

int hicn_vapi_register_route(vapi_ctx_t ctx,
                             hicn_producer_set_route_params *input_params) {
  vapi_lock();
  vapi_msg_hicn_api_route_nhops_add *msg =
      vapi_alloc_hicn_api_route_nhops_add(ctx);

  fib_prefix_t prefix;
  memcpy(&prefix.fp_addr, &input_params->prefix->address,
         sizeof(ip46_address_t));
  prefix.fp_len = input_params->prefix->len;
  msg->payload.face_ids[0] = input_params->face_id;
  msg->payload.n_faces = 1;

  int ret = vapi_hicn_api_route_nhops_add(ctx, msg, reigster_route_cb, NULL);

  vapi_unlock();
  return ret;
}

char *hicn_vapi_get_error_string(int ret_val) {
  return get_error_string(ret_val);
}

#endif  // __vpp__
