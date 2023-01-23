/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

#include "base.h"
#include "strategy.h"

#include <vpp_plugins/hicn/hicn_enums.h>

static int _ip_prefix_encode(const hicn_ip_address_t *address,
                             int prefix_length, int family,
                             vapi_type_prefix *out) {
  out->len = prefix_length;
  int ret = 0;

  switch (family) {
    case AF_INET:
      memcpy(&out->address.un.ip4[0], &address->v4, 4);
      out->address.af = ADDRESS_IP4;
      break;
    case AF_INET6:
      memcpy(&out->address.un.ip6[0], &address->v6, 16);
      out->address.af = ADDRESS_IP6;
      break;
    default:
      // This should never happen
      ret = -1;
  }

  return ret;
}

static vapi_enum_hicn_strategy _vpp_strategy_libhicn_to_hicnplugin_strategy(
    strategy_type_t strategy) {
  switch (strategy) {
    case STRATEGY_TYPE_LOADBALANCER:
      return HICN_STRATEGY_RR;
    case STRATEGY_TYPE_LOCAL_REMOTE:
      return HICN_STRATEGY_LR;
    case STRATEGY_TYPE_REPLICATION:
      return HICN_STRATEGY_RP;
    case STRATEGY_TYPE_BESTPATH:
      return HICN_STRATEGY_MW;
    default:
      return HICN_STRATEGY_NULL;
  }
}

static vapi_error_e _hicn_strategy_set_cb(
    vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_hicn_api_strategy_set_reply *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;
  return reply->retval;
}

static int _vpp_strategy_set(hc_sock_vpp_data_t *s,
                             const hc_strategy_t *strategy) {
  int ret = -1;

  // Convert libhicn strategy enum to hicnplugin strategy enum and make sure it
  // is valid
  vapi_enum_hicn_strategy strategy_id =
      _vpp_strategy_libhicn_to_hicnplugin_strategy(strategy->type);

  if (strategy_id == HICN_STRATEGY_NULL) {
    return -1;
  }

  // Construct API message
  vapi_msg_hicn_api_strategy_set *msg =
      vapi_alloc_hicn_api_strategy_set(s->g_vapi_ctx_instance);

  // Fill it
  msg->payload.strategy_id = strategy_id;
  ret = _ip_prefix_encode(&strategy->address, strategy->len, strategy->family,
                          &msg->payload.prefix);

  if (ret != 0) {
    return -1;
  }

  vapi_lock();
  ret = vapi_hicn_api_strategy_set(s->g_vapi_ctx_instance, msg,
                                   _hicn_strategy_set_cb, NULL);
  vapi_unlock();

  return ret;
}

int vpp_strategy_create(hc_sock_t *sock, hc_object_t *object, hc_data_t *data) {
  return -1;
}

int vpp_strategy_delete(hc_sock_t *sock, hc_object_t *object, hc_data_t *data) {
  return -1;
}

int vpp_strategy_list(hc_sock_t *sock, hc_object_t *object, hc_data_t *data) {
  return -1;
}

int vpp_strategy_set(hc_sock_t *sock, hc_object_t *object, hc_data_t *data) {
  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;
  return _vpp_strategy_set(s, &object->strategy);
}

DECLARE_VPP_MODULE_OBJECT_OPS(vpp, strategy);
