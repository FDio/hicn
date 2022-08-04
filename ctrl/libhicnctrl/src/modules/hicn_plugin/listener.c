/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

/**
 * \file modules/hicn_plugin/listener.c
 * \brief Implementation of listener object VFT for hicn_plugin.
 */

#include <hicn/util/vector.h>

#include "base.h"
#include "listener.h"

struct listener_data_s {
  hc_listener_t listener;
  hc_data_t *data;
};

/**
 * This is a callback used to append in callback_ctx which is a hc_data_t
 * designed to hold hc_listener_t, a list of listener, each corresponding to an
 * IP address (v4 then v6) of the interfaces, and thus build a list of hICN
 * listeners.
 */
static vapi_error_e process_ip_info(struct vapi_ctx_s *ctx, void *callback_ctx,
                                    vapi_error_e rv, bool is_last,
                                    vapi_payload_ip_address_details *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;
  if (reply && is_last) printf("COUCOU\n");
  if (is_last) return 0;

  struct listener_data_s *ld = (struct listener_data_s *)callback_ctx;

  if (reply->prefix.address.af == ADDRESS_IP4) {
    memcpy(&(ld->listener.local_addr), reply->prefix.address.un.ip4,
           IPV4_ADDR_LEN);
    ld->listener.family = AF_INET;
  } else {
    memcpy(&(ld->listener.local_addr), reply->prefix.address.un.ip6,
           IPV6_ADDR_LEN);
    ld->listener.family = AF_INET6;
  }
  ld->listener.local_port = 0;

  ld->listener.id = reply->sw_if_index;
  hc_data_t *data = ld->data;
  hc_listener_t *listener = &ld->listener;
  hc_data_push(data, listener);

  return rv;
}

/* LISTENER LIST */

typedef struct {
  u32 swif;
  char interface_name[INTERFACE_LEN];
} hc_vapi_interface_t;

/*
 * A pointer to hc_data_t is passed in the callback context
 * Objective is to store a vector of hc_vapi_interface_t inside
 */
static vapi_error_e on_listener_list_complete_cb(
    struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
    vapi_payload_sw_interface_details *reply) {
  if (reply == NULL || rv != VAPI_OK) return rv;

  if (is_last) return 0;

  hc_vapi_interface_t **vpp_interfaces_vec =
      (hc_vapi_interface_t **)callback_ctx;

  hc_vapi_interface_t interface = {.swif = reply->sw_if_index};
  // XXX bug
  memcpy(interface.interface_name, reply->interface_name, INTERFACE_LEN);

  vector_push(*vpp_interfaces_vec, interface);

  return rv;
}

static int _vpp_listener_list(hc_sock_t *sock, hc_data_t *data) {
  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;

  int retval = -1;  // VAPI_OK;

  hc_vapi_interface_t *vpp_interfaces_vec = NULL;
  vector_init(vpp_interfaces_vec, 0, 0);

  vapi_lock();

  vapi_msg_sw_interface_dump *msg =
      vapi_alloc_sw_interface_dump(s->g_vapi_ctx_instance);
  if (!msg) {
    retval = VAPI_ENOMEM;
    goto ERR_MSG;
  }
  msg->payload.sw_if_index = ~0;
  msg->payload.name_filter_valid = 0;

  /* Retrieve the list of interfaces in vpp_interfaces_vec */
  int ret =
      vapi_sw_interface_dump(s->g_vapi_ctx_instance, msg,
                             on_listener_list_complete_cb, &vpp_interfaces_vec);

  if (ret != VAPI_OK) goto ERR_LIST_INTERFACES;

  /* Query the forwarder for each interface */
  // stored in data->buffer == hc_vapi_interface_t* []
  // 2 calls for each interface
  //
  // This function is called twice for each interface, to get resp. the v4 and
  // v6 IP addresses associated to it:
  //     ip_address_dump(sw_if_index, is_ipv6)
  //
  // Function call :
  // vapi_msg_XXX *msg = vapi_alloc_XXX(s->g_vapi_ctx_instance);
  // msg->payload.ATTR = VALUE;
  // [...]
  // int ret = vapi_XXX((s->g_vapi_ctx_instance, msg, CALLBACK, USER_DATA);
  //
  // CALLBACK = process_ip_info
  // USER_DATA = data2
  //
  // We can assume the callbacks are executed before the function returns, and
  // that there is no async code.
  //
  int rc;

  hc_vapi_interface_t *interface;
  vapi_msg_ip_address_dump *msg2;

  struct listener_data_s ld;
  vector_foreach(vpp_interfaces_vec, interface, {
    memset(&ld, 0, sizeof(struct listener_data_s));
    ld.listener.type = FACE_TYPE_HICN;
    rc = snprintf(ld.listener.interface_name, INTERFACE_LEN, "%s",
                  interface->interface_name);
    if (rc < 0 || rc >= INTERFACE_LEN) goto ERR_FOREACH;

    ld.data = data;

    for (unsigned i = 0; i < 2; i++) {
      msg2 = vapi_alloc_ip_address_dump(s->g_vapi_ctx_instance);
      msg2->payload.sw_if_index = interface->swif;
      msg2->payload.is_ipv6 = i;
      retval = vapi_ip_address_dump(s->g_vapi_ctx_instance, msg2,
                                    process_ip_info, &ld);
      if (ret != VAPI_OK) goto ERR_GET_IP;
    }
  });
  retval = 0;
ERR_GET_IP:
ERR_FOREACH:
  vector_free(vpp_interfaces_vec);
ERR_LIST_INTERFACES:
ERR_MSG:
  vapi_unlock();
  return retval;
}

#define vpp_listener_create NULL
#define vpp_listener_delete NULL

static int vpp_listener_list(hc_sock_t *sock, hc_object_t *object,
                             hc_data_t *data) {
  assert(!object || hc_object_is_empty(object));
  return _vpp_listener_list(sock, data);
}

DECLARE_VPP_MODULE_OBJECT_OPS(vpp, listener);
