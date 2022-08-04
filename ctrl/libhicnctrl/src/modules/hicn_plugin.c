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
 * \file api.c
 * \brief Implementation of hICN control library API
 */

#include <assert.h>  // assert
#include <fcntl.h>   // fcntl
#include <math.h>    // log2
#include <stdbool.h>
#include <stdio.h>       // snprintf
#include <string.h>      // memmove, strcasecmp
#include <sys/socket.h>  // socket
#include <unistd.h>      // close, fcntl

#include <hicn/ctrl/data.h>
#include <hicn/ctrl/socket.h>

#include <vapi/vapi_safe.h>
#include <vppinfra/clib.h>
#include <vpp_plugins/hicn/error.h>

#include "../socket_private.h"

#include "hicn_plugin/base.h"  // hc_sock_vpp_data_t
#include "hicn_plugin/listener.h"
#include "hicn_plugin/route.h"

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#if 0

#define foreach_hc_command          \
  _(hicn_api_node_params_set)       \
  _(hicn_api_node_params_set_reply) \
  _(hicn_api_node_params_get_reply) \
  _(hicn_api_node_stats_get_reply)  \
  _(hicn_api_face_get)              \
  _(hicn_api_faces_details)         \
  _(hicn_api_face_stats_details)    \
  _(hicn_api_face_get_reply)        \
  _(hicn_api_route_get)             \
  _(hicn_api_route_get_reply)       \
  _(hicn_api_routes_details)        \
  _(hicn_api_strategies_get_reply)  \
  _(hicn_api_strategy_get)          \
  _(hicn_api_strategy_get_reply)


typedef vapi_type_msg_header2_t hc_msg_header_t;

typedef union {
#define _(a) vapi_payload_##a a;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

typedef struct __attribute__((__packed__)) {
  hc_msg_header_t hdr;
  hc_msg_payload_t payload;
} hc_hicnp_t;

typedef void (*NTOH)(void *msg);

typedef struct __attribute__((__packed__)) {
  hc_data_t *data;
  uint32_t curr_msg;
} callback_ctx_t;

typedef struct __attribute__((__packed__)) {
  hc_hicnp_t *msg;
  vapi_cb_t callback;
  callback_ctx_t *callback_ctx;
  NTOH ntoh;
} hc_msg_s;

/******************************************************************************
 * Control socket
 ******************************************************************************/

static void vpp_free(hc_sock_t *socket) {
  hc_sock_vpp_t *s = TO_HC_SOCK_VPP(socket);
  if (s->url) free(s->url);
  free(s);

  vapi_disconnect_safe();
}

static int vpp_get_next_seq(hc_sock_t *socket) {
  hc_sock_vpp_t *s = TO_HC_SOCK_VPP(socket);
  return vapi_gen_req_context(s->g_vapi_ctx_instance);
}

static int vpp_set_nonblocking(hc_sock_t *socket) {
  hc_sock_vpp_t *s = TO_HC_SOCK_VPP(socket);
  return 0;
}

static int vpp_callback(hc_sock_t *socket, hc_data_t **pdata) {
  // NOT IMPLEMENTED
  return -1;
}

static int vpp_reset(hc_sock_t *socket) {
  // NOT IMPLEMENTED
  return -1;
}
#endif

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

/******************************************************************************
 * Module functions
 ******************************************************************************/

hc_sock_vpp_data_t *hc_sock_vpp_data_create(const char *url) {
  hc_sock_vpp_data_t *s = malloc(sizeof(hc_sock_vpp_data_t));
  if (!s) goto ERR_MALLOC;

  s->roff = s->woff = 0;
  s->url = url ? strdup(url) : NULL;

  return s;

ERR_MALLOC:
  return NULL;
}

void hc_sock_vpp_data_free(hc_sock_vpp_data_t *s) {
  vapi_disconnect_safe();

  if (s->url) free(s->url);
  free(s);
}

static int vpp_connect(hc_sock_t *sock) {
  hc_sock_vpp_data_t *s = (hc_sock_vpp_data_t *)sock->data;
  vapi_error_e rv =
      vapi_connect_safe(&s->g_vapi_ctx_instance, hc_sock_is_async(sock));
  if (rv != VAPI_OK) goto ERR_CONNECT;

  return 0;

ERR_CONNECT:
  ERROR("[hc_sock_connect] connection failed");
  return -1;
}

static ssize_t vpp_prepare(hc_sock_t *sock, hc_request_t *request,
                           uint8_t **buffer) {
  assert(!buffer);

  // XXX all the beginning is generic and could be shared across multiple
  // modules

  /* Dispatch to subrequest if any */
  hc_request_t *current_request = hc_request_get_current(request);

  _ASSERT(!hc_request_get_data(current_request));

  hc_action_t action = hc_request_get_action(current_request);
  hc_object_type_t object_type = hc_request_get_object_type(current_request);
  hc_object_t *object = hc_request_get_object(current_request);

  _ASSERT(hc_request_get_data(current_request) == NULL);
  hc_data_t *data = hc_data_create(object_type);
  if (!data) {
    ERROR("[vpp_prepare] Could not create data storage");
    goto ERR;
  }
  hc_request_set_data(current_request, data);

  hc_module_object_ops_t *vft = &sock->ops.object_vft[object_type];
  if (!vft) goto ERR;
  hc_execute_t execute = vft->execute[action];
  if (!execute) goto ERR;
  int rc = execute(sock, object, data);
  if (rc < 0) goto ERR;

  /* The result is fully contained in data */
  (void)rc;

  hc_request_set_complete(request);
  return 0;

ERR:
  hc_data_set_error(data);
  hc_request_set_complete(request);
  return 0;
}

static hc_sock_ops_t hc_sock_vpp = (hc_sock_ops_t){
    .create_data = (void *(*)(const char *))hc_sock_vpp_data_create,
    .free_data = (void (*)(void *))hc_sock_vpp_data_free,
    .get_fd = NULL,           // not fd based
    .get_recv_buffer = NULL,  // no async support
    .connect = vpp_connect,
    .prepare = vpp_prepare,
    .send = NULL,
    .recv = NULL,
    .process = NULL,
};

ssize_t vpp_command_serialize(hc_action_t action, hc_object_type_t object_type,
                              hc_object_t *object, uint8_t *msg) {
  return hc_sock_vpp.object_vft[object_type].serialize[action](object, msg);
}

// Public constructor

int hc_sock_initialize_module(hc_sock_t *s) {
  s->ops = hc_sock_vpp;
  // XXX shall we memset the VFT ?
  /* LISTENER: CREATE, GET, DELETE not implemented, LIST ok */
  s->ops.object_vft[OBJECT_TYPE_LISTENER] = vpp_listener_module_ops;
  /* CONNECTION : CREATE, GET, UPDATE, DELETE, LIST, SET_* not
     implemented */
  s->ops.object_vft[OBJECT_TYPE_CONNECTION] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_FACE] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_PUNTING] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_CACHE] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_MAPME] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_WLDR] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_POLICY] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_ROUTE] = vpp_route_module_ops;
  s->ops.object_vft[OBJECT_TYPE_STRATEGY] = HC_MODULE_OBJECT_OPS_EMPTY;
  s->ops.object_vft[OBJECT_TYPE_SUBSCRIPTION] = HC_MODULE_OBJECT_OPS_EMPTY;
  return 0;
}
