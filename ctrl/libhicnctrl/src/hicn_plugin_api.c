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

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/commands.h>
#include <hicn/util/token.h>
#include <strings.h>
#include <vapi/hicn.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types_api.h>

#define APP_NAME "hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE 2

// #define vl_typedefs
// #include <vpp/api/vpe_all_api_h.h>
// #undef vl_typedefs

DEFINE_VAPI_MSG_IDS_HICN_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON

/*
 * Internal state associated to a pending request
 */
typedef struct {
  vapi_ctx_t g_vapi_ctx_instance;
  int seq;
  // Reusing the buffer of data to hold both the unparsed response from the
  // forwarder and the result of the parsing
  hc_data_t *data;
  /* Information used to process results */
  int size_in;
  HC_PARSE parse;
} hc_sock_request_t;

/**
 * Messages to the forwarder might be multiplexed thanks to the seqNum fields in
 * the header_control_message structure. The forwarder simply answers back the
 * original sequence number. We maintain a map of such sequence number to
 * outgoing queries so that replied can be demultiplexed and treated
 * appropriately.
 */
TYPEDEF_MAP_H(hc_sock_map, int, hc_sock_request_t *);
TYPEDEF_MAP(hc_sock_map, int, hc_sock_request_t *, int_cmp, int_snprintf,
            generic_snprintf);

struct hc_sock_s {
  vapi_ctx_t g_vapi_ctx_instance;
  char *url;
  int fd;

  size_t roff; /**< Read offset */
  size_t woff; /**< Write offset */
  u32 buffer[RECV_BUFLEN];
  /* Next sequence number to be used for requests */
  int seq;

  bool async;
  hc_sock_map_t *map;
};

hc_sock_request_t *hc_sock_request_create(int seq, hc_data_t *data,
                                          HC_PARSE parse) {
  assert(data);

  hc_sock_request_t *request = malloc(sizeof(hc_sock_request_t));
  if (!request) return NULL;
  request->seq = seq;
  request->data = data;
  request->parse = parse;
  request->size_in = 0;
  return request;
}

void hc_sock_request_free(hc_sock_request_t *request) { free(request); }

/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_hc_command             \
  _(hicn_api_node_params_set)          \
  _(hicn_api_node_params_set_reply)    \
  _(hicn_api_node_params_get_reply)    \
  _(hicn_api_node_stats_get_reply)     \
  _(hicn_api_face_add)                 \
  _(hicn_api_face_add_reply)           \
  _(hicn_api_face_del)                 \
  _(hicn_api_face_del_reply)           \
  _(hicn_api_face_get)                 \
  _(hicn_api_faces_details)            \
  _(hicn_api_face_stats_details)       \
  _(hicn_api_face_get_reply)           \
  _(hicn_api_route_nhops_add)          \
  _(hicn_api_route_nhops_add_reply)    \
  _(hicn_api_route_del)                \
  _(hicn_api_route_del_reply)          \
  _(hicn_api_route_nhop_del)           \
  _(hicn_api_route_nhop_del_reply)     \
  _(hicn_api_route_get)                \
  _(hicn_api_route_get_reply)          \
  _(hicn_api_routes_details)           \
  _(hicn_api_strategies_get_reply)     \
  _(hicn_api_strategy_get)             \
  _(hicn_api_strategy_get_reply)       \
  _(hicn_api_punting_add)              \
  _(hicn_api_punting_add_reply)        \
  _(hicn_api_punting_del)              \
  _(hicn_api_punting_del_reply)

typedef vapi_type_msg_header2_t hc_msg_header_t;

typedef union {
#define _(a) vapi_payload_ ## a a;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

#define IS_DUMP_MSG(a) (a == vapi_msg_id_hicn_api_face_stats_dump ||           \
                        a == vapi_msg_id_hicn_api_routes_dump ||               \
                        a == vapi_msg_id_hicn_api_faces_dump ||                \
                        a == vapi_msg_id_sw_interface_dump)

typedef struct __attribute__ ((__packed__)) {
  hc_msg_header_t hdr;
  hc_msg_payload_t payload;
} hc_hicnp_t;

typedef void (* NTOH)(void *msg);

typedef struct __attribute__((__packed__)) {
  hc_sock_t *s;
  uint32_t ctx_msg;
} callback_ctx_t;

typedef struct __attribute__((__packed__)) {
  hc_hicnp_t * hicnp_msg;
  vapi_cb_t callback;
  callback_ctx_t *callback_ctx;
  NTOH ntoh;
} hc_msg_s;

/******************************************************************************
 * Control Data
 ******************************************************************************/

hc_data_t *hc_data_create(size_t in_element_size, size_t out_element_size, data_callback_t complete_cb) {
  hc_data_t *data = malloc(sizeof(hc_data_t));
  if (!data) goto ERR_MALLOC;

  /* FIXME Could be NULL thanks to realloc provided size is 0 */
  data->in_element_size = in_element_size;
  data->out_element_size = out_element_size;
  data->size = 0;
  data->current = 0;
  data->complete = false;
  data->command_id = 0;  // TODO this could also be a busy mark in the socket
  /* No callback needed in blocking code for instance */
  data->complete_cb = complete_cb;

  return data;

ERR_MALLOC:
  return NULL;
}

void hc_data_free(hc_data_t *data) {
  if (data != NULL) {
    if (data->buffer) free(data->buffer);
    free(data);
  }
}

/******************************************************************************
 * Control socket
 ******************************************************************************/

/**
 * \brief Parse a connection URL into a sockaddr
 * \param [in] url - URL
 * \param [out] sa - Resulting struct sockaddr, expected zero'ed.
 * \return 0 if parsing succeeded, a negative error value otherwise.
 */
int hc_sock_parse_url(const char *url, struct sockaddr *sa) {
  // NOT IMPLEMENTED
  return -1;
}

hc_sock_t *hc_sock_create_url(const char *url) {
  // NOT IMPLEMENTED
  return NULL;
}

hc_sock_t *hc_sock_create(void) {
  hc_sock_t *s = malloc(sizeof(hc_sock_t));
  memset(s, 0, sizeof(hc_sock_t));

  s->map = hc_sock_map_create();
  if (!s->map) goto ERR_MAP;

  //By default the socket is blocking -- not async
  s->async = 0;

  return s;

ERR_MAP:
  free(s);
  return NULL;
}

void hc_sock_free(hc_sock_t *s) {
  hc_sock_request_t **request_array = NULL;
  int n = hc_sock_map_get_value_array(s->map, &request_array);
  if (n < 0) {
    ERROR("Could not retrieve pending request array for freeing up resources");
  } else {
    for (unsigned i = 0; i < n; i++) {
      hc_sock_request_t *request = request_array[i];
      hc_sock_request_free(request);
    }
    free(request_array);
  }

  hc_sock_map_free(s->map);
  if (s->url) free(s->url);
  close(s->fd);
  free(s);
}

int hc_sock_get_next_seq(hc_sock_t *s) {
  return vapi_gen_req_context(s->g_vapi_ctx_instance);
}

int hc_sock_set_nonblocking(hc_sock_t *s) {
  s->async = 1;
  return 0;
}

int hc_sock_get_fd(hc_sock_t *s) { return 1; }

vapi_error_e vapi_cb(vapi_ctx_t ctx, void *callback_ctx, vapi_error_e error, bool is_last, void *payload) {
  callback_ctx_t *ctx_call = (callback_ctx_t *)callback_ctx;
  hc_sock_t *s = ctx_call->s;

  if ((s->woff != s->roff) && (s->woff % RECV_BUFLEN == 0)) {
    ERROR("[hc_sock_process] No more space on the buffer to store responces");
    return -1;
  }

  if (is_last) {
    s->buffer[s->woff % RECV_BUFLEN] = ctx_call->ctx_msg;
    s->woff++;
  }

  if(!payload)
    return 0;

  hc_sock_request_t *request = NULL;
  if (hc_sock_map_get(s->map, ctx_call->ctx_msg, &request) <
      0) {
    ERROR("[hc_sock_process] Error searching for matching request");
    return -1;
  }

  if (request->data->current == request->data->size) {
    if (request->data->size == 0){
      request->data->size = 1;
      request->data->buffer = malloc(request->data->in_element_size * request->data->size);
    } else {
      void *tmp =
          malloc(request->data->in_element_size * request->data->size * 2);
      memcpy(tmp, request->data->buffer, request->data->current * request->data->in_element_size);
      free(request->data->buffer);
      request->data->size *= 2;
      request->data->buffer = tmp;
    }
  }
  memcpy(request->data->buffer +
             request->data->current * request->data->in_element_size,
         payload, request->data->in_element_size);
  request->data->current++;

  return 0;
}

int hc_sock_connect(hc_sock_t *s) {
  if (s->g_vapi_ctx_instance == NULL) {
    vapi_error_e rv = vapi_ctx_alloc(&s->g_vapi_ctx_instance);
    rv = vapi_connect(s->g_vapi_ctx_instance, APP_NAME, NULL,
                      MAX_OUTSTANDING_REQUESTS, RESPONSE_QUEUE_SIZE,
                      s->async ? VAPI_MODE_NONBLOCKING : VAPI_MODE_BLOCKING, true);
    if (rv != VAPI_OK) {
      vapi_ctx_free(s->g_vapi_ctx_instance);
      goto ERR_CONNECT;
    }
    printf("[hc_sock_connect] *connected %s ok", APP_NAME);
  } else {
    printf("connection %s keeping", APP_NAME);
  }

  return 0;

ERR_CONNECT:
  ERROR("[hc_sock_connect] connection %s failes", APP_NAME);
  return -1;
}

int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, int seq) {
  vapi_cb_t callback = ((hc_msg_s *)msg)->callback;
  callback_ctx_t *callback_ctx = ((hc_msg_s *)msg)->callback_ctx;

  if (!msg || !callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(s->g_vapi_ctx_instance) && vapi_requests_full(s->g_vapi_ctx_instance)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (s->g_vapi_ctx_instance))) {
    return rv;
  }
  ((hc_msg_s *)msg)->hicnp_msg->hdr.context = seq;
  callback_ctx->ctx_msg = seq;
  vapi_msg_id_t msg_id = vapi_lookup_vapi_msg_id_t(s->g_vapi_ctx_instance, ((hc_msg_s *)msg)->hicnp_msg->hdr._vl_msg_id);
  ((hc_msg_s *)msg)->ntoh(((hc_msg_s *)msg)->hicnp_msg);
  if (IS_DUMP_MSG(msg_id)) {
    if (VAPI_OK == (rv = vapi_send_with_control_ping (s->g_vapi_ctx_instance, ((hc_msg_s *)msg)->hicnp_msg, seq))) {
      vapi_store_request(s->g_vapi_ctx_instance, seq, true, (vapi_cb_t)callback, callback_ctx);
    }
  } else {
    if (VAPI_OK == (rv = vapi_send (s->g_vapi_ctx_instance, ((hc_msg_s *)msg)->hicnp_msg))) {
        vapi_store_request(s->g_vapi_ctx_instance, seq, false, (vapi_cb_t)callback, callback_ctx);
    }
  }
    
  if (rv != VAPI_OK) {
    if (VAPI_OK != vapi_producer_unlock (s->g_vapi_ctx_instance)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}

int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_sock_recv(hc_sock_t *s) {
  vapi_error_e rv;
  if (VAPI_OK != vapi_producer_unlock (s->g_vapi_ctx_instance)) {
    abort (); /* this really shouldn't happen */
  }
  if (vapi_is_nonblocking(s->g_vapi_ctx_instance)) {
    rv = VAPI_OK;
  } else {
    rv = vapi_dispatch(s->g_vapi_ctx_instance);
  }

  return rv;
}

int hc_sock_process(hc_sock_t *s, hc_data_t **pdata) {
  int err = 0;
  int seq = s->buffer[s->roff % RECV_BUFLEN];

  hc_sock_request_t *request = NULL;
  if (hc_sock_map_get(s->map, seq, &request) < 0) {
    ERROR("[hc_sock_process] Error searching for matching request");
    return -1;
  }
  if (!request) {
    ERROR("[hc_sock_process] No request matching received sequence number");
    return -1;
  }

  if (s->roff == s->woff) {
    ERROR("[hc_sock_process] No data received for the corresponding request");
    return -1;
  }

  if(request->parse != NULL)
    err = request->parse((u8 *)request, NULL);
  request->data->complete = 1;
  if (!err && request->data->complete_cb != NULL)
    err = request->data->complete_cb(request->data, s);
  s->roff++;

  if (pdata) *pdata = request->data;

  hc_sock_map_remove(s->map, seq, NULL);
  hc_sock_request_free(request);

  return err;
}

int hc_sock_callback(hc_sock_t *s, hc_data_t **pdata) {
  hc_data_t *data = NULL;

  for (;;) {
    int n = hc_sock_recv(s);
    if (n == 0) {
      goto ERR_EOF;
    }
    if (n < 0) {
      switch (errno) {
        case ECONNRESET:
        case ENODEV:
          /* Forwarder restarted */
          WARN("Forwarder likely restarted: not (yet) implemented");
          goto ERR;
        case EWOULDBLOCK:
          // DEBUG("Would block... stop reading from socket");
          goto END;
        default:
          perror("hc_sock_recv");
          goto ERR;
      }
    }
    if (hc_sock_process(s, &data) < 0) {
      goto ERR;
    }
  }
END:
  if (pdata)
    *pdata = data;
  else
    hc_data_free(data);
  return 0;

ERR:
  hc_data_free(data);
ERR_EOF:
  return -1;
}

int hc_sock_reset(hc_sock_t *s) {
  s->roff = s->woff = 0;
  return 0;
}

/******************************************************************************
 * Command-specific structures and functions
 ******************************************************************************/

typedef int (*HC_PARSE)(const u8 *, u8 *);

typedef struct {
  hc_action_t cmd;
  command_id cmd_id;
  size_t size_in;
  size_t size_out;
  HC_PARSE parse;
  data_callback_t complete_cb;
} hc_command_params_t;

int hc_execute_command(hc_sock_t *s, hc_msg_t *msg, size_t msg_len,
                       hc_command_params_t *params, hc_data_t **pdata,
                       bool async) {
  if (async) assert(!pdata);

  /* Sanity check */
  switch (params->cmd) {
    case ACTION_CREATE:
      assert(params->size_in != 0); /* payload repeated */
      //assert(params->size_out == 0); //Face will return the face id
      //assert(params->parse == NULL);
      break;
    case ACTION_DELETE:
      assert(params->size_in != 0); /* payload repeated */
      assert(params->size_out == 0);
      //assert(params->parse == NULL);
      break;
    case ACTION_LIST:
      assert(params->size_in != 0);
      assert(params->size_out != 0);
      //assert(params->parse != NULL);
      break;
    case ACTION_SET:
      assert(params->size_in != 0);
      assert(params->size_out == 0);
      //assert(params->parse == NULL);
      break;
    default:
      return -1;
  }

  /* XXX data will at least store the result (complete) */
  hc_data_t *data = hc_data_create(params->size_in, params->size_out, params->complete_cb);
  if (!data) {
    ERROR("[hc_execute_command] Could not create data storage");
    goto ERR_DATA;
  }

  int seq = hc_sock_get_next_seq(s);

  /* Create state used to process the request */
  hc_sock_request_t *request = NULL;
  request = hc_sock_request_create(seq, data, params->parse);
  if (!request) {
    ERROR("[hc_execute_command] Could not create request state");
    goto ERR_REQUEST;
  }

  /* Add state to map */
  if (hc_sock_map_add(s->map, seq, request) < 0) {
    ERROR("[hc_execute_command] Error adding request state to map");
    goto ERR_MAP;
  }

  if (hc_sock_send(s, msg, msg_len, seq) < 0) {
    ERROR("[hc_execute_command] Error sending message");
    goto ERR_PROCESS;
  }

  if (async) return 0;

  while (!data->complete) {
    // CAN WE COLLAPSE THEM INTO A SINGLE COMMAND? Ideally the process would be
    // done in the recv
    /*
     * As the socket is non blocking it might happen that we need to read
     * several times before success... shall we alternate between blocking
     * and non-blocking mode ?
     */
    if (hc_sock_recv(s) < 0) continue;  // break;
    if (hc_sock_process(s, pdata) < 0) {
      ERROR("[hc_execute_command] Error processing socket results");
      goto ERR_PROCESS;
    }
  }

  if (!pdata) hc_data_free(data);

  return 0;

ERR_PROCESS:
ERR_MAP:
  hc_sock_request_free(request);
ERR_REQUEST:
  hc_data_free(data);
ERR_DATA:
  return -1;
}

/*----------------------------------------------------------------------------*
 * Listeners
 *----------------------------------------------------------------------------*/

/* LISTENER CREATE */

int _hc_listener_create(hc_sock_t *s, hc_listener_t *listener, bool async) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_listener_create(hc_sock_t *s, hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_listener_create_async(hc_sock_t *s, hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

/* LISTENER GET */
int hc_listener_get(hc_sock_t *s, hc_listener_t *listener,
                    hc_listener_t **listener_found) {
  // NOT IMPLEMENTED
  return -1;
}

/* LISTENER DELETE */

int hc_listener_delete(hc_sock_t *s, hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_listener_delete_async(hc_sock_t *s, hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

vapi_error_e process_ip_info(struct vapi_ctx_s *ctx,
                            void *callback_ctx,
                            vapi_error_e rv,
                            bool is_last,
                            vapi_payload_ip_address_details *reply) {

  if (is_last)
    return 0;
  hc_data_t *data = (hc_data_t *)callback_ctx;

  if (data->size == data->current) {
    hc_listener_t * listeners = malloc(sizeof(hc_listener_t) * data->size * 2);
    memcpy(listeners, data->buffer, sizeof(hc_listener_t) * data->size);
    data->size *=2;
    free(data->buffer);
    data->buffer = (void *)listeners;
  }

  hc_listener_t * listener = (hc_listener_t *)(data->buffer + data->current * sizeof(hc_listener_t));

  if(reply->prefix.address.af == ADDRESS_IP4) {
    memcpy(listener->local_addr.v4.as_u8, reply->prefix.address.un.ip4, IPV4_ADDR_LEN);
    listener->family = AF_INET;
  }
  else {
    memcpy(listener->local_addr.v6.as_u8, reply->prefix.address.un.ip6, IPV6_ADDR_LEN);
    listener->family = AF_INET6;
  }

  listener->id = reply->sw_if_index;
  data->current++;
  return rv;
}

/* A listener in vpp is an interface with classify enabled */
int listener_list_complete_cb(struct hc_data_s * data, void *ctx) {
  // No need to write anything on the dst, no data expected

  hc_sock_t *s = (hc_sock_t *)ctx;

  int n_interfaces = data->current;
  u32 *swifs = malloc(sizeof(u32) * n_interfaces);

  for (int i = 0; i < n_interfaces; i++) {
    vapi_payload_sw_interface_details *reply =
      (vapi_payload_sw_interface_details *)(data->buffer + i * data->in_element_size);
    swifs[i] = reply->sw_if_index;
  }

  vapi_payload_sw_interface_details * temp = (vapi_payload_sw_interface_details *)data->buffer;
  data->buffer = malloc(sizeof(hc_listener_t));
  data->size = 1;
  data->current = 0;

  /* Query the forwarder for each interface */
  for(int i = 0; i < n_interfaces; i++) {
    size_t index = data->current;
    vapi_msg_ip_address_dump* msg = vapi_alloc_ip_address_dump(s->g_vapi_ctx_instance);
    msg->payload.sw_if_index = swifs[i];
    msg->payload.is_ipv6 = 0;
    vapi_payload_sw_interface_details *reply =
      &(temp[i]);
    int retval = vapi_ip_address_dump(s->g_vapi_ctx_instance, msg, process_ip_info, data);
    vapi_msg_ip_address_dump* msg2 = vapi_alloc_ip_address_dump(s->g_vapi_ctx_instance);
    msg2->payload.sw_if_index = swifs[i];
    msg2->payload.is_ipv6 = 1;
    retval = vapi_ip_address_dump(s->g_vapi_ctx_instance, msg2, process_ip_info, data);
    for (size_t j = index; j < data->current; j++) {
      memcpy(((hc_listener_t *)(data->buffer))[j].interface_name, reply->interface_name, INTERFACE_LEN);
    }
    if (retval)
      return retval;
  }
  
  data->size = data->current;
  data->out_element_size = sizeof(hc_listener_t);
  free(temp);
  return 0;
}

/* LISTENER LIST */
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
//  vapi_msg_flow_classify_dump *hicnp_msg;
  vapi_msg_sw_interface_dump *hicnp_msg;
  hicnp_msg = vapi_alloc_sw_interface_dump(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_sw_interface_dump_hton;

  hicnp_msg->payload.sw_if_index = ~0;
  hicnp_msg->payload.name_filter_valid = 0;

  //hicnp_msg->payload.type = 1; //0 v4, 1 v6
  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_LISTENERS,
      .size_in = sizeof(vapi_msg_sw_interface_details),
      .size_out = sizeof(hc_listener_t),
      .parse = (HC_PARSE)NULL,
      .complete_cb = listener_list_complete_cb,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, pdata,
                            false);
}

int hc_listener_list_async(hc_sock_t *s, hc_data_t **pdata) {
  // NOT IMPLEMENTED
  return -1;
}

/* LISTENER VALIDATE */

int hc_listener_validate(const hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

/* LISTENER CMP */

int hc_listener_cmp(const hc_listener_t *l1, const hc_listener_t *l2) {
  // NOT IMPLEMENTED
  return -1;
}

/* LISTENER PARSE */

int hc_listener_parse(void *in, hc_listener_t *listener) {
  // NOT IMPLEMENTED
  return -1;
}

GENERATE_FIND(listener)

/* LISTENER SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int
hc_listener_snprintf(char * s, size_t size, hc_listener_t * listener)
{
    char local[MAXSZ_URL];
    int rc;
    rc = url_snprintf(local, MAXSZ_URL,
         listener->family, &listener->local_addr, listener->local_port);
    if (rc >= MAXSZ_URL)
        WARN("[hc_listener_snprintf] Unexpected truncation of URL string");
    if (rc < 0)
        return rc;

    return snprintf(s, size, "%s %s", listener->interface_name, local);
}

/*----------------------------------------------------------------------------*
 * CONNECTION
 *----------------------------------------------------------------------------*/

/* CONNECTION CREATE */

int hc_connection_create(hc_sock_t *s, hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_connection_create_async(hc_sock_t *s, hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION GET */

int hc_connection_get(hc_sock_t *s, hc_connection_t *connection,
                      hc_connection_t **connection_found) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION DELETE */

int hc_connection_delete(hc_sock_t *s, hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_connection_delete_async(hc_sock_t *s, hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION LIST */

int hc_connection_list(hc_sock_t *s, hc_data_t **pdata) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_connection_list_async(hc_sock_t *s, hc_data_t **pdata) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION VALIDATE */

int hc_connection_validate(const hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION CMP */

/*
 * hICN light uses ports even for hICN connections, but their value is ignored.
 * As connections are specific to hicn-light, we can safely use IP and ports for
 * comparison independently of the face type.
 */
int hc_connection_cmp(const hc_connection_t *c1, const hc_connection_t *c2) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION PARSE */

int hc_connection_parse(void *in, hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

GENERATE_FIND(connection)

/* CONNECTION SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_connection_snprintf(char *s, size_t size,
                           const hc_connection_t *connection) {
  // NOT IMPLEMENTED
  return -1;
}

/* CONNECTION SET ADMIN STATE */

int hc_connection_set_admin_state(hc_sock_t *s, const char *conn_id_or_name,
                                  face_state_t state) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_connection_set_admin_state_async(hc_sock_t *s,
                                        const char *conn_id_or_name,
                                        face_state_t state) {
  // NOT IMPLEMENTED
  return -1;
}

/*----------------------------------------------------------------------------*
 * Routes
 *----------------------------------------------------------------------------*/

/* ROUTE CREATE */
int parse_route_create(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;
  vapi_payload_hicn_api_route_nhops_add_reply *reply =
      (vapi_payload_hicn_api_route_nhops_add_reply *)request->data->buffer;

  int retval = reply->retval;
  free(reply);
  return retval;
}

int _hc_route_create(hc_sock_t *s, hc_route_t *route, bool async) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_route_nhops_add *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_route_nhops_add(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_route_nhops_add_hton;

  if (route->family == AF_INET) {
    memcpy(&hicnp_msg->payload.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
  }
  else {
    memcpy(&hicnp_msg->payload.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
  }
  hicnp_msg->payload.prefix.address.af =
      route->family == AF_INET ? ADDRESS_IP4 : ADDRESS_IP6;
  hicnp_msg->payload.prefix.len = route->len;
  hicnp_msg->payload.face_ids[0] = route->face_id;
  hicnp_msg->payload.n_faces = 1;

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = ADD_ROUTE,
      .size_in =
          sizeof(vapi_msg_hicn_api_route_nhops_add),
      .size_out = 0,
      .parse = (HC_PARSE)parse_route_create,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, NULL,
                            async);
}

int hc_route_create(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_create(s, route, false);
}

int hc_route_create_async(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_create(s, route, true);
}

/* ROUTE DELETE */

int parse_route_delete(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;
  vapi_payload_hicn_api_route_nhop_del_reply *reply =
      (vapi_payload_hicn_api_route_nhop_del_reply *)request->data->buffer;

  int retval = reply->retval;
  free(reply);
  return retval;
}

int _hc_route_delete(hc_sock_t *s, hc_route_t *route, bool async) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_route_nhop_del *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_route_nhop_del(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_route_nhop_del_hton;

  memcpy(&hicnp_msg->payload.prefix.address.un.ip6[0], &route->remote_addr, 16);
  hicnp_msg->payload.prefix.address.af =
      route->family == AF_INET ? ADDRESS_IP4 : ADDRESS_IP6;
  hicnp_msg->payload.prefix.len = route->len;
  hicnp_msg->payload.faceid = route->face_id;

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = REMOVE_ROUTE,
      .size_in =
          sizeof(vapi_msg_hicn_api_route_nhop_del), 
      .size_out = 0,
      .parse = (HC_PARSE)parse_route_delete,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, NULL,
                            async);
}

int hc_route_delete(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_delete(s, route, false);
}

int hc_route_delete_async(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_delete(s, route, true);
}

/* ROUTE LIST */
int parse_route_list(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;

  int size = 0;
  for (int i = 0; i < request->data->current; i++) {
    vapi_payload_hicn_api_routes_details *reply =
        (vapi_payload_hicn_api_routes_details
             *)(request->data->buffer + i * request->data->in_element_size);
    size += reply->nfaces;
  }
  hc_route_t *output = malloc(sizeof(hc_route_t) * size);

  int cur = 0;
  for (int j = 0; j < request->data->current; j++) {
    vapi_payload_hicn_api_routes_details *reply =
        (vapi_payload_hicn_api_routes_details
             *)(request->data->buffer + j * request->data->in_element_size);
    for (int i = 0; i < reply->nfaces; i++) {
      output[cur].face_id = reply->faceids[i];
      output[cur].cost = 1;
      output[cur].len = reply->prefix.len;
      if (reply->prefix.address.af == ADDRESS_IP6)
      {
        memcpy(output[cur].remote_addr.v6.as_u8, reply->prefix.address.un.ip6, 16);
      }
      else
      {
        memcpy(output[cur].remote_addr.v4.as_u8, reply->prefix.address.un.ip4, 4);
      }
      output[cur].family = reply->prefix.address.af == ADDRESS_IP6? AF_INET6 : AF_INET;
      cur++;
    }
  }

  free(request->data->buffer);
  request->data->buffer = (void *)output;
  request->data->size = size;
  request->data->out_element_size = sizeof(hc_route_t);
  return 0;
}

int _hc_route_list(hc_sock_t *s, hc_data_t **pdata, bool async) {
  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_routes_dump *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_routes_dump(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_routes_dump_hton;

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_ROUTES,
      .size_in = sizeof(vapi_msg_hicn_api_routes_details),
      .size_out = sizeof(hc_route_t),
      .parse = (HC_PARSE)parse_route_list,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, pdata,
                            async);
}

int hc_route_list(hc_sock_t *s, hc_data_t **pdata) {
  return _hc_route_list(s, pdata, false);
}

int hc_route_list_async(hc_sock_t *s) {
  return _hc_route_list(s, NULL, true);
}

/* ROUTE SNPRINTF */

/* /!\ Please update constants in header file upon changes */
int hc_route_snprintf(char *s, size_t size, hc_route_t *route) {
  /* interface cost prefix length */

  char prefix[MAXSZ_IP_ADDRESS];
  int rc;

  rc = ip_address_snprintf(prefix, MAXSZ_IP_ADDRESS, &route->remote_addr,
                           route->family);
  if (rc < 0) return rc;

  return snprintf(s, size, "%*d %*d %s %*d", MAXSZ_FACE_ID, route->face_id,
                  MAXSZ_COST, route->cost, prefix, MAXSZ_LEN, route->len);
}

/*----------------------------------------------------------------------------*
 * Face
 *
 * Face support is not directly available in hicn-light, but we can offer such
 * an interface through a combination of listeners and connections. The code
 * starts with some conversion functions between faces/listeners/connections.
 *
 * We also need to make sure that there always exist a (single) listener when a
 * connection is created, and in the hICN face case, that there is a single
 * connection attached to this listener.
 *
 *----------------------------------------------------------------------------*/

/* FACE -> LISTENER */

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener) {
  const face_t *f = &face->face;

  switch (f->type) {
    case FACE_TYPE_HICN_LISTENER:
      break;
    case FACE_TYPE_TCP_LISTENER:
      break;
    case FACE_TYPE_UDP_LISTENER:
      break;
    default:
      return -1;
  }
  return -1; /* XXX Not implemented */
}

/* LISTENER -> FACE */

int hc_listener_to_face(const hc_listener_t *listener, hc_face_t *face) {
  return -1; /* XXX Not implemented */
}

/* FACE -> CONNECTION */

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name) {
  return 0;
}

/* CONNECTION -> FACE */

int hc_connection_to_face(const hc_connection_t *connection, hc_face_t *face) {
  return 0;
}

/* CONNECTION -> LISTENER */

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener) {
  return 0;
}

/* FACE CREATE */
int parse_face_create(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;
  vapi_payload_hicn_api_face_add_reply *reply =
      (vapi_payload_hicn_api_face_add_reply *)request->data->buffer;

  hc_face_t *output = malloc(sizeof(hc_face_t));

  output->id = reply->faceid;
  int retval = reply->retval;
  free(request->data->buffer);
  request->data->buffer = (void *)output;
  request->data->size = 1;
  request->data->out_element_size = sizeof(hc_face_t);
  return retval;
}

int hc_face_create(hc_sock_t *s, hc_face_t *face) {
  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_face_add *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_face_add(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_face_add_hton;

  switch(face->face.type) {
    case FACE_TYPE_HICN:
    {
      u8 check = ip46_address_is_ip4((ip46_address_t *)&(face->face.local_addr)) == ip46_address_is_ip4((ip46_address_t *)&(face->face.remote_addr));
      if (!check)
        return -1;

      hicnp_msg->payload.type = IP_FACE;
      if (ip46_address_is_ip4((ip46_address_t *)&(face->face.local_addr)))
      {
        memcpy(hicnp_msg->payload.face.ip.local_addr.un.ip4, face->face.local_addr.v4.as_u8, 4);
        memcpy(hicnp_msg->payload.face.ip.remote_addr.un.ip4, face->face.remote_addr.v4.as_u8, 4);
        hicnp_msg->payload.face.ip.local_addr.af = ADDRESS_IP4;
        hicnp_msg->payload.face.ip.remote_addr.af = ADDRESS_IP4;
      }
      else
      {
        memcpy(hicnp_msg->payload.face.ip.local_addr.un.ip6, face->face.local_addr.v6.as_u8, 16);
        memcpy(hicnp_msg->payload.face.ip.remote_addr.un.ip6, face->face.remote_addr.v6.as_u8, 16);
        hicnp_msg->payload.face.ip.local_addr.af = ADDRESS_IP6;
        hicnp_msg->payload.face.ip.remote_addr.af = ADDRESS_IP6;
      }
      hicnp_msg->payload.face.ip.swif = face->face.netdevice.index;
      memcpy(hicnp_msg->payload.face.ip.if_name, face->face.netdevice.name, IFNAMSIZ);
      break;
    }
    case FACE_TYPE_UDP:
    {
      u8 check = ip46_address_is_ip4((ip46_address_t *)&(face->face.local_addr)) == ip46_address_is_ip4((ip46_address_t *)&(face->face.remote_addr));
      if (!check)
        return -1;

      hicnp_msg->payload.type = UDP_FACE;
      if (ip46_address_is_ip4((ip46_address_t *)&(face->face.local_addr)))
      {
        memcpy(hicnp_msg->payload.face.udp.local_addr.un.ip4, face->face.local_addr.v4.as_u8, 4);
        memcpy(hicnp_msg->payload.face.udp.remote_addr.un.ip4, face->face.remote_addr.v4.as_u8, 4);
        hicnp_msg->payload.face.udp.local_addr.af = ADDRESS_IP4;
        hicnp_msg->payload.face.udp.remote_addr.af = ADDRESS_IP4;
      }
      else
      {
        memcpy(hicnp_msg->payload.face.udp.local_addr.un.ip6, face->face.local_addr.v6.as_u8, 16);
        memcpy(hicnp_msg->payload.face.udp.remote_addr.un.ip6, face->face.remote_addr.v6.as_u8, 16);
        hicnp_msg->payload.face.udp.local_addr.af = ADDRESS_IP6;
        hicnp_msg->payload.face.udp.remote_addr.af = ADDRESS_IP6;
      }
      hicnp_msg->payload.face.udp.lport = face->face.local_port;
      hicnp_msg->payload.face.udp.rport = face->face.remote_port;
      hicnp_msg->payload.face.udp.swif = face->face.netdevice.index;
      memcpy(hicnp_msg->payload.face.udp.if_name, face->face.netdevice.name, IFNAMSIZ);
      break;
    }
    default:
      return -1;
  }

  hc_command_params_t params = {
      .cmd = ACTION_CREATE,
      .cmd_id = ADD_CONNECTION,
      .size_in =
          sizeof(vapi_msg_hicn_api_face_add),
      .size_out = sizeof(hc_face_t),
      .parse = (HC_PARSE)parse_face_create,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, NULL,
                            false);
}

/* FACE DELETE */
int parse_face_delete(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;
  vapi_payload_hicn_api_face_del_reply *reply =
      (vapi_payload_hicn_api_face_del_reply *)request->data->buffer;

  int retval = reply->retval;
  free(reply);
  return retval;
}

int hc_face_delete(hc_sock_t *s, hc_face_t *face) {

  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_face_del *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_face_del(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_face_del_hton;

  hicnp_msg->payload.faceid = face->id;

  hc_command_params_t params = {
      .cmd = ACTION_DELETE,
      .cmd_id = REMOVE_ROUTE,
      .size_in =
          sizeof(vapi_msg_hicn_api_face_del), 
      .size_out = 0,
      .parse = (HC_PARSE)parse_route_delete,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, NULL,
                            false);
}

/* FACE LIST */

int parse_face_list(uint8_t *src, uint8_t *dst) {
  // No need to write anything on the dst, no data expected

  hc_sock_request_t *request = (hc_sock_request_t *)src;
  hc_face_t *output = malloc(sizeof(hc_face_t)*request->data->current);

  int retval;
  int cur = 0;
  for (int j = 0; j < request->data->current; j++) {
    vapi_payload_hicn_api_faces_details *reply =
        (vapi_payload_hicn_api_faces_details
             *)(request->data->buffer + j * request->data->in_element_size);
    retval = reply->retval;
    switch(reply->type)
    {
      case IP_FACE:
      {
        if (reply->face.ip.local_addr.af == ADDRESS_IP4)
        {
          memcpy(output[j].face.local_addr.v4.as_u8, reply->face.ip.local_addr.un.ip4, IPV4_ADDR_LEN);
          memcpy(output[j].face.remote_addr.v4.as_u8, reply->face.ip.remote_addr.un.ip4, IPV4_ADDR_LEN);
        }
        else
        {
          memcpy(output[j].face.local_addr.v6.as_u8, reply->face.ip.local_addr.un.ip6, IPV6_ADDR_LEN);
          memcpy(output[j].face.remote_addr.v6.as_u8, reply->face.ip.remote_addr.un.ip6, IPV6_ADDR_LEN);
        }
        output[j].face.type = FACE_TYPE_HICN;
        output[j].id = reply->faceid;
        output[j].face.netdevice.index = reply->face.ip.swif;
        memcpy(output[j].face.netdevice.name, reply->face.ip.if_name, IFNAMSIZ);
        break;
      }
      case UDP_FACE:
      {
        if (reply->face.ip.local_addr.af == ADDRESS_IP4)
        {
          memcpy(output[j].face.local_addr.v4.as_u8, reply->face.udp.local_addr.un.ip4, IPV4_ADDR_LEN);
          memcpy(output[j].face.remote_addr.v4.as_u8, reply->face.udp.remote_addr.un.ip4, IPV4_ADDR_LEN);
        }
        else
        {
          memcpy(output[j].face.local_addr.v6.as_u8, reply->face.udp.local_addr.un.ip6, IPV6_ADDR_LEN);
          memcpy(output[j].face.remote_addr.v6.as_u8, reply->face.udp.remote_addr.un.ip6, IPV6_ADDR_LEN);
        }
        output[j].face.local_port = reply->face.udp.lport;
        output[j].face.remote_port = reply->face.udp.rport;
        output[j].face.type = FACE_TYPE_UDP;
        output[j].id = reply->faceid;
        output[j].face.netdevice.index = reply->face.udp.swif;
        memcpy(output[j].face.netdevice.name, reply->face.udp.if_name, IFNAMSIZ);
        break;
      }
      default:
        retval = -1;
    }
    if (!retval)
      cur++;
  }
  
  free(request->data->buffer);
  request->data->buffer = (void *)output;
  request->data->size = request->data->current;
  request->data->out_element_size = sizeof(hc_face_t);
  return retval;
}

int hc_face_list(hc_sock_t *s, hc_data_t **pdata) {
  hc_msg_s *msg = malloc(sizeof(hc_msg_s));
  vapi_msg_hicn_api_faces_dump *hicnp_msg;
  hicnp_msg = vapi_alloc_hicn_api_faces_dump(s->g_vapi_ctx_instance);
  msg->hicnp_msg = (hc_hicnp_t *)hicnp_msg;
  msg->callback = &vapi_cb;
  msg->callback_ctx = malloc(sizeof(callback_ctx_t));
  msg->callback_ctx->s = s;
  msg->ntoh = (NTOH)&vapi_msg_hicn_api_faces_dump_hton;

  hc_command_params_t params = {
      .cmd = ACTION_LIST,
      .cmd_id = LIST_CONNECTIONS,
      .size_in = sizeof(vapi_msg_hicn_api_faces_details),
      .size_out = sizeof(hc_face_t),
      .parse = (HC_PARSE)parse_face_list,
  };

  return hc_execute_command(s, (hc_msg_t *)msg, sizeof(msg), &params, (hc_data_t**)pdata,
                            false);
  }

int hc_connection_parse_to_face(void *in, hc_face_t *face) { return 0; }

int hc_face_list_async(hc_sock_t *s)  //, hc_data_t ** pdata)
{
  return 0;
}

/* /!\ Please update constants in header file upon changes */
int hc_face_snprintf(char *s, size_t size, hc_face_t *face) { return 0; }

int hc_face_set_admin_state(
    hc_sock_t *s, const char *conn_id_or_name,  // XXX wrong identifier
    face_state_t admin_state) {
  return 0;
}

/*----------------------------------------------------------------------------*
 * Punting
 *----------------------------------------------------------------------------*/

int _hc_punting_create(hc_sock_t *s, hc_punting_t *punting, bool async) {
  return 0;
}

int hc_punting_create(hc_sock_t *s, hc_punting_t *punting) {
  return _hc_punting_create(s, punting, false);
}

int hc_punting_create_async(hc_sock_t *s, hc_punting_t *punting) {
  return _hc_punting_create(s, punting, true);
}

int hc_punting_get(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found) {
  ERROR("hc_punting_get not (yet) implemented.");
  return -1;
}

int hc_punting_delete(hc_sock_t *s, hc_punting_t *punting) {
  ERROR("hc_punting_delete not (yet) implemented.");
  return -1;
}

int hc_punting_list(hc_sock_t *s, hc_data_t **pdata) {
  ERROR("hc_punting_list not (yet) implemented.");
  return -1;
}

int hc_punting_validate(const hc_punting_t *punting) {
  if (!IS_VALID_FAMILY(punting->family)) return -1;

  /*
   * We might use the zero value to add punting on all faces but this is not
   * (yet) implemented
   */
  if (punting->face_id == 0) {
    ERROR("Punting on all faces is not (yet) implemented.");
    return -1;
  }

  return 0;
}

int hc_punting_cmp(const hc_punting_t *p1, const hc_punting_t *p2) {
  return ((p1->face_id == p2->face_id) && (p1->family == p2->family) &&
          (ip_address_cmp(&p1->prefix, &p2->prefix, p1->family) == 0) &&
          (p1->prefix_len == p2->prefix_len))
             ? 0
             : -1;
}

int hc_punting_parse(void *in, hc_punting_t *punting) {
  ERROR("hc_punting_parse not (yet) implemented.");
  return -1;
}

int hc_punting_snprintf(char *s, size_t size, hc_punting_t *punting) {
  ERROR("hc_punting_snprintf not (yet) implemented.");
  return -1;
}

/*----------------------------------------------------------------------------*
 * Cache
 *----------------------------------------------------------------------------*/

int _hc_cache_set_store(hc_sock_t *s, int enabled, bool async) {
  return 0;
}

int hc_cache_set_store(hc_sock_t *s, int enabled) {
  return _hc_cache_set_store(s, enabled, false);
}

int hc_cache_set_store_async(hc_sock_t *s, int enabled) {
  return _hc_cache_set_store(s, enabled, true);
}

int _hc_cache_set_serve(hc_sock_t *s, int enabled, bool async) {
  return 0;
}

int hc_cache_set_serve(hc_sock_t *s, int enabled) {
  return _hc_cache_set_serve(s, enabled, false);
}

int hc_cache_set_serve_async(hc_sock_t *s, int enabled) {
  return _hc_cache_set_serve(s, enabled, true);
}

/*----------------------------------------------------------------------------*
 * Strategy
 *----------------------------------------------------------------------------*/

// per prefix
int hc_strategy_set(hc_sock_t *s /* XXX */) { return 0; }

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

int hc_strategy_list(hc_sock_t *s, hc_data_t **data) {
  return 0;
}

/* /!\ Please update constants in header file upon changes */
int hc_strategy_snprintf(char *s, size_t size, hc_strategy_t *strategy) {
  return snprintf(s, size, "%s", strategy->name);
}

/*----------------------------------------------------------------------------*
 * WLDR
 *----------------------------------------------------------------------------*/

// per connection
int hc_wldr_set(hc_sock_t *s /* XXX */) { return 0; }

/*----------------------------------------------------------------------------*
 * MAP-Me
 *----------------------------------------------------------------------------*/

int hc_mapme_set(hc_sock_t *s, int enabled) { return 0; }

int hc_mapme_set_discovery(hc_sock_t *s, int enabled) { return 0; }

int hc_mapme_set_timescale(hc_sock_t *s, double timescale) { return 0; }

int hc_mapme_set_retx(hc_sock_t *s, double timescale) { return 0; }

/* Useless function defined to prevent undefined reference */
hc_connection_type_t
connection_type_from_str(const char * str)
{
    if (strcasecmp(str, "TCP") == 0)
        return CONNECTION_TYPE_TCP;
    else if (strcasecmp(str, "UDP") == 0)
        return CONNECTION_TYPE_UDP;
    else if (strcasecmp(str, "HICN") == 0)
        return CONNECTION_TYPE_HICN;
    else
	return CONNECTION_TYPE_UNDEFINED;
}

/*********************** Missing Symbol in vpp libraries *************************/
u8 *
format_vl_api_address_union (u8 * s, va_list * args)
{
  return NULL;
}
