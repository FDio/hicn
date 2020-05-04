/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
#include <vapi/vapi_safe.h>

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/commands.h>
#include <hicn/util/token.h>
#include <strings.h>
#include <vapi/hicn.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/udp.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <hicn/error.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip46_address.h>

#define APP_NAME "hicn_plugin"
#define MAX_OUTSTANDING_REQUESTS 4
#define RESPONSE_QUEUE_SIZE 2

DEFINE_VAPI_MSG_IDS_HICN_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON
DEFINE_VAPI_MSG_IDS_UDP_API_JSON

typedef struct {
  vapi_ctx_t g_vapi_ctx_instance;
  bool async;
} vapi_skc_ctx_t;

vapi_skc_ctx_t vapi_skc = {
  .g_vapi_ctx_instance = NULL,
  .async = false,
};

/**
 * Messages to the forwarder might be multiplexed thanks to the seqNum fields in
 * the header_control_message structure. The forwarder simply answers back the
 * original sequence number. We maintain a map of such sequence number to
 * outgoing queries so that replied can be demultiplexed and treated
 * appropriately.
 */
/* TYPEDEF_MAP_H(hc_sock_map, int, hc_sock_request_t *); */
/* TYPEDEF_MAP(hc_sock_map, int, hc_sock_request_t *, int_cmp, int_snprintf, */
/*             generic_snprintf); */

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
};


/******************************************************************************
 * Message helper types and aliases
 ******************************************************************************/

#define foreach_hc_command             \
  _(hicn_api_node_params_set)          \
  _(hicn_api_node_params_set_reply)    \
  _(hicn_api_node_params_get_reply)    \
  _(hicn_api_node_stats_get_reply)     \
  _(hicn_api_face_get)                 \
  _(hicn_api_faces_details)            \
  _(hicn_api_face_stats_details)       \
  _(hicn_api_face_get_reply)           \
  _(hicn_api_route_get)                \
  _(hicn_api_route_get_reply)          \
  _(hicn_api_routes_details)           \
  _(hicn_api_strategies_get_reply)     \
  _(hicn_api_strategy_get)             \
  _(hicn_api_strategy_get_reply)


typedef vapi_type_msg_header2_t hc_msg_header_t;

typedef union {
#define _(a) vapi_payload_ ## a a;
  foreach_hc_command
#undef _
} hc_msg_payload_t;

typedef struct __attribute__ ((__packed__)) {
  hc_msg_header_t hdr;
  hc_msg_payload_t payload;
} hc_hicnp_t;

typedef void (* NTOH)(void *msg);

typedef struct __attribute__((__packed__)) {
  hc_data_t *data;
  uint32_t curr_msg;
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

  if (!s) goto ERR_SOCK;

  memset(s, 0, sizeof(hc_sock_t));

  //By default the socket is blocking -- not async
  s->async = 0;

  return s;

ERR_SOCK:
  return NULL;
}

void hc_sock_free(hc_sock_t *s) {
  if (s->url) free(s->url);
  close(s->fd);
  free(s);

  vapi_disconnect_safe();
  vapi_skc.g_vapi_ctx_instance = NULL;
}

int hc_sock_get_next_seq(hc_sock_t *s) {
  return vapi_gen_req_context(s->g_vapi_ctx_instance);
}

int hc_sock_set_nonblocking(hc_sock_t *s) {
  s->async = 1;
  return 0;
}

int hc_sock_get_fd(hc_sock_t *s) { return 1; }

int hc_sock_connect(hc_sock_t *s) {

  vapi_error_e rv = vapi_connect_safe(&s->g_vapi_ctx_instance, s->async);
  if (rv != VAPI_OK)
    goto ERR_CONNECT;

  return 0;

ERR_CONNECT:
  ERROR("[hc_sock_connect] connection failed");
  return -1;
}

int hc_sock_send(hc_sock_t *s, hc_msg_t *msg, size_t msglen, int seq) {
  return -1;
}

int hc_sock_get_available(hc_sock_t *s, u8 **buffer, size_t *size) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_sock_recv(hc_sock_t *s) {
  // NOT IMPLEMENTED
  return -1;
}

int hc_sock_process(hc_sock_t *s, hc_data_t **pdata) {
  //NOT IMPLEMENTED
  return -1;
}

/******************************************************************************
 * Command-specific structures and functions
 ******************************************************************************/


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
    data->buffer = realloc(data->buffer, sizeof(hc_listener_t) * data->size * 2);

    if (!data->buffer)
      return VAPI_ENOMEM;

    data->size *=2;
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

typedef struct {
  u32 swif;
  char interface_name[INTERFACE_LEN];
} hc_vapi_interface_t;

vapi_error_e listener_list_complete_cb (struct vapi_ctx_s *ctx,
					void *callback_ctx,
					vapi_error_e rv,
					bool is_last,
				        vapi_payload_sw_interface_details *reply) {

  if (reply == NULL || rv != VAPI_OK)
    return rv;

  if (is_last)
    return 0;

  hc_data_t *data = (hc_data_t *)callback_ctx;

  if (data->size == data->current) {
    data->buffer = realloc(data->buffer, sizeof(hc_vapi_interface_t) * data->size * 2);

    if (!data->buffer)
      return VAPI_ENOMEM;

    data->size *=2;
  }

  hc_vapi_interface_t *swif = &((hc_vapi_interface_t*)data->buffer)[data->current];

  swif[0].swif = reply->sw_if_index;
  memcpy(swif[0].interface_name, reply->interface_name, INTERFACE_LEN);

  data->current++;

  return rv;
}


/* LISTENER LIST */
int hc_listener_list(hc_sock_t *s, hc_data_t **pdata) {
  int retval = VAPI_OK;
  vapi_lock();
  vapi_msg_sw_interface_dump *hicnp_msg;
  hicnp_msg = vapi_alloc_sw_interface_dump(s->g_vapi_ctx_instance);

  if (!hicnp_msg) {
    retval = VAPI_ENOMEM;
    goto END;
  }

  hicnp_msg->payload.sw_if_index = ~0;
  hicnp_msg->payload.name_filter_valid = 0;

  hc_data_t *data = hc_data_create(0, sizeof(hc_vapi_interface_t),NULL);

  if (!data) {
    retval = -1;
    goto END;
  }

  hc_data_t *data2 = hc_data_create(0, 1,NULL);

  if (!data2) {
    retval = -1;
    goto END;
  }

  data->buffer = malloc(sizeof(hc_vapi_interface_t));
  data->size = 1;

  if (!data->buffer) {
    free (data);
    retval = -1;
    goto FREE_DATA;
  }

  int ret = vapi_sw_interface_dump(s->g_vapi_ctx_instance, hicnp_msg, listener_list_complete_cb, data);

  if (ret != VAPI_OK) {
    free(data->buffer);
    free(data);
    retval = -1;
    goto FREE_DATA_BUFFER;
  }

  data2->buffer = malloc(sizeof(hc_listener_t));
  data2->size = 1;
  data2->out_element_size = 1;

  if (!data2->buffer) {
    free (data2->buffer);
    retval =1 -1;
    goto CLEAN;
  }

  /* Query the forwarder for each interface */
  for(int i = 0; i < data->current; i++) {
    int index = data2->current;
    vapi_msg_ip_address_dump* msg = vapi_alloc_ip_address_dump(s->g_vapi_ctx_instance);
    msg->payload.sw_if_index = ((hc_vapi_interface_t *)data->buffer)[i].swif;
    msg->payload.is_ipv6 = 0;
    retval = vapi_ip_address_dump(s->g_vapi_ctx_instance, msg, process_ip_info, data2);
    vapi_msg_ip_address_dump* msg2 = vapi_alloc_ip_address_dump(s->g_vapi_ctx_instance);

    if (retval) goto CLEAN;

    msg2->payload.sw_if_index = ((hc_vapi_interface_t *)data->buffer)[i].swif;
    msg2->payload.is_ipv6 = 1;
    retval = vapi_ip_address_dump(s->g_vapi_ctx_instance, msg2, process_ip_info, data2);
    for (size_t j = index; j < data2->current; j++) {
      memcpy(((hc_listener_t *)(data2->buffer))[j].interface_name, ((hc_vapi_interface_t*)(data->buffer))[i].interface_name, INTERFACE_LEN);
    }

    if (retval) goto CLEAN;
  }

CLEAN:
FREE_DATA_BUFFER:
  free(data->buffer);
FREE_DATA:
  free(data);

  data2->size = data2->current;
  data2->out_element_size = sizeof(hc_listener_t);
  *pdata = data2;
 END:
  vapi_unlock();
  return retval;
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

vapi_error_e  create_udp_tunnel_cb( vapi_ctx_t ctx,
				void *callback_ctx,
				vapi_error_e rv,
				bool is_last,
				vapi_payload_hicn_api_udp_tunnel_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  if (reply->retval != VAPI_OK)
    return reply->retval;

  u32 * uei = (u32*) callback_ctx;
  *uei = reply->uei;

  return reply->retval;
}

/* ROUTE CREATE */
vapi_error_e parse_route_create( vapi_ctx_t ctx,
				void *callback_ctx,
				vapi_error_e rv,
				bool is_last,
				vapi_payload_ip_route_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  if (reply->retval != VAPI_OK)
    return reply->retval;

  return reply->retval;
}

vapi_error_e hicn_enable_cb( vapi_ctx_t ctx,
                              void *callback_ctx,
                              vapi_error_e rv,
                              bool is_last,
                              vapi_payload_hicn_api_enable_disable_reply *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  return reply->retval;
}

int _hc_route_create(hc_sock_t *s, hc_route_t *route, bool async) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  int ret;
  vapi_lock();

  vapi_msg_ip_route_add_del *hicnp_msg = vapi_alloc_ip_route_add_del(s->g_vapi_ctx_instance, 1);

  hicnp_msg->payload.is_add = 1;
  if (route->family == AF_INET) {
    memcpy(&hicnp_msg->payload.route.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
    hicnp_msg->payload.route.prefix.address.af = ADDRESS_IP4;
  }
  else {
    memcpy(&hicnp_msg->payload.route.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
    hicnp_msg->payload.route.prefix.address.af = ADDRESS_IP6;
  }

  hicnp_msg->payload.route.prefix.len = route->len;

  hicnp_msg->payload.route.paths[0].sw_if_index = ~0;
  hicnp_msg->payload.route.paths[0].table_id = 0;

  hc_face_t *face = &(route->face);
  switch (face->face.type) {
    case FACE_TYPE_HICN:
      {
        if (ip46_address_is_ip4((ip46_address_t *)(&(face->face.remote_addr)))) {
          memcpy(&(hicnp_msg->payload.route.paths[0].nh.address.ip4), &face->face.remote_addr.v4, sizeof(ip4_address_t));
          hicnp_msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
        }
        else{
          memcpy(&(hicnp_msg->payload.route.paths[0].nh.address.ip6), &face->face.remote_addr.v6, sizeof(ip6_address_t));
          hicnp_msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP6;
        }

        hicnp_msg->payload.route.paths[0].type = FIB_API_PATH_FLAG_NONE;
        hicnp_msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;

        break;
      }
    case FACE_TYPE_UDP:
      {
        vapi_msg_hicn_api_udp_tunnel_add_del *msg = NULL;
        u32 uei = ~0;

        if (ip46_address_is_ip4((ip46_address_t *)(&(face->face.remote_addr))) &&
            ip46_address_is_ip4((ip46_address_t *)(&(face->face.local_addr)))) {

          msg = vapi_alloc_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance);
          memcpy(msg->payload.src_addr.un.ip4, &face->face.local_addr.v4, sizeof(ip4_address_t));
          msg->payload.src_addr.af = ADDRESS_IP4;

          memcpy(msg->payload.dst_addr.un.ip4, &face->face.remote_addr.v4, sizeof(ip4_address_t));
          msg->payload.dst_addr.af = ADDRESS_IP4;

        } else if (!ip46_address_is_ip4((ip46_address_t *)(&(route->face.face.remote_addr))) &&
                  !ip46_address_is_ip4((ip46_address_t *)(&(route->face.face.local_addr)))) {

          msg = vapi_alloc_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance);
          memcpy(msg->payload.src_addr.un.ip6, &face->face.local_addr.v6, sizeof(ip6_address_t));
          msg->payload.src_addr.af = ADDRESS_IP4;

          memcpy(msg->payload.dst_addr.un.ip6, &face->face.remote_addr.v6, sizeof(ip6_address_t));
          msg->payload.dst_addr.af = ADDRESS_IP6;

        } else {
          //NOT IMPLEMENTED
          ret = -1;
          goto done;
        }

        msg->payload.src_port = face->face.local_port;
        msg->payload.dst_port = face->face.remote_port;
        msg->payload.is_add = 1;

        int ret = vapi_hicn_api_udp_tunnel_add_del(s->g_vapi_ctx_instance, msg, create_udp_tunnel_cb, &uei);

        if(ret) {
          vapi_msg_free(s->g_vapi_ctx_instance, hicnp_msg);
          goto done;
        }

        hicnp_msg->payload.route.paths[0].type = FIB_API_PATH_TYPE_UDP_ENCAP;
        hicnp_msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;
        hicnp_msg->payload.route.paths[0].nh.obj_id = uei;
        break;
      }
    default:
      ret = -1;
      goto done;
  }

  ret = vapi_ip_route_add_del(s->g_vapi_ctx_instance, hicnp_msg, parse_route_create, NULL);

  if (ret)
    goto done;

  vapi_msg_hicn_api_enable_disable *msg = vapi_alloc_hicn_api_enable_disable(s->g_vapi_ctx_instance);

  if (route->family == AF_INET) {
    memcpy(&msg->payload.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
    msg->payload.prefix.address.af = ADDRESS_IP4;
  }
  else {
    memcpy(&msg->payload.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
    msg->payload.prefix.address.af = ADDRESS_IP6;
  }

  msg->payload.prefix.len = route->len;
  msg->payload.enable_disable = 1;

  ret = vapi_hicn_api_enable_disable(s->g_vapi_ctx_instance, msg, hicn_enable_cb, NULL);
done:
  vapi_unlock();
  return ret;
}

int hc_route_create(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_create(s, route, false);
}

int hc_route_create_async(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_create(s, route, true);
}

/* ROUTE DELETE */
vapi_error_e parse_route_delete( vapi_ctx_t ctx,
				void *callback_ctx,
				vapi_error_e rv,
				bool is_last,
				vapi_payload_ip_route_add_del_reply *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  return reply->retval;
}

int _hc_route_delete(hc_sock_t *s, hc_route_t *route, bool async) {
  if (!IS_VALID_FAMILY(route->family)) return -1;

  vapi_lock();
  vapi_msg_ip_route_add_del *hicnp_msg = vapi_alloc_ip_route_add_del(s->g_vapi_ctx_instance, 1);

  hicnp_msg->payload.is_add = 0;
  if (route->family == AF_INET) {
    memcpy(&hicnp_msg->payload.route.prefix.address.un.ip4[0], &route->remote_addr.v4, 4);
    hicnp_msg->payload.route.prefix.address.af = ADDRESS_IP4;
  }
  else {
    memcpy(&hicnp_msg->payload.route.prefix.address.un.ip6[0], &route->remote_addr.v6, 16);
    hicnp_msg->payload.route.prefix.address.af = ADDRESS_IP6;
  }

  hicnp_msg->payload.route.prefix.len = route->len;

  hicnp_msg->payload.route.paths[0].sw_if_index = ~0;
  hicnp_msg->payload.route.paths[0].table_id = 0;

  hc_face_t *face = &(route->face);
  switch (face->face.type) {
    case FACE_TYPE_HICN:
      {
        if (ip46_address_is_ip4((ip46_address_t *)(&(face->face.remote_addr)))) {
          memcpy(&(hicnp_msg->payload.route.paths[0].nh.address.ip4), &face->face.remote_addr.v4, sizeof(ip4_address_t));
          hicnp_msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP4;
        }
        else{
          memcpy(&(hicnp_msg->payload.route.paths[0].nh.address.ip6), &face->face.remote_addr.v6, sizeof(ip6_address_t));
          hicnp_msg->payload.route.paths[0].proto = FIB_API_PATH_NH_PROTO_IP6;
        }

        hicnp_msg->payload.route.paths[0].type = FIB_API_PATH_FLAG_NONE;
        hicnp_msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;

        break;
      }
    case FACE_TYPE_UDP:
      {
        hicnp_msg->payload.route.paths[0].type = FIB_API_PATH_TYPE_UDP_ENCAP;
        hicnp_msg->payload.route.paths[0].flags = FIB_API_PATH_FLAG_NONE;
        hicnp_msg->payload.route.paths[0].nh.obj_id = face->face.netdevice.index;
        break;
      }
    default:
      return -1;
  }

  vapi_error_e ret = vapi_ip_route_add_del(s->g_vapi_ctx_instance, hicnp_msg, parse_route_delete, NULL);

  vapi_unlock();
  return ret;
}

int hc_route_delete(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_delete(s, route, false);
}

int hc_route_delete_async(hc_sock_t *s, hc_route_t *route) {
  return _hc_route_delete(s, route, true);
}

vapi_error_e parse_udp_encap_list( vapi_ctx_t ctx,
			      void *callback_ctx,
			      vapi_error_e rv,
			      bool is_last,
			      vapi_payload_udp_encap_details *reply) {
  if (reply == NULL || rv != VAPI_OK)
    return rv;

  hc_face_t * face = (hc_face_t *)callback_ctx;

  if (face->face.netdevice.index == reply->udp_encap.id)
  {
    switch(reply->udp_encap.src_ip.af) {
      case ADDRESS_IP4:
      {
        memcpy(&face->face.local_addr.v4, &(reply->udp_encap.src_ip.un.ip4), sizeof(ip4_address_t));
        memcpy(&face->face.remote_addr.v4, &(reply->udp_encap.dst_ip.un.ip4), sizeof(ip4_address_t));
        break;
      }
      case ADDRESS_IP6:
      {
        memcpy(&face->face.local_addr.v6, &(reply->udp_encap.src_ip.un.ip6), sizeof(ip6_address_t));
        memcpy(&face->face.remote_addr.v6, &(reply->udp_encap.dst_ip.un.ip6), sizeof(ip6_address_t));
        break;
      }
      default:
      break;
    }

    face->face.local_port = reply->udp_encap.src_port;
    face->face.remote_port = reply->udp_encap.dst_port;
  }
  return rv;
}

int fill_face_with_info(hc_face_t * face, vapi_type_fib_path *path, hc_sock_t *s) {
  switch(path->type){
    case FIB_API_PATH_FLAG_NONE:
    {
      face->face.type = FACE_TYPE_HICN;
      switch(path->proto){
        case FIB_API_PATH_NH_PROTO_IP4:
          memcpy(&face->face.remote_addr.v4, &(path->nh.address.ip4), sizeof(ip4_address_t));
        break;
        case FIB_API_PATH_NH_PROTO_IP6:
          memcpy(&face->face.remote_addr.v6, &(path->nh.address.ip6), sizeof(ip6_address_t));
        break;
        default:
        break;
      }
      face->face.netdevice.index = path->sw_if_index;
    }
    break;
    case FIB_API_PATH_TYPE_UDP_ENCAP:
    {
      face->face.type = FACE_TYPE_UDP;
      face->face.netdevice.index = clib_net_to_host_u32(path->nh.obj_id);
      //vapi_msg_udp_encap_dump *msg;
      //msg = vapi_alloc_udp_encap_dump(s->g_vapi_ctx_instance);
      //vapi_udp_encap_dump(s->g_vapi_ctx_instance, msg, parse_udp_encap_list, face);
    }
    break;
    default:
      return -1;
  }
  return 0;
}

/* ROUTE LIST */
typedef struct hicn_route_socket_s {
  hc_data_t *data;
  hc_sock_t *s;
} hicn_route_socket_t;

vapi_error_e parse_route_list( vapi_ctx_t ctx,
			      void *callback_ctx,
			      vapi_error_e rv,
			      bool is_last,
			      vapi_payload_ip_route_details *reply) {

  if (reply == NULL || rv != VAPI_OK)
    return rv;

  hicn_route_socket_t *rs = (hicn_route_socket_t *)callback_ctx;
  hc_data_t *data = rs->data;

  u8 found = false;
  for (int j = 0; j < reply->route.n_paths; j++){
    for (int i = 0; i < data->size && !found; i++) {
      hc_route_t * route = &((hc_route_t*)(data->buffer))[i];

      if(ip46_address_is_ip4((ip46_address_t *)&(route->remote_addr)) &&
        memcmp(route->remote_addr.v4.as_u8, reply->route.prefix.address.un.ip4, sizeof(ip4_address_t)) == 0 &&
        route->len == reply->route.prefix.len && route->face_id == ~0) {
          fill_face_with_info(&(route->face), &reply->route.paths[j], rs->s);
          found = true;
      } else if (memcmp(route->remote_addr.v6.as_u8, reply->route.prefix.address.un.ip6, sizeof(ip6_address_t)) == 0 &&
                route->len == reply->route.prefix.len && route->face_id == ~0) {
          fill_face_with_info(&(route->face), &reply->route.paths[j], rs->s);
          found = true;
      }
    }
  }

  return rv;
}

vapi_error_e parse_hicn_route_list( vapi_ctx_t ctx,
			      void *callback_ctx,
			      vapi_error_e rv,
			      bool is_last,
			      vapi_payload_hicn_api_routes_details *reply) {

  if (reply == NULL || rv != VAPI_OK)
    return rv;

  hc_data_t *data = (hc_data_t *)callback_ctx;

  int empty_spots = data->size - data->current;
  if (empty_spots < reply->nfaces) {
    int new_size = data->size + (reply->nfaces - empty_spots);
    data->buffer = realloc(data->buffer, sizeof(hc_route_t) * (new_size));
    if (!data->buffer)
      return VAPI_ENOMEM;

    data->size =new_size;
  }

  for (int i = 0; i < reply->nfaces; i++) {
    hc_route_t * route = &((hc_route_t*)(data->buffer))[data->current];
    route->face_id = ~0;
    route->cost = 1;
    route->len = reply->prefix.len;
    if (reply->prefix.address.af == ADDRESS_IP6)
      {
        memcpy(route->remote_addr.v6.as_u8, reply->prefix.address.un.ip6, 16);
      }
      else
      {
        memcpy(route->remote_addr.v4.as_u8, reply->prefix.address.un.ip4, 4);
      }
    route->family = reply->prefix.address.af == ADDRESS_IP6? AF_INET6 : AF_INET;
    data->current++;
  }

  return rv;
}

int _hc_route_list(hc_sock_t *s, hc_data_t **pdata, bool async) {
  vapi_lock();

  vapi_msg_hicn_api_routes_dump *msg;
  msg = vapi_alloc_hicn_api_routes_dump(s->g_vapi_ctx_instance);

  hc_data_t *data = hc_data_create(0, sizeof(hc_route_t),NULL);
  int ret = VAPI_OK;

  if (!data){
    ret = -1;
    goto err;
  }

  data->buffer = malloc(sizeof(hc_route_t));
  data->size = 1;

  if (!data->buffer) {
    ret = -1;
    goto err_free;
  }

  ret = vapi_hicn_api_routes_dump(s->g_vapi_ctx_instance, msg, parse_hicn_route_list, data);

  if (ret != VAPI_OK)
    goto err_free;

  vapi_msg_ip_route_dump *hicnp_msg;
  hicnp_msg = vapi_alloc_ip_route_dump(s->g_vapi_ctx_instance);
  hicnp_msg->payload.table.table_id = 0;
  hicnp_msg->payload.table.is_ip6 = 1;

  hicn_route_socket_t ctx = {
    .data = data,
    .s = s,
  };

  ret = vapi_ip_route_dump(s->g_vapi_ctx_instance, hicnp_msg, parse_route_list, &ctx);

  hicnp_msg = vapi_alloc_ip_route_dump(s->g_vapi_ctx_instance);
  hicnp_msg->payload.table.table_id = 0;
  hicnp_msg->payload.table.is_ip6 = 0;

  ret = vapi_ip_route_dump(s->g_vapi_ctx_instance, hicnp_msg, parse_route_list, &ctx);

  if (ret != VAPI_OK)
    goto err_free;

  *pdata = data;

  vapi_unlock();
  return ret;

 err_free:
  free(data);
 err:
  vapi_unlock();
  return ret;
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

int hc_face_create(hc_sock_t *s, hc_face_t *face) {
  ERROR("Face creation implemented.");
  return -1;
}

int hc_face_delete(hc_sock_t *s, hc_face_t *face) {

  ERROR("Face deletion not implemented.");
  return -1;
}

/* FACE LIST */

int hc_face_list(hc_sock_t *s, hc_data_t **pdata) {

ERROR("Face list not implemented.");
return -1;
}

int hc_connection_parse_to_face(void *in, hc_face_t *face) { return 0; }

int hc_face_list_async(hc_sock_t *s)
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
