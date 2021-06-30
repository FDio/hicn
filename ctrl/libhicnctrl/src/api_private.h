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

#ifndef HICN_API_PRIVATE_H
#define HICN_API_PRIVATE_H

#include <hicn/ctrl/api.h>
#include <hicn/ctrl/commands.h>
#include <hicn/util/token.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>

#define INT_CMP(x, y) ((x > y) ? 1 : (x < y) ? -1 : 0)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

#if 0
#ifdef __APPLE__
#define RANDBYTE() (u8)(arc4random() & 0xFF)
#else
#define RANDBYTE() (u8)(random() & 0xFF)
#endif
#endif
#define RANDBYTE() (u8)(rand() & 0xFF)

hc_connection_type_t
connection_type_from_str(const char * str);

extern const hc_connection_type_t map_from_list_connections_type[];
extern const hc_connection_type_t map_from_encap_type[];
extern const connection_type map_to_connection_type[];
extern const listener_mode map_to_listener_mode[];
extern const hc_connection_state_t map_from_list_connections_state[];
extern const int map_from_addr_type[];
extern const address_type map_to_addr_type[];
extern const char * connection_state_str[];
extern const char * connection_type_str[];

typedef enum {
    ENCAP_TCP,
    ENCAP_UDP,
    ENCAP_ETHER,
    ENCAP_LOCAL,
    ENCAP_HICN
} EncapType;

#define connection_state_to_face_state(x) ((face_state_t)(x))
#define face_state_to_connection_state(x) ((hc_connection_state_t)(x))

#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

#define IS_VALID_CONNECTION_TYPE(x) IS_VALID_ENUM_TYPE(CONNECTION_TYPE, x)

typedef struct hc_sock_impl_s hc_sock_impl_t;

int hc_data_ensure_available(hc_data_t * data, size_t count);
u8 *hc_data_get_next(hc_data_t * data);
int hc_data_set_error(hc_data_t * data);

int
hc_connection_parse_to_face(void * in, hc_face_t * face);

int
hc_listener_to_face(const hc_listener_t * listener, hc_face_t * face);

int
hc_connection_to_face(const hc_connection_t * connection, hc_face_t * face);

int
hc_face_to_listener(const hc_face_t * face, hc_listener_t * listener);

int
hc_connection_to_local_listener(const hc_connection_t * connection, hc_listener_t * listener);

int
hc_face_to_connection(const hc_face_t * face, hc_connection_t * connection, bool generate_name);

struct hc_sock_s {
  int (*hc_sock_get_next_seq)(hc_sock_t *s);
  int (*hc_sock_set_nonblocking)(hc_sock_t *s);
  int (*hc_sock_get_fd)(hc_sock_t *s);
  int (*hc_sock_connect)(hc_sock_t *s);
  int (*hc_sock_get_available)(hc_sock_t *s, u8 **buffer, size_t *size);
  int (*hc_sock_send)(hc_sock_t *s, hc_msg_t *msg, size_t msglen, int seq);
  int (*hc_sock_recv)(hc_sock_t *s);
  int (*hc_sock_process)(hc_sock_t *s, hc_data_t **data);
  int (*hc_sock_callback)(hc_sock_t *s, hc_data_t **data);
  int (*hc_sock_reset)(hc_sock_t *s);
  void (*hc_sock_free)(hc_sock_t *s);

  int (*hc_listener_create)(hc_sock_t *s, hc_listener_t *listener);
  int (*hc_listener_create_async)(hc_sock_t *s, hc_listener_t *listener);
  int (*hc_listener_get)(hc_sock_t *s, hc_listener_t *listener,
                    hc_listener_t **listener_found);
  int (*hc_listener_delete)(hc_sock_t *s, hc_listener_t *listener);
  int (*hc_listener_delete_async)(hc_sock_t *s, hc_listener_t *listener);
  int (*hc_listener_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_listener_list_async)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_listener_validate)(const hc_listener_t *listener);
  int (*hc_listener_cmp)(const hc_listener_t *l1, const hc_listener_t *l2);
  int (*hc_listener_parse)(void *in, hc_listener_t *listener);

  int (*hc_connection_create)(hc_sock_t *s, hc_connection_t *connection);
  int (*hc_connection_create_async)(hc_sock_t *s, hc_connection_t *connection);
  int (*hc_connection_get)(hc_sock_t *s, hc_connection_t *connection,
                      hc_connection_t **connection_found);
  int (*hc_connection_update_by_id)(hc_sock_t *s, int hc_connection_id,
                               hc_connection_t *connection);
  int (*hc_connection_update)(hc_sock_t *s, hc_connection_t *connection_current,
                         hc_connection_t *connection_updated);
  int (*hc_connection_delete)(hc_sock_t *s, hc_connection_t *connection);
  int (*hc_connection_delete_async)(hc_sock_t *s, hc_connection_t *connection);
  int (*hc_connection_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_connection_list_async)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_connection_validate)(const hc_connection_t *connection);
  int (*hc_connection_cmp)(const hc_connection_t *c1, const hc_connection_t *c2);
  int (*hc_connection_parse)(void *in, hc_connection_t *connection);
  int (*hc_connection_set_admin_state)(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);
  int (*hc_connection_set_admin_state_async)(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);

#ifdef WITH_POLICY
  int (*hc_connection_set_priority)(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
  int (*hc_connection_set_priority_async)(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
  int (*hc_connection_set_tags)(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
  int (*hc_connection_set_tags_async)(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
#endif // WITH_POLICY

  int (*hc_connection_snprintf)(char *s, size_t size,
                             const hc_connection_t *connection);

  int (*hc_face_create)(hc_sock_t *s, hc_face_t *face);
  int (*hc_face_get)(hc_sock_t *s, hc_face_t *face, hc_face_t **face_found);
  int (*hc_face_delete)(hc_sock_t *s, hc_face_t *face);
  int (*hc_face_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_face_list_async)(hc_sock_t *s);
  int (*hc_face_set_admin_state)(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);
  int (*hc_face_set_admin_state_async)(hc_sock_t * s, const char * conn_id_or_name, face_state_t state);

#ifdef WITH_POLICY
  int (*hc_face_set_priority)(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
  int (*hc_face_set_priority_async)(hc_sock_t * s, const char * conn_id_or_name, uint32_t priority);
  int (*hc_face_set_tags)(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
  int (*hc_face_set_tags_async)(hc_sock_t * s, const char * conn_id_or_name, policy_tags_t tags);
#endif // WITH_POLICY

  int (*hc_face_snprintf)(char *s, size_t size, hc_face_t *face);

  int (*hc_route_parse)(void *in, hc_route_t *route);
  int (*hc_route_create)(hc_sock_t * s, hc_route_t * route);
  int (*hc_route_create_async)(hc_sock_t * s, hc_route_t * route);
  int (*hc_route_delete)(hc_sock_t * s, hc_route_t * route);
  int (*hc_route_delete_async)(hc_sock_t * s, hc_route_t * route);
  int (*hc_route_list)(hc_sock_t * s, hc_data_t ** pdata);
  int (*hc_route_list_async)(hc_sock_t * s);

  int (*hc_punting_create)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_create_async)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_get)(hc_sock_t *s, hc_punting_t *punting,
                   hc_punting_t **punting_found);
  int (*hc_punting_delete)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_punting_validate)(const hc_punting_t *punting);
  int (*hc_punting_cmp)(const hc_punting_t *c1, const hc_punting_t *c2);
  int (*hc_punting_parse)(void *in, hc_punting_t *punting);

  int (*hc_cache_set_store)(hc_sock_t *s, int enabled);
  int (*hc_cache_set_serve)(hc_sock_t *s, int enabled);
  int (*hc_cache_set_store_async)(hc_sock_t *s, int enabled);
  int (*hc_cache_set_serve_async)(hc_sock_t *s, int enabled);

  int (*hc_strategy_list)(hc_sock_t *s, hc_data_t **data);
  int (*hc_strategy_snprintf)(char *s, size_t size, hc_strategy_t *strategy);
  int (*hc_strategy_set)(hc_sock_t *s /* XXX */);

  int (*hc_wldr_set)(hc_sock_t *s /* XXX */);

  int (*hc_mapme_set)(hc_sock_t *s, int enabled);
  int (*hc_mapme_set_discovery)(hc_sock_t *s, int enabled);
  int (*hc_mapme_set_timescale)(hc_sock_t *s, double timescale);
  int (*hc_mapme_set_retx)(hc_sock_t *s, double timescale);

#ifdef WITH_POLICY
  int (*hc_policy_parse)(void *in, hc_policy_t *policy);
  int (*hc_policy_create)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_create_async)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_delete)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_delete_async)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_policy_list_async)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_policy_snprintf)(char *s, size_t size, hc_policy_t *policy);
#endif // WITH_POLICY

  // Reference to module containing the implementation
  void *handle;
};

#endif // HICN_API_PRIVATE_H