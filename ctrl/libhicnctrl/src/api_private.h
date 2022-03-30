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

#ifndef HICN_API_PRIVATE_H
#define HICN_API_PRIVATE_H

#include <hicn/ctrl/api.h>
#include <hicn/util/token.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>
#include <hicn/util/sstrncpy.h>
#include <hicn/validation.h>
#include <ctype.h>

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

/*
 * Input validation
 */

static inline bool IS_VALID_ADDRESS(const ip_address_t *addr, int family) {
  char addr_str[INET6_ADDRSTRLEN];
  return !ip_address_empty(addr) &&
         ip_address_ntop(addr, addr_str, INET6_ADDRSTRLEN, family) >= 0;
}

static inline bool IS_VALID_PREFIX_LEN(u8 len) {
  return len <= MAX_IPV6_PREFIX_LEN;
}

// https://github.com/shemminger/iproute2/blob/50b668bdbf0ebc270495eb4b352d0c3982159d0a/lib/utils.c#L825
static inline bool IS_VALID_INTERFACE_NAME(const char *name) {
  size_t len = strnlen_s(name, INTERFACE_LEN);
  if (len == 0 || len >= IFNAMSIZ) return true;

  while (*name) {
    if (*name == '/' || isspace(*name)) return false;
    ++name;
  }

  return true;
}

static inline bool IS_VALID_NAME(const char *name) {
  return is_symbolic_name(name, SYMBOLIC_NAME_LEN);
}

static inline bool IS_VALID_STR_ID(const char *name) {
  return is_number(name, SYMBOLIC_NAME_LEN);
}

#define IS_VALID_TYPE(x) IS_VALID_ENUM_TYPE(FACE_TYPE, x)
#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

#define IS_VALID_ID(x) (1)
#define IS_VALID_POLICY(x) (1)

typedef struct hc_sock_impl_s hc_sock_impl_t;

int hc_data_ensure_available(hc_data_t *data, size_t count);
u8 *hc_data_get_next(hc_data_t *data);
int hc_data_set_error(hc_data_t *data);

int hc_listener_to_face(const hc_listener_t *listener, hc_face_t *face);

int hc_connection_to_face(const hc_connection_t *connection, hc_face_t *face);

int hc_face_to_listener(const hc_face_t *face, hc_listener_t *listener);

int hc_connection_to_local_listener(const hc_connection_t *connection,
                                    hc_listener_t *listener);

int hc_face_to_connection(const hc_face_t *face, hc_connection_t *connection,
                          bool generate_name);

struct hc_sock_s {
  int (*hc_sock_get_next_seq)(hc_sock_t *s);
  int (*hc_sock_set_nonblocking)(hc_sock_t *s);
  int (*hc_sock_get_fd)(hc_sock_t *s);
  int (*hc_sock_connect)(hc_sock_t *s);
  int (*hc_sock_get_available)(hc_sock_t *s, u8 **buffer, size_t *size);
  int (*hc_sock_send)(hc_sock_t *s, hc_msg_t *msg, size_t msglen, uint32_t seq);
  int (*hc_sock_recv)(hc_sock_t *s);
  int (*hc_sock_process)(hc_sock_t *s, hc_data_t **data);
  int (*hc_sock_callback)(hc_sock_t *s, hc_data_t **data);
  int (*hc_sock_reset)(hc_sock_t *s);
  void (*hc_sock_free)(hc_sock_t *s);
  void (*hc_sock_increment_woff)(hc_sock_t *s, size_t bytes);
  int (*hc_sock_prepare_send)(hc_sock_t *s, hc_result_t *result,
                              data_callback_t complete_cb,
                              void *complete_cb_data);
  int (*hc_sock_set_recv_timeout_ms)(hc_sock_t *s, long timeout_ms);
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
  int (*hc_connection_cmp)(const hc_connection_t *c1,
                           const hc_connection_t *c2);
  int (*hc_connection_parse)(void *in, hc_connection_t *connection);
  int (*hc_connection_set_admin_state)(hc_sock_t *s,
                                       const char *conn_id_or_name,
                                       face_state_t state);
  int (*hc_connection_set_admin_state_async)(hc_sock_t *s,
                                             const char *conn_id_or_name,
                                             face_state_t state);

#ifdef WITH_POLICY
  int (*hc_connection_set_priority)(hc_sock_t *s, const char *conn_id_or_name,
                                    uint32_t priority);
  int (*hc_connection_set_priority_async)(hc_sock_t *s,
                                          const char *conn_id_or_name,
                                          uint32_t priority);
  int (*hc_connection_set_tags)(hc_sock_t *s, const char *conn_id_or_name,
                                policy_tags_t tags);
  int (*hc_connection_set_tags_async)(hc_sock_t *s, const char *conn_id_or_name,
                                      policy_tags_t tags);
#endif  // WITH_POLICY

  int (*hc_connection_snprintf)(char *s, size_t size,
                                const hc_connection_t *connection);

  int (*hc_face_create)(hc_sock_t *s, hc_face_t *face);
  int (*hc_face_get)(hc_sock_t *s, hc_face_t *face, hc_face_t **face_found);
  int (*hc_face_delete)(hc_sock_t *s, hc_face_t *face, uint8_t delete_listener);
  int (*hc_face_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_face_list_async)(hc_sock_t *s);
  int (*hc_face_set_admin_state)(hc_sock_t *s, const char *conn_id_or_name,
                                 face_state_t state);
  int (*hc_face_set_admin_state_async)(hc_sock_t *s,
                                       const char *conn_id_or_name,
                                       face_state_t state);

#ifdef WITH_POLICY
  int (*hc_face_set_priority)(hc_sock_t *s, const char *conn_id_or_name,
                              uint32_t priority);
  int (*hc_face_set_priority_async)(hc_sock_t *s, const char *conn_id_or_name,
                                    uint32_t priority);
  int (*hc_face_set_tags)(hc_sock_t *s, const char *conn_id_or_name,
                          policy_tags_t tags);
  int (*hc_face_set_tags_async)(hc_sock_t *s, const char *conn_id_or_name,
                                policy_tags_t tags);
#endif  // WITH_POLICY

  int (*hc_face_snprintf)(char *s, size_t size, hc_face_t *face);

  int (*hc_route_parse)(void *in, hc_route_t *route);
  int (*hc_route_create)(hc_sock_t *s, hc_route_t *route);
  int (*hc_route_create_async)(hc_sock_t *s, hc_route_t *route);
  int (*hc_route_delete)(hc_sock_t *s, hc_route_t *route);
  int (*hc_route_delete_async)(hc_sock_t *s, hc_route_t *route);
  int (*hc_route_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_route_list_async)(hc_sock_t *s);

  int (*hc_punting_create)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_create_async)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_get)(hc_sock_t *s, hc_punting_t *punting,
                        hc_punting_t **punting_found);
  int (*hc_punting_delete)(hc_sock_t *s, hc_punting_t *punting);
  int (*hc_punting_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_punting_validate)(const hc_punting_t *punting);
  int (*hc_punting_cmp)(const hc_punting_t *c1, const hc_punting_t *c2);
  int (*hc_punting_parse)(void *in, hc_punting_t *punting);

  int (*hc_cache_parse)(void *in, hc_cache_info_t *cache_info);
  int (*hc_cache_set_store)(hc_sock_t *s, hc_cache_t *cache);
  int (*hc_cache_set_serve)(hc_sock_t *s, hc_cache_t *cache);
  int (*hc_cache_clear)(hc_sock_t *s, hc_cache_t *cache);
  int (*hc_cache_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_cache_set_store_async)(hc_sock_t *s, hc_cache_t *cache);
  int (*hc_cache_set_serve_async)(hc_sock_t *s, hc_cache_t *cache);
  int (*hc_cache_snprintf)(char *s, size_t size,
                           const hc_cache_info_t *cache_info);

  int (*hc_strategy_list)(hc_sock_t *s, hc_data_t **data);
  int (*hc_strategy_snprintf)(char *s, size_t size, hc_strategy_t *strategy);
  int (*hc_strategy_set)(hc_sock_t *s, hc_strategy_t *strategy);
  int (*hc_strategy_add_local_prefix)(hc_sock_t *s, hc_strategy_t *strategy);

  int (*hc_wldr_set)(hc_sock_t *s /* XXX */);

  int (*hc_mapme_set)(hc_sock_t *s, int enabled);
  int (*hc_mapme_set_discovery)(hc_sock_t *s, int enabled);
  int (*hc_mapme_set_timescale)(hc_sock_t *s, uint32_t timescale);
  int (*hc_mapme_set_retx)(hc_sock_t *s, uint32_t timescale);
  int (*hc_mapme_send_update)(hc_sock_t *s, hc_mapme_t *mapme);

#ifdef WITH_POLICY
  int (*hc_policy_parse)(void *in, hc_policy_t *policy);
  int (*hc_policy_create)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_create_async)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_delete)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_delete_async)(hc_sock_t *s, hc_policy_t *policy);
  int (*hc_policy_list)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_policy_list_async)(hc_sock_t *s, hc_data_t **pdata);
  int (*hc_policy_snprintf)(char *s, size_t size, hc_policy_t *policy);
#endif  // WITH_POLICY

  int (*hc_subscription_create)(hc_sock_t *s, hc_subscription_t *subscription);
  int (*hc_subscription_delete)(hc_sock_t *s, hc_subscription_t *subscription);

  hc_result_t *(*hc_listener_create_conf)(hc_sock_t *s,
                                          hc_listener_t *listener);
  hc_result_t *(*hc_listener_list_conf)(hc_sock_t *s, hc_data_t **pdata);
  hc_result_t *(*hc_connection_create_conf)(hc_sock_t *s,
                                            hc_connection_t *connection);
  hc_result_t *(*hc_connection_delete_conf)(hc_sock_t *s,
                                            hc_connection_t *connection);
  hc_result_t *(*hc_route_create_conf)(hc_sock_t *s, hc_route_t *route);
  hc_result_t *(*hc_strategy_set_conf)(hc_sock_t *s, hc_strategy_t *strategy);
  hc_result_t *(*hc_strategy_add_local_prefix_conf)(hc_sock_t *s,
                                                    hc_strategy_t *strategy);
  hc_result_t *(*hc_subscription_create_conf)(hc_sock_t *s,
                                              hc_subscription_t *subscription);
  hc_result_t *(*hc_subscription_delete_conf)(hc_sock_t *s,
                                              hc_subscription_t *subscription);

  hc_msg_t *(*hc_result_get_msg)(hc_result_t *result);
  bool (*hc_result_get_success)(hc_result_t *result);
  int (*hc_result_get_cmd_id)(hc_result_t *result);
  void (*hc_result_free)(hc_result_t *result);

  // Reference to module containing the implementation
  void *handle;
};

#endif  // HICN_API_PRIVATE_H
