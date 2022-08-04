/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

/*
 * @file commands.h
 * @brief All hicn-light commands: 14 in total.
 *
 * Header and payload in binary format.
 */

#ifndef HICN_CTRL_HICNLIGHTNG_H
#define HICN_CTRL_HICNLIGHTNG_H

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <stdint.h>
#include <stdlib.h>

#include <hicn/policy.h>
#include <hicn/strategy.h>
#include <hicn/util/ip_address.h>

#include "api.h"

#define SYMBOLIC_NAME_LEN 16

typedef struct in6_addr ipv6_addr_t;
typedef uint32_t ipv4_addr_t;

typedef enum {
  MESSAGE_COMMAND_SUBTYPE_UNDEFINED,
  REQUEST_LIGHT = 0xc0,  // this is a command
  RESPONSE_LIGHT,
  ACK_LIGHT,
  NACK_LIGHT,
  NOTIFICATION_LIGHT,
  MESSAGE_COMMAND_SUBTYPE_N
} message_command_subtype_t;

#define message_type_is_valid(message_type)    \
  ((message_type != MESSAGE_TYPE_UNDEFINED) && \
   (message_type != MESSAGE_COMMAND_SUBTYPE_N))

#define message_type_from_uchar(x)                               \
  (((x) < REQUEST_LIGHT) || (((x) >= MESSAGE_COMMAND_SUBTYPE_N)) \
       ? MESSAGE_COMMAND_SUBTYPE_N                               \
       : (message_command_subtype_t)(x))

#define foreach_command_type                              \
  _(listener_add, LISTENER_ADD)                           \
  _(listener_remove, LISTENER_REMOVE)                     \
  _(listener_list, LISTENER_LIST)                         \
  _(connection_add, CONNECTION_ADD)                       \
  _(connection_remove, CONNECTION_REMOVE)                 \
  _(connection_list, CONNECTION_LIST)                     \
  _(connection_update, CONNECTION_UPDATE)                 \
  _(route_add, ROUTE_ADD)                                 \
  _(route_remove, ROUTE_REMOVE)                           \
  _(route_list, ROUTE_LIST)                               \
  _(cache_set_store, CACHE_SET_STORE)                     \
  _(cache_set_serve, CACHE_SET_SERVE)                     \
  _(cache_clear, CACHE_CLEAR)                             \
  _(cache_list, CACHE_LIST)                               \
  _(strategy_set, STRATEGY_SET)                           \
  _(strategy_add_local_prefix, STRATEGY_ADD_LOCAL_PREFIX) \
  _(wldr_set, WLDR_SET)                                   \
  _(punting_add, PUNTING_ADD)                             \
  _(mapme_enable, MAPME_ENABLE)                           \
  _(mapme_set_discovery, MAPME_SET_DISCOVERY)             \
  _(mapme_set_timescale, MAPME_SET_TIMESCALE)             \
  _(mapme_set_retx, MAPME_SET_RETX)                       \
  _(mapme_send_update, MAPME_SEND_UPDATE)                 \
  _(policy_add, POLICY_ADD)                               \
  _(policy_remove, POLICY_REMOVE)                         \
  _(policy_list, POLICY_LIST)                             \
  _(active_interface_update, ACTIVE_INTERFACE_UPDATE)     \
  _(subscription_add, SUBSCRIPTION_ADD)                   \
  _(subscription_remove, SUBSCRIPTION_REMOVE)             \
  _(stats_get, STATS_GET)                                 \
  _(stats_list, STATS_LIST)

typedef enum {
  COMMAND_TYPE_UNDEFINED,
#define _(l, u) COMMAND_TYPE_##u,
  foreach_command_type
#undef _
      COMMAND_TYPE_N,
} command_type_t;

extern const char *command_type_str[];

#define command_type_str(x) command_type_str[x]

#define command_type_is_valid(command_type) \
  ((command_type != COMMAND_TYPE_UNDEFINED) && (command_type != COMMAND_TYPE_N))

#define command_type_from_uchar(x) \
  (((x) >= COMMAND_TYPE_N) ? COMMAND_TYPE_N : (command_type_t)(x))

/* Should be at least 8 bytes */
typedef struct {
  uint8_t message_type;
  uint8_t command_id;
  uint16_t length; /* Number of structures in the payload */
  uint32_t seq_num;
} cmd_header_t;

typedef struct {
  cmd_header_t header;
} msg_header_t;

/* Listener */

typedef struct {
  char symbolic[SYMBOLIC_NAME_LEN];
  char interface_name[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t address;
  uint16_t port;
  uint8_t family;
  uint8_t type;
} cmd_listener_add_t;

typedef struct {
  char symbolicOrListenerid[SYMBOLIC_NAME_LEN];
} cmd_listener_remove_t;

typedef struct {
  void *_;  // Otherwise empty structs result in clang build error
} cmd_listener_list_t;

/* Connection */

typedef struct {
  char symbolic[SYMBOLIC_NAME_LEN];
  // char interface_name[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t remote_ip;
  hicn_ip_address_t local_ip;
  uint16_t remote_port;
  uint16_t local_port;
  uint8_t family;
  uint8_t type;
  uint8_t admin_state;
  uint8_t __pad;
  uint32_t priority;
  policy_tags_t tags;
} cmd_connection_add_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
} cmd_connection_remove_t;

typedef struct {
  void *_;
} cmd_connection_list_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  uint8_t admin_state;
  uint8_t pad8[3];
} cmd_connection_set_admin_state_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  uint8_t admin_state;
  uint32_t priority;
  policy_tags_t tags;
} cmd_connection_update_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  uint32_t priority;
} cmd_connection_set_priority_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  policy_tags_t tags;
} cmd_connection_set_tags_t;

/* Route */

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t address;
  uint16_t cost;
  uint8_t family;
  uint8_t len;
} cmd_route_add_t;

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
} cmd_route_remove_t;

typedef struct {
  void *_;
} cmd_route_list_t;

/* Cache */

typedef struct {
  uint8_t activate;
} cmd_cache_set_store_t;

typedef struct {
  uint8_t activate;
} cmd_cache_set_serve_t;

typedef struct {
  void *_;
} cmd_cache_clear_t;

typedef struct {
  void *_;
} cmd_cache_list_t;

typedef struct {
  uint8_t store_in_cs;
  uint8_t serve_from_cs;
  uint32_t cs_size;
  uint32_t num_stale_entries;
} cmd_cache_list_reply_t;

typedef struct {
  cmd_header_t header;
  cmd_cache_list_reply_t payload;
} msg_cache_list_reply_t;

/* WLDR */

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  uint8_t activate;
} cmd_wldr_set_t;

/* Strategy */

typedef struct {
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
  uint8_t type;
  uint8_t related_prefixes;
  union {
    struct {
      hicn_ip_address_t addresses[MAX_FWD_STRATEGY_RELATED_PREFIXES];
      uint8_t lens[MAX_FWD_STRATEGY_RELATED_PREFIXES];
      uint8_t families[MAX_FWD_STRATEGY_RELATED_PREFIXES];
    } low_latency;
  };
} cmd_strategy_set_t;

typedef struct {
  uint8_t type;
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
  hicn_ip_address_t local_address;
  uint8_t local_family;
  uint8_t local_len;
} cmd_strategy_add_local_prefix_t;

/* Punting */

typedef struct {
  char symbolic_or_connid[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
} cmd_punting_add_t;

/* MAP-Me */

typedef struct {
  uint8_t activate;
} cmd_mapme_activator_t;

typedef cmd_mapme_activator_t cmd_mapme_enable_t;
typedef cmd_mapme_activator_t cmd_mapme_set_discovery_t;

typedef struct {
  uint32_t timePeriod;
} cmd_mapme_timing_t;

typedef cmd_mapme_timing_t cmd_mapme_set_timescale_t;
typedef cmd_mapme_timing_t cmd_mapme_set_retx_t;

typedef struct {
  void *_;
} cmd_mapme_send_update_t;

/* Policy */

typedef struct {
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
  hicn_policy_t policy;
} cmd_policy_add_t;

typedef struct {
  hicn_ip_address_t address;
  uint8_t family;
  uint8_t len;
} cmd_policy_remove_t;

typedef struct {
  void *_;
} cmd_policy_list_t;

/* Subscription */

typedef struct {
  uint32_t topics;
} cmd_subscription_add_t;

typedef struct {
  uint32_t topics;
} cmd_subscription_remove_t;

/* Statistics */

// General stats
typedef struct {
  void *_;
} cmd_stats_get_t;

// Per-face stats
typedef struct {
  void *_;
} cmd_stats_list_t;

typedef void *cmd_active_interface_update_t;

/* Full messages */

#define _(l, u)          \
  typedef struct {       \
    cmd_header_t header; \
    cmd_##l##_t payload; \
  } msg_##l##_t;
foreach_command_type
#undef _

    /* Serialized version of hc_listener_t */
    typedef struct {
  char name[SYMBOLIC_NAME_LEN];
  char interface_name[INTERFACE_LEN];
  hicn_ip_address_t local_addr;
  uint32_t id;
  uint16_t local_port;
  uint8_t type;
  uint8_t family;
} cmd_listener_list_item_t;

static_assert(sizeof(cmd_listener_list_item_t) == 56, "");

typedef struct {
  cmd_header_t header;
  cmd_listener_list_item_t payload;
} msg_listener_list_reply_t;

/* Serialized version of hc_connection_t */
typedef struct {
  char name[SYMBOLIC_NAME_LEN];
  char interface_name[INTERFACE_LEN];
  hicn_ip_address_t local_addr;
  hicn_ip_address_t remote_addr;
  uint32_t id;
  uint32_t priority;
  uint16_t local_port;
  uint16_t remote_port;
  uint8_t netdevice_type;
  uint8_t type;
  uint8_t family;
  uint8_t admin_state;
  uint8_t tags;
  uint8_t state;
  uint8_t __pad[6];
} cmd_connection_list_item_t;

static_assert(POLICY_TAG_N <= 8, "");
static_assert(sizeof(cmd_connection_list_item_t) == 88, "");

typedef struct {
  cmd_header_t header;
  cmd_connection_list_item_t payload;
} msg_connection_list_reply_t;

typedef msg_connection_list_reply_t msg_connection_notify_t;

typedef struct {
  char interface_name[INTERFACE_LEN];
  hicn_ip_address_t local_addr;
  hicn_ip_address_t remote_addr;
  uint32_t id;
  uint32_t priority;
  uint16_t local_port;
  uint16_t remote_port;
  uint8_t netdevice_type;
  uint8_t type;
  uint8_t family;
  uint8_t admin_state;
  uint8_t tags;
  uint8_t state;
  uint8_t __pad[6];
} cmd_face_list_item_t;

static_assert(sizeof(cmd_face_list_item_t) == 72, "");

typedef struct {
  char face_name[SYMBOLIC_NAME_LEN];
  hicn_ip_address_t remote_addr;
  uint32_t face_id;
  uint16_t cost;
  uint8_t family;
  uint8_t len;
  cmd_face_list_item_t face;
} cmd_route_list_item_t;

static_assert(sizeof(cmd_route_list_item_t) == 112, "");

typedef struct {
  cmd_header_t header;
  cmd_route_list_item_t payload;
} msg_route_list_reply_t;

typedef msg_route_list_reply_t msg_route_notify_t;

typedef struct {
  uint8_t state;
  uint8_t disabled;
  uint16_t __pad;
} _policy_tag_state_t;

typedef struct {
  uint32_t throughput;
  uint32_t latency;
  uint32_t loss_rate;
} _interface_stats_t;

typedef struct {
  _interface_stats_t wired;
  _interface_stats_t wifi;
  _interface_stats_t cellular;
  _interface_stats_t all;
} _policy_stats_t;

typedef struct {
  char app_name[APP_NAME_LEN];
  _policy_tag_state_t tags[POLICY_TAG_N];
  _policy_stats_t stats;
  uint8_t __pad[4];
} _hicn_policy_t;

static_assert(sizeof(_hicn_policy_t) == 208, "");

typedef struct {
  uint8_t policy[208];
  hicn_ip_address_t remote_addr;
  uint8_t family;
  uint8_t len;
  uint8_t __pad[6];
} cmd_policy_list_item_t;

static_assert(sizeof(cmd_policy_list_item_t) == 232, "");

typedef struct {
  cmd_header_t header;
  cmd_policy_list_item_t payload;
} msg_policy_list_reply_t;

typedef msg_policy_list_reply_t msg_policy_notify_t;

/* Those are needed to build but not used */
typedef struct {
  uint8_t _;
} cmd_strategy_list_item_t;
typedef struct {
  uint8_t _;
} cmd_subscription_list_item_t;

/* Statistics */

typedef struct {
  cmd_header_t header;
  hicn_light_stats_t payload;
} msg_stats_get_reply_t;

typedef struct {
  uint32_t id;
  connection_stats_t stats;
} cmd_stats_list_item_t;

typedef struct {
  cmd_header_t header;
  cmd_stats_list_item_t payload;
} msg_stats_list_reply_t;

//===== size of commands ======
// REMINDER: when a new_command is added, the following switch has to be
// updated.
static inline int command_get_payload_len(command_type_t command_type) {
  switch (command_type) {
#define _(l, u)          \
  case COMMAND_TYPE_##u: \
    return sizeof(cmd_##l##_t);
    foreach_command_type
#undef _
        case COMMAND_TYPE_UNDEFINED : case COMMAND_TYPE_N : return 0;
  }
}

ssize_t hc_light_command_serialize(hc_action_t action,
                                   hc_object_type_t object_type,
                                   hc_object_t *object, uint8_t *msg);

int hc_sock_initialize_module(hc_sock_t *s);

#endif /* HICN_CTRL_HICNLIGHTNG_H */
