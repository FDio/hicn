/*
   Copyright (c) 2017-2019 Cisco and/or its affiliates.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0
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

#ifndef commands_h
#define commands_h

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <stdint.h>
#include <stdlib.h>

#include <hicn/base/strategy.h> // to be moved in libhicn
#include <hicn/util/ip_address.h>
#ifdef WITH_POLICY
#include <hicn/policy.h>
#endif /* WITH_POLICY */

#define SYMBOLIC_NAME_LEN 16

typedef struct in6_addr ipv6_addr_t;
typedef uint32_t ipv4_addr_t;

typedef enum {
    MESSAGE_TYPE_UNDEFINED,
    REQUEST_LIGHT = 0xc0, // this is a command
    RESPONSE_LIGHT,
    ACK_LIGHT,
    NACK_LIGHT,
    MESSAGE_TYPE_N
} message_type_t;

#define message_type_is_valid(message_type) \
    ((message_type != MESSAGE_TYPE_UNDEFINED) && (message_type != MESSAGE_TYPE_N))

#define message_type_from_uchar(x) \
    (((x) < REQUEST_LIGHT) || (((x) >= MESSAGE_TYPE_N)) ? MESSAGE_TYPE_N : (message_type_t)(x))

typedef enum {
    COMMAND_TYPE_UNDEFINED,
    ADD_LISTENER = 0,
    ADD_CONNECTION,
    LIST_CONNECTIONS,
    ADD_ROUTE,
    LIST_ROUTES,
    REMOVE_CONNECTION,
    REMOVE_LISTENER,
    REMOVE_ROUTE,
    CACHE_STORE,
    CACHE_SERVE,
    CACHE_CLEAR,
    SET_STRATEGY,
    SET_WLDR,
    ADD_PUNTING,
    LIST_LISTENERS,
    MAPME_ENABLE,
    MAPME_DISCOVERY,
    MAPME_TIMESCALE,
    MAPME_RETX,
    MAPME_SEND_UPDATE,
    CONNECTION_SET_ADMIN_STATE,
#ifdef WITH_POLICY
    ADD_POLICY,
    LIST_POLICIES,
    REMOVE_POLICY,
    UPDATE_CONNECTION,
    CONNECTION_SET_PRIORITY,
    CONNECTION_SET_TAGS,
#endif /* WITH_POLICY */
    COMMAND_TYPE_N,
} command_type_t;

#define command_type_is_valid(command_type) \
    ((command_type != COMMAND_TYPE_UNDEFINED) && (command_type != COMMAND_TYPE_N))

#define command_type_from_uchar(x) \
    (((x) >= COMMAND_TYPE_N) ? COMMAND_TYPE_N : (command_type_t)(x))

typedef enum {
    UDP_CONN,
    TCP_CONN,
    GRE_CONN,  // not implemented
    HICN_CONN
} connection_type;

typedef enum { ACTIVATE_ON, ACTIVATE_OFF } activate_type;

//==========    HEADER    ==========

typedef struct {
    uint8_t messageType;
    uint8_t commandID;
    uint16_t length;  // tells the number of structures in the payload
    uint32_t seqNum;
} header_control_message;
// for the moment has to be at least 8 bytes

// SIZE=8

//==========  [00]  ADD LISTENER    ==========

typedef enum { ETHER_MODE, IP_MODE, HICN_MODE } listener_mode;

typedef struct {
    char symbolic[SYMBOLIC_NAME_LEN];
    char interfaceName[SYMBOLIC_NAME_LEN];
    ip_address_t address;
    uint16_t port;
    // uint16_t etherType;
    uint8_t family;
    uint8_t listenerMode;
    uint8_t connectionType;
} add_listener_command;

// SIZE=56

//==========  [01]  ADD CONNECTION    ==========

typedef struct {
    char symbolic[SYMBOLIC_NAME_LEN];
    //char interfaceName[SYMBOLIC_NAME_LEN];
    ip_address_t remoteIp;
    ip_address_t localIp;
    uint16_t remotePort;
    uint16_t localPort;
    uint8_t family;
    uint8_t connectionType;
    uint8_t admin_state;
#ifdef WITH_POLICY
    uint32_t priority;
    policy_tags_t tags;
#endif /* WITH_POLICY */
} add_connection_command;

// SIZE=56

//==========  [02]  LIST CONNECTIONS    ==========

#if 0
typedef enum {
    CONN_GRE,
    CONN_TCP,
    CONN_UDP,
    CONN_MULTICAST,
    CONN_L2,
    CONN_HICN
} list_connections_type;

typedef enum {
    IFACE_UP = 0,
    IFACE_DOWN = 1,
    IFACE_UNKNOWN = 2  // not used actually
} connection_state;
#endif

typedef struct {
    add_connection_command connectionData;
    uint32_t connid;
    uint8_t state;
    char interfaceName[SYMBOLIC_NAME_LEN];
    char connectionName[SYMBOLIC_NAME_LEN];
} list_connections_command;

// SIZE=80

//==========  [03]  ADD ROUTE    ==========

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    ip_address_t address;
    uint16_t cost;
    uint8_t family;
    uint8_t len;
} add_route_command;

// SIZE=36

//==========  [04]  LIST ROUTE    ==========

typedef struct {
    ip_address_t address;
    uint32_t connid;
    uint16_t cost;
    uint8_t family;
    uint8_t len;
} list_routes_command;

// SIZE=24

//==========  [05]  REMOVE CONNECTION    ==========
typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
} remove_connection_command;

//==========  [06]  REMOVE LISTENER    ==========
typedef struct {
    char symbolicOrListenerid[SYMBOLIC_NAME_LEN];
} remove_listener_command;

// SIZE=16

//==========  [07]  REMOVE ROUTE    ==========

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    ip_address_t address;
    uint8_t family;
    uint8_t len;
} remove_route_command;

// SIZE=36

//==========  [08]  CACHE STORE    ==========

typedef struct {
    uint8_t activate;
} cache_store_command;

// SIZE=1

//==========  [09]  CACHE SERVE    ==========

typedef struct {
    uint8_t activate;
} cache_serve_command;

// SIZE=1

//==========  [10]  SET STRATEGY    ==========

typedef struct {
    ip_address_t address;
    uint8_t strategy_type;
    uint8_t family;
    uint8_t len;
    uint8_t related_prefixes;
    union {
        struct {
            ip_address_t addresses[MAX_FWD_STRATEGY_RELATED_PREFIXES];
            uint8_t lens[MAX_FWD_STRATEGY_RELATED_PREFIXES];
            uint8_t families[MAX_FWD_STRATEGY_RELATED_PREFIXES];
        } low_latency;
    };
} set_strategy_command;

// SIZE=208

//==========  [11]  SET WLDR    ==========

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    uint8_t activate;
} set_wldr_command;

// SIZE=17

//==========  [12]  ADD PUNTING    ==========

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    ip_address_t address;
    uint8_t family;
    uint8_t len;
} add_punting_command;

// SIZE=36

//==========  [13]  LIST LISTENER    ==========

typedef struct {
    ip_address_t address;
    char listenerName[SYMBOLIC_NAME_LEN];
    char interfaceName[SYMBOLIC_NAME_LEN];
    uint32_t connid;
    uint16_t port;
    uint8_t family;
    uint8_t encapType;
} list_listeners_command;

// SIZE=56

//==========  [14]  MAPME    ==========

//  (enable/discovery/timescale/retx)

typedef struct {
    uint8_t activate;
} mapme_activator_command;

// SIZE=1

typedef struct {
    uint32_t timePeriod;
} mapme_timing_command;

typedef struct {
    ip_address_t address;
    uint8_t family;
    uint8_t len;
} mapme_send_update_command;

// SIZE=1

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    uint8_t admin_state;
    uint8_t pad8[3];
} connection_set_admin_state_command;

#ifdef WITH_POLICY

typedef struct {
    ip_address_t address;
    uint8_t family;
    uint8_t len;
    policy_t policy;
} add_policy_command;

typedef struct {
    ip_address_t address;
    uint8_t family;
    uint8_t len;
    policy_t policy;
} list_policies_command;

typedef struct {
    ip_address_t address;
    uint8_t family;
    uint8_t len;
} remove_policy_command;

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    uint8_t admin_state;
    uint32_t priority;
    policy_tags_t tags;
} update_connection_command;

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    uint32_t priority;
} connection_set_priority_command;

typedef struct {
    char symbolicOrConnid[SYMBOLIC_NAME_LEN];
    policy_tags_t tags;
} connection_set_tags_command;

#endif /* WITH_POLICY */

//===== size of commands ======
// REMINDER: when a new_command is added, the following switch has to be
// updated.
static inline int command_get_payload_len(command_type_t command_type) {
    switch (command_type) {
        case ADD_LISTENER:
            return sizeof(add_listener_command);
        case ADD_CONNECTION:
            return sizeof(add_connection_command);
        case LIST_CONNECTIONS:
            return 0;  // list connections: payload always 0
        case ADD_ROUTE:
            return sizeof(add_route_command);
        case LIST_ROUTES:
            return 0;  // list routes: payload always 0
        case REMOVE_CONNECTION:
            return sizeof(remove_connection_command);
        case REMOVE_LISTENER:
            return sizeof(remove_listener_command);
        case REMOVE_ROUTE:
            return sizeof(remove_route_command);
        case CACHE_STORE:
            return sizeof(cache_store_command);
        case CACHE_SERVE:
            return sizeof(cache_serve_command);
        case CACHE_CLEAR:
            return 0;  // cache clear
        case SET_STRATEGY:
            return sizeof(set_strategy_command);
        case SET_WLDR:
            return sizeof(set_wldr_command);
        case ADD_PUNTING:
            return sizeof(add_punting_command);
        case LIST_LISTENERS:
            return 0;  // list listeners: payload always 0
        case MAPME_ENABLE:
            return sizeof(mapme_activator_command);
        case MAPME_DISCOVERY:
            return sizeof(mapme_activator_command);
        case MAPME_TIMESCALE:
            return sizeof(mapme_timing_command);
        case MAPME_RETX:
            return sizeof(mapme_timing_command);
        case MAPME_SEND_UPDATE:
            return sizeof(mapme_send_update_command);
        case CONNECTION_SET_ADMIN_STATE:
            return sizeof(connection_set_admin_state_command);
#ifdef WITH_POLICY
        case ADD_POLICY:
            return sizeof(add_policy_command);
        case LIST_POLICIES:
            return 0; // list policies: payload always 0
        case REMOVE_POLICY:
            return sizeof(remove_policy_command);
        case UPDATE_CONNECTION:
            return sizeof(update_connection_command);
        case CONNECTION_SET_PRIORITY:
            return sizeof(connection_set_priority_command);
        case CONNECTION_SET_TAGS:
            return sizeof(connection_set_tags_command);
#endif /* WITH_POLICY */
        case LAST_COMMAND_VALUE:
            return 0;
        default:
            return 0;
    }
}
#endif
