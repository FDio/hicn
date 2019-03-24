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

typedef struct in6_addr ipv6_addr_t;
typedef uint32_t ipv4_addr_t;

union commandAddr {
  ipv4_addr_t ipv4;
  ipv6_addr_t ipv6;
};

typedef enum {
  REQUEST_LIGHT = 0xc0,  // this is a command
  RESPONSE_LIGHT,
  ACK_LIGHT,
  NACK_LIGHT,
  LAST_MSG_TYPE_VALUE
} message_type;

typedef enum {
  ADD_LISTENER = 0,
  ADD_CONNECTION,
  LIST_CONNECTIONS,
  ADD_ROUTE,
  LIST_ROUTES,
  REMOVE_CONNECTION,
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
  LAST_COMMAND_VALUE
} command_id;

typedef enum {
  ADDR_INET = 1,
  ADDR_INET6,
  ADDR_LINK,
  ADDR_IFACE,
  ADDR_UNIX /* PF_UNIX */
} address_type;

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
  char symbolic[16];
  // char interfaceName[16];
  union commandAddr address;
  uint16_t port;
  // uint16_t etherType;
  uint8_t addressType;
  uint8_t listenerMode;
  uint8_t connectionType;
} add_listener_command;

// SIZE=40

//==========  [01]  ADD CONNECTION    ==========

typedef struct {
  char symbolic[16];
  union commandAddr remoteIp;
  union commandAddr localIp;
  uint16_t remotePort;
  uint16_t localPort;
  uint8_t ipType;
  uint8_t connectionType;
} add_connection_command;

// SIZE=56

//==========  [02]  LIST CONNECTIONS    ==========

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

typedef struct {
  add_connection_command connectionData;
  uint32_t connid;
  uint8_t state;
} list_connections_command;

// SIZE=64

//==========  [03]  ADD ROUTE    ==========

typedef struct {
  char symbolicOrConnid[16];
  union commandAddr address;
  uint16_t cost;
  uint8_t addressType;
  uint8_t len;
} add_route_command;

// SIZE=36

//==========  [04]  LIST ROUTE    ==========

typedef struct {
  union commandAddr address;
  uint32_t connid;
  uint16_t cost;
  uint8_t addressType;
  uint8_t len;
} list_routes_command;

// SIZE=24

//==========  [05]  REMOVE CONNECTION    ==========

typedef struct {
  char symbolicOrConnid[16];
} remove_connection_command;

// SIZE=16

//==========  [06]  REMOVE ROUTE    ==========

typedef struct {
  char symbolicOrConnid[16];
  union commandAddr address;
  uint8_t addressType;
  uint8_t len;
} remove_route_command;

// SIZE=36

//==========  [07]  CACHE STORE    ==========

typedef struct {
  uint8_t activate;
} cache_store_command;

// SIZE=1

//==========  [08]  CACHE SERVE    ==========

typedef struct {
  uint8_t activate;
} cache_serve_command;

// SIZE=1

//==========  [09]  SET STRATEGY    ==========

typedef enum {
  SET_STRATEGY_LOADBALANCER,
  SET_STRATEGY_RANDOM,
  SET_STRATEGY_RANDOM_PER_DASH_SEGMENT,
  SET_STRATEGY_LOADBALANCER_WITH_DELAY,
  SET_STRATEGY_LOADBALANCER_BY_RATE,
  SET_STRATEGY_LOADBALANCER_BEST_ROUTE,
  LAST_STRATEGY_VALUE
} strategy_type;

typedef struct {
  union commandAddr address;
  uint8_t strategyType;
  uint8_t addressType;
  uint8_t len;
} set_strategy_command;

// SIZE=20

//==========  [11]  SET WLDR    ==========

typedef struct {
  char symbolicOrConnid[16];
  uint8_t activate;
} set_wldr_command;

// SIZE=17

//==========  [12]  ADD PUNTING    ==========

typedef struct {
  char symbolicOrConnid[16];
  union commandAddr address;
  uint8_t addressType;
  uint8_t len;
} add_punting_command;

// SIZE=36

//==========  [13]  LIST LISTENER    ==========

typedef struct {
  union commandAddr address;
  uint32_t connid;
  uint16_t port;
  uint8_t addressType;
  uint8_t encapType;
} list_listeners_command;

// SIZE=24

//==========  [14]  MAPME    ==========

//  (enable/discovery/timescale/retx)

typedef struct {
  uint8_t activate;
} mapme_activator_command;

// SIZE=1

typedef struct {
  uint32_t timePeriod;
} mapme_timing_command;

// SIZE=1

//===== size of commands ======
// REMINDER: when a new_command is added, the following switch has to be
// updated.
static inline int payloadLengthDaemon(command_id id) {
  switch (id) {
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
    case LAST_COMMAND_VALUE:
      return 0;
    default:
      return 0;
  }
}
#endif
