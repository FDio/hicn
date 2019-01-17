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

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct in6_addr ipv6_addr_t;
typedef uint32_t ipv4_addr_t;

union commandAddr{
    ipv4_addr_t ipv4;
    ipv6_addr_t ipv6;
};

typedef enum {
    REQUEST_LIGHT = 100,
    RESPONSE_LIGHT,
    ACK_LIGHT,
    NACK_LIGHT,
    LAST_MSG_TYPE_VALUE
} message_type;

typedef enum {
    ADD_LISTENER,
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
    ADDR_UNIX    /* PF_UNIX */
} address_type;

typedef enum {
    UDP_CONN,
    TCP_CONN,
    GRE_CONN, //not implemented
    HICN_CONN
} connection_type;

typedef enum {
    ACTIVATE_ON,
    ACTIVATE_OFF
} activate_type;


//==========    HEADER    ==========

typedef struct{
    uint8_t messageType;
    uint8_t commandID;
    uint16_t length;       //tells the number of structures in the payload
    uint32_t seqNum;
} header_control_message;
//for the moment has to be at least 8 bytes

    //SIZE=8


//==========  [00]  ADD LISTENER    ==========

typedef enum {
    ETHER_MODE,
    IP_MODE,
    HICN_MODE
} listener_mode;

typedef struct{
    char symbolic[16];
    //char interfaceName[16];
    union commandAddr address;
    uint16_t port;
    //uint16_t etherType;
    uint8_t addressType;
    uint8_t listenerMode;
    uint8_t connectionType;
} add_listener_command;

    //SIZE=40


//==========  [01]  ADD CONNECTION    ==========

typedef struct{
    char symbolic[16];
    union commandAddr remoteIp;
    union commandAddr localIp;
    uint16_t remotePort;
    uint16_t localPort;
    uint8_t ipType;
    uint8_t connectionType;
} add_connection_command;

    //SIZE=56


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
    IFACE_UNKNOWN = 2  //not used actually
} connection_state;


typedef struct{
    add_connection_command connectionData;
    uint32_t connid;
    uint8_t state;
} list_connections_command;

//SIZE=64


//==========  [03]  ADD ROUTE    ==========

typedef struct{
    char symbolicOrConnid[16];
    union commandAddr address;
    uint16_t cost;
    uint8_t addressType;
    uint8_t len;
} add_route_command;

//SIZE=36


//==========  [04]  LIST ROUTE    ==========

typedef struct{
    union commandAddr address;
    uint32_t connid;
    uint16_t cost;
    uint8_t addressType;
    uint8_t len;
} list_routes_command;

//SIZE=24

//==========  [05]  REMOVE CONNECTION    ==========

typedef struct{
    char symbolicOrConnid[16];
} remove_connection_command;

//SIZE=16


//==========  [06]  REMOVE ROUTE    ==========

typedef struct{
    char symbolicOrConnid[16];
    union commandAddr address;
    uint8_t addressType;
    uint8_t len;
} remove_route_command;

//SIZE=36


//==========  [07]  CACHE STORE    ==========


typedef struct{
    uint8_t activate;
} cache_store_command;

//SIZE=1


//==========  [08]  CACHE SERVE    ==========


typedef struct{
    uint8_t activate;
} cache_serve_command;

//SIZE=1


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


typedef struct{
    union commandAddr address;
    uint8_t strategyType;
    uint8_t addressType;
    uint8_t len;
} set_strategy_command;

//SIZE=20


//==========  [11]  SET WLDR    ==========

typedef struct{
    char symbolicOrConnid[16];
    uint8_t activate;
} set_wldr_command;

//SIZE=17


//==========  [12]  ADD PUNTING    ==========

typedef struct{
    char symbolicOrConnid[16];
    union commandAddr address;
    uint8_t addressType;
    uint8_t len;
} add_punting_command;

//SIZE=36


//==========  [13]  LIST LISTENER    ==========

typedef struct{
    union commandAddr address;
    uint32_t connid;
    uint16_t port;
    uint8_t addressType;
    uint8_t encapType;
} list_listeners_command;

//SIZE=24


//==========  [14]  MAPME    ==========

//  (enable/discovery/timescale/retx)

typedef struct{
    uint8_t activate;
} mapme_activator_command;

//SIZE=1

typedef struct{
    uint32_t timePeriod;
} mapme_timing_command;

//SIZE=1


#endif
