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
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <ctype.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_String.h>

#include <hicn/config/configurationListeners.h>
#include <hicn/config/symbolicNameTable.h>

#include <hicn/core/connection.h>
#include <hicn/base/connection_table.h>
#include <hicn/core/forwarder.h>
//#include <hicn/core/system.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#include <hicn/io/streamConnection.h>

#include <hicn/io/hicnTunnel.h>
#include <hicn/io/udpTunnel.h>

#include <parc/algol/parc_Unsigned.h>
#include <hicn/io/listener.h>     //the listener list
#include <hicn/base/listener_table.h>
#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#define ETHERTYPE 0x0801
#define DEFAULT_COST 1

#define DEBUG(FMT, ...) do {                                                           \
    if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Debug))  \
    logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Debug, __func__,  \
            FMT, ## __VA_ARGS__);                                                 \
} while(0);

#define WARN(FMT, ...) do {                                                            \
    if (logger_IsLoggable(config->logger, LoggerFacility_Config,  PARCLogLevel_Error)) \
    logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,  \
            FMT, ## __VA_ARGS__);                                                 \
} while(0);

#define ERROR(FMT, ...) do {                                                           \
    if (logger_IsLoggable(config->logger, LoggerFacility_Config,  PARCLogLevel_Error)) \
    logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,  \
            FMT, ## __VA_ARGS__);                                                 \
} while(0);

struct configuration {
    Forwarder *forwarder;
    Logger *logger;

    size_t maximumContentObjectStoreSize;

    // map from prefix (parcString) to strategy (parcString)
    PARCHashMap *strategy_map;

    // translates between a symblic name and a connection id
    SymbolicNameTable *symbolicNameTable;
};

// ========================================================================================

// connid = UINT_MAX when symbolicName is not found
static inline
    unsigned
_symbolic_to_connid(Configuration * config, const char * symbolicOrConnid,
        bool allow_self, unsigned ingress_id)
{
    unsigned connid;

    if (allow_self && strcmp(symbolicOrConnid, "SELF") == 0) {
        connid = ingress_id;
    } else if (utils_IsNumber(symbolicOrConnid)) {
        // case for connid as input
        int id = strtold(symbolicOrConnid, NULL);
        if (id < 0)
            return CONNECTION_ID_INVALID;
        connid = id;

        connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
        if (!connection_table_validate_id(table, connid)) {
            ERROR("ConnID not found, check list connections");
            connid = CONNECTION_ID_INVALID;
        }
    } else {
        // case for symbolic as input: check if symbolic name can be resolved
        connid = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        if (connection_id_is_valid(connid)) {
            DEBUG("Resolved symbolic name '%s' to connid %u", symbolicOrConnid, connid);
        } else {
            WARN("Symbolic name '%s' could not be resolved", symbolicOrConnid);
        }
    }

    return connid;
}

#define symbolic_to_connid(config, symbolic) _symbolic_to_connid(config, symbolic, false, 0)

#define symbolic_to_connid_self(config, symbolic, ingress_id) \
    _symbolic_to_connid(config, symbolic, true, ingress_id)

    Connection *
getConnectionBySymbolicOrId(Configuration * config, const char * symbolicOrConnid)
{
    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    unsigned connid = symbolic_to_connid(config, symbolicOrConnid);
    if (!connection_id_is_valid(connid))
        return NULL;

    /* connid is assumed validated here */
    return connection_table_at(table, connid);
}

// ========================================================================================

Configuration *configuration_Create(Forwarder *forwarder) {
    parcAssertNotNull(forwarder, "Parameter hicn-fwd must be non-null");
    Configuration *config = parcMemory_AllocateAndClear(sizeof(Configuration));
    parcAssertNotNull(config, "parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(Configuration));
    config->forwarder = forwarder;
    config->logger = logger_Acquire(forwarder_GetLogger(forwarder));
    config->maximumContentObjectStoreSize = 100000;
    config->strategy_map = parcHashMap_Create();
    config->symbolicNameTable = symbolicNameTable_Create();

    return config;
}

void configuration_Destroy(Configuration **configPtr) {
    parcAssertNotNull(configPtr, "Parameter must be non-null double poitner");
    parcAssertNotNull(*configPtr,
            "Parameter must dereference to non-null pointer");

    Configuration *config = *configPtr;
    logger_Release(&config->logger);
    parcHashMap_Release(&(config->strategy_map));
    symbolicNameTable_Destroy(&config->symbolicNameTable);
    parcMemory_Deallocate((void **)&config);
    *configPtr = NULL;
}

struct iovec *configuration_ProcessRegisterHicnPrefix(Configuration *config,
        struct iovec *request,
        unsigned ingressId) {
    header_control_message *header = request[0].iov_base;
    add_route_command *control = request[1].iov_base;

    unsigned connid = symbolic_to_connid_self(config, control->symbolicOrConnid, ingressId);
    if (!connection_id_is_valid(connid))
        goto NACK;

    if (!forwarder_AddOrUpdateRoute(config->forwarder, control, connid))
        goto NACK;

    return utils_CreateAck(header, control, sizeof(add_route_command));

NACK:
    return utils_CreateNack(header, control, sizeof(add_route_command));
}

struct iovec *configuration_ProcessUnregisterHicnPrefix(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    remove_route_command *control = request[1].iov_base;

    unsigned connid = symbolic_to_connid(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(connid))
        goto NACK;

    if (!forwarder_RemoveRoute(config->forwarder, control, connid))
        goto NACK;

    return utils_CreateAck(header, control, sizeof(remove_route_command));

NACK:
    return utils_CreateNack(header, control, sizeof(remove_route_command));
}

    struct iovec *
configuration_ProcessRegistrationList(Configuration *config,
        struct iovec *request)
{
    fib_entry_list_t *fibList = forwarder_GetFibEntries(config->forwarder);

    size_t payloadSize = fib_entry_list_Length(fibList);
    size_t effective_payloadSize = 0;
    size_t pointerLocation = 0;

    // allocate payload, cast from void* to uint8_t* = bytes granularity
    uint8_t *payloadResponse =
        parcMemory_AllocateAndClear(sizeof(list_routes_command) * payloadSize);

    for (size_t i = 0; i < fib_entry_list_Length(fibList); i++) {
        fib_entry_t *fib_entry = (fib_entry_t *)fib_entry_list_Get(fibList, i);
        NameBitvector *prefix = name_GetContentName(fib_entry_GetPrefix(fib_entry));
        const nexthops_t * nexthops = fib_entry_nexthops(fib_entry);

        size_t num_nexthops = nexthops_curlen(nexthops);

        if (num_nexthops == 0)
            continue;

        if (num_nexthops > 1) {
            // payload extended, need reallocate, further entries via nexthops
            payloadSize = payloadSize + num_nexthops - 1;
            payloadResponse = (uint8_t *) parcMemory_Reallocate(
                    payloadResponse, sizeof(list_routes_command) * payloadSize);
        }

        unsigned nexthop;
        nexthops_foreach(fib_entry_nexthops(fib_entry), nexthop, {
                list_routes_command *cmd = (list_routes_command *)(payloadResponse +
                        (pointerLocation * sizeof(list_routes_command)));

                address_t address;
                nameBitvector_ToAddress(prefix, &address);
                switch(address_family(&address)) {
                case AF_INET:
                cmd->family = AF_INET;
                cmd->address.v4.as_inaddr = address4_ip(&address);
                break;
                case AF_INET6:
                cmd->family = AF_INET6;
                cmd->address.v6.as_in6addr = address6_ip(&address);
                break;
                default:
                break;
                }
                cmd->connid = nexthop;
                cmd->len = nameBitvector_GetLength(prefix);
                cmd->cost = DEFAULT_COST;

                pointerLocation++;
                effective_payloadSize++;
        });
    }

    // send response
    header_control_message *header = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (unsigned)effective_payloadSize;

    struct iovec *response =
        parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = sizeof(list_routes_command) * effective_payloadSize;

    fib_entry_list_Destroy(&fibList);
    return response;
}

static void configuration_SendResponse(Configuration *config, struct iovec *msg,
        unsigned egressId) {
    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    /* egressId is assumed valid here */
    const Connection *conn = connection_table_at(table, egressId);
    connection_SendIOVBuffer(conn, msg, 2);
}

struct iovec *configuration_ProcessCreateTunnel(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    add_connection_command *control = request[1].iov_base;

    const char *symbolicName = control->symbolic;

    if (symbolicNameTable_Exists(config->symbolicNameTable, symbolicName)) {
        ERROR("Connection symbolic name already exists");
        goto NACK;
    }

    address_pair_t pair;
    if (address_pair_from_ip_port(&pair, control->family,
                &control->localIp, control->localPort,
                &control->remoteIp, control->remotePort) < 0)
        goto NACK;

    Connection ** conn_ptr;

    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    conn_ptr = connection_table_lookup(table, &pair);
#ifdef WITH_MAPME
    connection_event_t event;
#endif /* WITH_MAPME */

    if (!*conn_ptr) {
        connection_table_allocate(table, conn_ptr, &pair);
        unsigned connid = connection_table_get_connection_id(table, conn_ptr);
        IoOperations *ops = NULL;
        switch (control->connectionType) {
            case TCP_CONN:
                ops = streamConnection_OpenConnection(config->forwarder, &pair, false, connid);
                break;
            case UDP_CONN:
                ops = udpTunnel_Create(config->forwarder, &pair, connid);
                break;
            case GRE_CONN:
                ERROR("Unsupported tunnel protocol: GRE");
                goto NACK;
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
            case HICN_CONN:
                ops = hicnTunnel_Create(config->forwarder, &pair);
                break;
#endif /* __APPLE__  _WIN32*/
            default:
                ERROR("Unsupported tunnel protocol: %d", control->connectionType);
                goto NACK;
        }

        *conn_ptr = connection_Create(ops);
        symbolicNameTable_Add(config->symbolicNameTable, symbolicName, connid);

#ifdef WITH_MAPME
        event = CONNECTION_EVENT_CREATE;
#endif /* WITH_MAPME */

    } else {
#ifdef WITH_POLICY
#ifdef WITH_MAPME
        event = CONNECTION_EVENT_UPDATE;
#endif /* WITH_MAPME */
#else
        ERROR("failed, symbolic name or connection already exist\n");
        goto NACK;
#endif /* WITH_POLICY */
    }

#ifdef WITH_POLICY
    connection_SetTags(*conn_ptr, control->tags);
    connection_SetPriority(*conn_ptr, control->priority);
#endif /* WITH_POLICY */

    connection_SetAdminState(*conn_ptr, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: new *conn_ptrection created through the control protocol */
    forwarder_onConnectionEvent(config->forwarder, *conn_ptr, event);
#endif /* WITH_MAPME */

    return utils_CreateAck(header, control, sizeof(add_connection_command));

NACK:
    return utils_CreateNack(header, control, sizeof(add_connection_command));
}

struct iovec *configuration_ProcessRemoveListener(Configuration *config,
        struct iovec *request,
        unsigned ingressId) {
    header_control_message *header = request[0].iov_base;
    remove_listener_command *control = request[1].iov_base;

    const char *symbolicOrListenerid = control->symbolicOrListenerid;
    off_t listener_id;
    ListenerOps * listener;

    listener_table_t * listener_table = forwarder_GetListenerTable(config->forwarder);

    if (utils_IsNumber(symbolicOrListenerid)) {
        // case for connid as input
        int id = strtold(symbolicOrListenerid, NULL);
        if (id < 0)
            goto NACK;
        listener_id = id;

        listener = listener_table_get_by_id(listener_table, listener_id);
        if (!listener) {
            ERROR("Listener Id not found, check list listeners");
            goto NACK;
        }

    } else {
        listener = listener_table_get_by_name(listener_table, symbolicOrListenerid);
        listener_id = listener_table_get_listener_id(listener_table, listener);
    }


    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    Connection ** conn_ptr;
    connection_table_foreach(table, conn_ptr, {
            Connection * conn = *conn_ptr;
            const address_pair_t * pair = connection_GetAddressPair(conn);
            if (!address_equals(listener->getListenAddress(listener), &pair->local))
            continue;

            off_t connid = connection_table_get_connection_id(table, conn_ptr);
            /* Remove connection from the FIB */
            forwarder_RemoveConnectionIdFromRoutes(config->forwarder, connid);
            connection_table_remove_by_id(table, connid);

            /* Remove connection */
            connection_table_remove_by_id(table, connid);

            const char *symbolicConnection =
            symbolicNameTable_GetNameByIndex(config->symbolicNameTable, connid);
            symbolicNameTable_Remove(config->symbolicNameTable, symbolicConnection);
            });

    /* Remove listener */
    listener_table_remove_by_id(listener_table, listener_id);

    return utils_CreateAck(header, control, sizeof(remove_connection_command));

NACK:
    return utils_CreateNack(header, control, sizeof(remove_listener_command));
}


/**
 * Add an IP-based tunnel.
 *
 * The call cal fail if the symbolic name is a duplicate.  It could also fail if
 * there's an problem creating the local side of the tunnel (i.e. the local
 * socket address is not usable).
 *
 * @return true Tunnel added
 * @return false Tunnel not added (an error)
 */

struct iovec *configuration_ProcessRemoveTunnel(Configuration *config,
        struct iovec *request,
        unsigned ingressId) {
    header_control_message *header = request[0].iov_base;
    remove_connection_command *control = request[1].iov_base;

    unsigned connid = symbolic_to_connid_self(config, control->symbolicOrConnid, ingressId);
    if (!connection_id_is_valid(connid))
        goto NACK;


    /* Remove connection from the FIB */
    forwarder_RemoveConnectionIdFromRoutes(config->forwarder, connid);

    /* Remove connection */
    connection_table_t *table = forwarder_GetConnectionTable(config->forwarder);
    connection_table_remove_by_id(table, connid);

    /* Remove connection from symbolicNameTable */
    const char *symbolicConnection = symbolicNameTable_GetNameByIndex(config->symbolicNameTable, connid);
    symbolicNameTable_Remove(config->symbolicNameTable, symbolicConnection);

#ifdef WITH_MAPME
    /* Hook: new connection created through the control protocol */
    forwarder_onConnectionEvent(config->forwarder, NULL, CONNECTION_EVENT_DELETE);
#endif /* WITH_MAPME */

    return utils_CreateAck(header, control, sizeof(remove_connection_command));

NACK:
    return utils_CreateNack(header, control, sizeof(remove_connection_command));
}

void _strlwr(char *string) {
    char *p = string;
    while ((*p = tolower(*p))) {
        p++;
    }
}

static inline
    void
fill_connections_command(Configuration * config, Connection * connection,
        list_connections_command *cmd)
{
    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;
    const address_pair_t * pair = connection_GetAddressPair(connection);
    const char *connectionName = symbolicNameTable_GetNameByIndex(config->symbolicNameTable,
            connection_GetConnectionId(connection));

    *cmd = (list_connections_command) {
        .connid = connection_GetConnectionId(connection),
            .state = connection_GetState(connection),
            .connectionData = {
                .admin_state = connection_GetAdminState(connection),
                .connectionType = ioOperations_GetConnectionType(connection_GetIoOperations(connection)),
#ifdef WITH_POLICY
                .priority = connection_GetPriority(connection),
                .tags = connection_GetTags(connection),
#endif /* WITH_POLICY */
            }
    };

    snprintf(cmd->connectionName, SYMBOLIC_NAME_LEN, "%s", connectionName);
    _strlwr(cmd->connectionName);

    snprintf(cmd->interfaceName, SYMBOLIC_NAME_LEN, "%s",
            ioOperations_GetInterfaceName(connection_GetIoOperations(connection)));

    switch(pair->local.ss_family) {
        case AF_INET:
            cmd->connectionData.family = AF_INET;

            sin = (struct sockaddr_in *)(&pair->local);
            cmd->connectionData.localPort = sin->sin_port;
            cmd->connectionData.localIp.v4.as_inaddr = sin->sin_addr;

            sin = (struct sockaddr_in *)(&pair->remote);
            cmd->connectionData.remotePort = sin->sin_port;
            cmd->connectionData.remoteIp.v4.as_inaddr = sin->sin_addr;
            break;

        case AF_INET6:
            cmd->connectionData.family = AF_INET6;

            sin6 = (struct sockaddr_in6 *)(&pair->local);
            cmd->connectionData.localPort = sin6->sin6_port;
            cmd->connectionData.localIp.v6.as_in6addr = sin6->sin6_addr;

            sin6 = (struct sockaddr_in6 *)(&pair->remote);
            cmd->connectionData.remotePort = sin6->sin6_port;
            cmd->connectionData.remoteIp.v6.as_in6addr = sin6->sin6_addr;
            break;

        default:
            break;
    }
}

    struct iovec *
configuration_ProcessConnectionList(Configuration *config,
        struct iovec *request)
{
    connection_table_t *table = forwarder_GetConnectionTable(config->forwarder);

    size_t n = connection_table_len(table);

    // allocate payload, cast from void* to uint8_t* fot bytes granularity
    uint8_t *payloadResponse = parcMemory_AllocateAndClear(
            sizeof(list_connections_command) * n);

    off_t i = 0;
    Connection ** conn_ptr;
    connection_table_foreach(table, conn_ptr, {
            Connection * conn = *conn_ptr;
            list_connections_command *cmd = (list_connections_command *)(payloadResponse
                    + (i * sizeof(list_connections_command)));
            fill_connections_command(config, conn, cmd);
            i++;
            });

    // send response
    header_control_message *header = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (uint16_t)n;

    struct iovec *response =
        parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = n * sizeof(list_connections_command);

    return response;
}

static inline
    void
fill_listener_command(Configuration * config, ListenerOps * listener,
        list_listeners_command * cmd)
{
    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;

    const address_t * addr = listener->getListenAddress(listener);

    *cmd = (list_listeners_command) {
        .connid = (uint32_t)listener->getInterfaceIndex(listener),
            .encapType = (uint8_t)listener->getEncapType(listener),
    };

    switch(addr->ss_family) {
        case AF_INET:
            sin = (struct sockaddr_in *) addr;
            cmd->family = AF_INET;
            cmd->address.v4.as_inaddr = sin->sin_addr;
            cmd->port = sin->sin_port;
            break;
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) addr;
            cmd->family = AF_INET6;
            cmd->address.v6.as_in6addr = sin6->sin6_addr;
            cmd->port = sin6->sin6_port;
            break;
        default:
            break;
    }

    const char * listenerName = listener->getListenerName(listener);
    snprintf(cmd->listenerName, SYMBOLIC_NAME_LEN, "%s", listenerName);
    if (listener->getEncapType(listener) == ENCAP_TCP ||
            listener->getEncapType(listener) == ENCAP_UDP) {
        const char * interfaceName = listener->getInterfaceName(listener);
        snprintf(cmd->interfaceName, SYMBOLIC_NAME_LEN, "%s", interfaceName);
    }

}

struct iovec *configuration_ProcessListenersList(Configuration *config,
        struct iovec *request) {
    listener_table_t * table = forwarder_GetListenerTable(config->forwarder);

    size_t n = listener_table_len(table);
    uint8_t *payloadResponse = parcMemory_AllocateAndClear(n *
            sizeof(list_listeners_command));

    off_t i = 0;
    ListenerOps ** listener_ptr;
    listener_table_foreach(table, listener_ptr, {
            ListenerOps * listener = *listener_ptr;
            list_listeners_command *cmd = (list_listeners_command *)(payloadResponse +
                    (i * sizeof(list_listeners_command)));
            fill_listener_command(config, listener, cmd);
            i++;
            });


    // send response
    header_control_message *header = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (uint16_t)n;

    struct iovec *response =
        parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = n * sizeof(list_listeners_command);

    return response;
}

struct iovec *configuration_ProcessCacheStore(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    cache_store_command *control = request[1].iov_base;

    bool success = false;

    switch (control->activate) {
        case ACTIVATE_ON:
            forwarder_SetChacheStoreFlag(config->forwarder, true);
            if (forwarder_GetChacheStoreFlag(config->forwarder)) {
                success = true;
            }
            break;

        case ACTIVATE_OFF:
            forwarder_SetChacheStoreFlag(config->forwarder, false);
            if (!forwarder_GetChacheStoreFlag(config->forwarder)) {
                success = true;
            }
            break;

        default:
            break;
    }

    struct iovec *response;
    if (success) {  // ACK
        response = utils_CreateAck(header, control, sizeof(cache_store_command));
    } else {  // NACK
        response = utils_CreateNack(header, control, sizeof(cache_store_command));
    }

    return response;
}

struct iovec *configuration_ProcessCacheServe(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    cache_serve_command *control = request[1].iov_base;

    bool success = false;

    switch (control->activate) {
        case ACTIVATE_ON:
            forwarder_SetChacheServeFlag(config->forwarder, true);
            if (forwarder_GetChacheServeFlag(config->forwarder)) {
                success = true;
            }
            break;

        case ACTIVATE_OFF:
            forwarder_SetChacheServeFlag(config->forwarder, false);
            if (!forwarder_GetChacheServeFlag(config->forwarder)) {
                success = true;
            }
            break;

        default:
            break;
    }

    struct iovec *response;
    if (success) {  // ACK
        response = utils_CreateAck(header, control, sizeof(cache_store_command));
    } else {  // NACK
        response = utils_CreateNack(header, control, sizeof(cache_store_command));
    }

    return response;
}

struct iovec *configuration_ProcessCacheClear(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;

    forwarder_ClearCache(config->forwarder);

    struct iovec *response = utils_CreateAck(header, NULL, 0);
    return response;
}

size_t configuration_GetObjectStoreSize(Configuration *config) {
    return config->maximumContentObjectStoreSize;
}

void _configuration_StoreFwdStrategy(Configuration *config, const char *prefix,
        strategy_type_t strategy) {
    PARCString *prefixStr = parcString_Create(prefix);
    PARCUnsigned *strategyValue = parcUnsigned_Create((unsigned)strategy);
    parcHashMap_Put(config->strategy_map, prefixStr, strategyValue);
    parcUnsigned_Release(&strategyValue);
    parcString_Release(&prefixStr);
}

struct iovec *configuration_SetWldr(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    set_wldr_command *control = request[1].iov_base;

    unsigned connid = symbolic_to_connid(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(connid))
        goto NACK;

    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    Connection * conn = connection_table_at(table, connid);

    switch (control->activate) {
        case ACTIVATE_ON:
            connection_EnableWldr(conn);
            break;
        case ACTIVATE_OFF:
            connection_DisableWldr(conn);
            break;
        default:
            goto NACK;
    }

    return utils_CreateAck(header, control, sizeof(set_wldr_command));

NACK:
    return utils_CreateAck(header, control, sizeof(set_wldr_command));
}

strategy_type_t configuration_GetForwardingStrategy(Configuration *config,
        const char *prefix) {
    PARCString *prefixStr = parcString_Create(prefix);
    const unsigned *val = parcHashMap_Get(config->strategy_map, prefixStr);
    parcString_Release(&prefixStr);

    if (val == NULL) {
        return STRATEGY_TYPE_UNDEFINED;
    } else {
        return (strategy_type_t)*val;
    }
}

struct iovec *configuration_SetForwardingStrategy(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    set_strategy_command *control = request[1].iov_base;

    const char *prefix = utils_PrefixLenToString(
            control->family, &control->address, &control->len);
    strategy_type_t strategy = control->strategy_type;
    strategy_type_t existingFwdStrategy =
        configuration_GetForwardingStrategy(config, prefix);

    if (existingFwdStrategy == STRATEGY_TYPE_UNDEFINED ||
            strategy != existingFwdStrategy) {
        // means such a new strategy is not present in the hash table or has to be
        // updated
        _configuration_StoreFwdStrategy(config, prefix, strategy);
        Name *hicnPrefix = name_CreateFromAddress(control->family,
                control->address, control->len);

        switch(control->strategy_type) {
            case STRATEGY_TYPE_LOW_LATENCY:
                {

                    strategy_options_t options;
                    options.low_latency.related_prefixes_len = control->related_prefixes;
                    Name **related_prefixes = options.low_latency.related_prefixes;

                    if(control->related_prefixes != 0){
                        for(int i = 0; i < control->related_prefixes; i++){
                            related_prefixes[i] = name_CreateFromAddress(
                                    control->low_latency.families[i],
                                    control->low_latency.addresses[i],
                                    control->low_latency.lens[i]);
                        }
                    }
                    forwarder_SetStrategy(config->forwarder, hicnPrefix, strategy, &options);

                    if(control->related_prefixes != 0){
                        for(int i = 0; i < control->related_prefixes; i++){
                            name_Release(&related_prefixes[i]);
                        }
                    }
                    break;
                }
            default:
                break;
        }
        name_Release(&hicnPrefix);
    }

    free((char *) prefix);
    struct iovec *response =
        utils_CreateAck(header, control, sizeof(set_strategy_command));

    return response;
}

void configuration_SetObjectStoreSize(Configuration *config,
        size_t maximumObjectCount) {
    config->maximumContentObjectStoreSize = maximumObjectCount;

    forwarder_SetContentObjectStoreSize(config->forwarder,
            config->maximumContentObjectStoreSize);
}

Forwarder *configuration_GetForwarder(const Configuration *config) {
    return config->forwarder;
}

Logger *configuration_GetLogger(const Configuration *config) {
    return config->logger;
}

struct iovec *configuration_MapMeEnable(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    mapme_activator_command *control = request[1].iov_base;
    const char *stateString[2] = {"on", "off"};

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer,
            "The mapme enable setting received is: %s",
            stateString[control->activate]);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);

    return utils_CreateAck(header, control, sizeof(mapme_timing_command));
}

struct iovec *configuration_MapMeDiscovery(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    mapme_activator_command *control = request[1].iov_base;
    const char *stateString[2] = {"on", "off"};

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer,
            "The mapme discovery setting received is: %s",
            stateString[control->activate]);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);

    return utils_CreateAck(header, control, sizeof(mapme_timing_command));
}

struct iovec *configuration_MapMeTimescale(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    mapme_timing_command *control = request[1].iov_base;

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer,
            "The mapme timescale value received is: %u",
            control->timePeriod);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);

    return utils_CreateAck(header, control, sizeof(mapme_timing_command));
}

struct iovec *configuration_MapMeRetx(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    mapme_timing_command *control = request[1].iov_base;

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(
            composer, "The mapme retransmission time value received is: %u",
            control->timePeriod);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **)&result);
    parcBufferComposer_Release(&composer);

    return utils_CreateAck(header, control, sizeof(mapme_timing_command));
}

struct iovec * configuration_MapMeSendUpdate(Configuration *config,
        struct iovec *request, unsigned ingressId) {
    header_control_message *header = request[0].iov_base;
    mapme_send_update_command *control = request[1].iov_base;

    FIB * fib = forwarder_getFib(config->forwarder);
    if (!fib)
        goto ERR;
    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    if (!prefix)
        goto ERR;
    fib_entry_t *entry = fib_Contains(fib, prefix);
    name_Release(&prefix);
    if (!entry)
        goto ERR;

    const nexthops_t * nexthops = fib_entry_nexthops(entry);

    /* The command is accepted iif triggered by (one of) the producer of this prefix */
    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
            if (nexthop == ingressId) {
            MapMe * mapme = forwarder_getMapmeInstance(config->forwarder);
            mapme_send_updates(mapme, entry, nexthops);
            return utils_CreateAck(header, control, sizeof(mapme_timing_command));
            }
            });

ERR:
    return utils_CreateNack(header, control, sizeof(connection_set_admin_state_command));
}


struct iovec *configuration_ConnectionSetAdminState(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    connection_set_admin_state_command *control = request[1].iov_base;

    if ((control->admin_state != CONNECTION_STATE_UP) && (control->admin_state != CONNECTION_STATE_DOWN))
        return utils_CreateNack(header, control, sizeof(connection_set_admin_state_command));

    Connection * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        return utils_CreateNack(header, control, sizeof(connection_set_admin_state_command));

    connection_SetAdminState(conn, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            control->admin_state == CONNECTION_STATE_UP
            ? CONNECTION_EVENT_SET_UP
            : CONNECTION_EVENT_SET_DOWN);
#endif /* WITH_MAPME */

    return utils_CreateAck(header, control, sizeof(connection_set_admin_state_command));
}

#ifdef WITH_POLICY

struct iovec *configuration_ConnectionSetPriority(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    connection_set_priority_command *control = request[1].iov_base;

    Connection * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        return utils_CreateNack(header, control, sizeof(connection_set_priority_command));

    connection_SetPriority(conn, control->priority);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            CONNECTION_EVENT_PRIORITY_CHANGED);
#endif /* WITH_MAPME */

    return utils_CreateAck(header, control, sizeof(connection_set_priority_command));
}

struct iovec *configuration_ConnectionSetTags(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    connection_set_tags_command *control = request[1].iov_base;

    Connection * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        return utils_CreateNack(header, control, sizeof(connection_set_tags_command));

    connection_SetTags(conn, control->tags);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            CONNECTION_EVENT_TAGS_CHANGED);
#endif /* WITH_MAPME */

    return utils_CreateAck(header, control, sizeof(connection_set_tags_command));
}

struct iovec *configuration_ProcessPolicyAdd(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    add_policy_command *control = request[1].iov_base;

    if (forwarder_AddOrUpdatePolicy(config->forwarder, control)) {
        return utils_CreateAck(header, control, sizeof(add_policy_command));
    } else {
        return utils_CreateNack(header, control, sizeof(add_policy_command));
    }
}

struct iovec *configuration_ProcessPolicyList(Configuration *config,
        struct iovec *request) {
    fib_entry_list_t *fibList = forwarder_GetFibEntries(config->forwarder);

    size_t payloadSize = fib_entry_list_Length(fibList);

    // allocate payload, cast from void* to uint8_t* = bytes granularity
    uint8_t *payloadResponse =
        parcMemory_AllocateAndClear(sizeof(list_policies_command) * payloadSize);

    for (size_t i = 0; i < fib_entry_list_Length(fibList); i++) {
        fib_entry_t *entry = (fib_entry_t *)fib_entry_list_Get(fibList, i);
        NameBitvector *prefix = name_GetContentName(fib_entry_GetPrefix(entry));

        list_policies_command *cmd = (list_policies_command *)(payloadResponse +
                (i * sizeof(list_policies_command)));

        address_t address;
        nameBitvector_ToAddress(prefix, &address);

        switch(address_family(&address)) {
            case AF_INET:
                cmd->family = AF_INET;
                cmd->address.v4.as_inaddr = address4_ip(&address);
                break;

            case AF_INET6:
                cmd->family = AF_INET6;
                cmd->address.v6.as_in6addr = address6_ip(&address);
                break;

            default:
                break;
        }
        cmd->len = nameBitvector_GetLength(prefix);
        cmd->policy = fib_entry_GetPolicy(entry);
    }

    // send response
    header_control_message *header = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (unsigned)payloadSize;

    struct iovec *response =
        parcMemory_AllocateAndClear(sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = sizeof(list_policies_command) * payloadSize;

    fib_entry_list_Destroy(&fibList);
    return response;
}

struct iovec *configuration_ProcessPolicyRemove(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    remove_policy_command *control = request[1].iov_base;

    if (forwarder_RemovePolicy(config->forwarder, control))
        return utils_CreateAck(header, control, sizeof(remove_policy_command));
    else
        return utils_CreateNack(header, control, sizeof(remove_policy_command));
}

struct iovec *configuration_UpdateConnection(Configuration *config,
        struct iovec *request) {
    header_control_message *header = request[0].iov_base;
    update_connection_command *control = request[1].iov_base;

    Connection * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        return utils_CreateNack(header, control, sizeof(update_connection_command));

    connection_SetTags(conn, control->tags);
    connection_SetAdminState(conn, control->admin_state);
    if (control->priority > 0)
        connection_SetPriority(conn, control->priority);

    return utils_CreateAck(header, control, sizeof(update_connection_command));
}
#endif /* WITH_POLICY */

// ===========================
// Main functions that deal with receiving commands, executing them, and sending
// ACK/NACK

struct iovec *configuration_DispatchCommand(Configuration *config,
        command_id command,
        struct iovec *control,
        unsigned ingressId) {
    struct iovec *response = NULL;
    switch (command) {
        case ADD_LISTENER:
            response = configurationListeners_Add(config, control, ingressId);
            break;

        case ADD_CONNECTION:
            response = configuration_ProcessCreateTunnel(config, control);
            break;

        case LIST_CONNECTIONS:
            response = configuration_ProcessConnectionList(config, control);
            break;

        case ADD_ROUTE:
            response =
                configuration_ProcessRegisterHicnPrefix(config, control, ingressId);
            break;

        case LIST_ROUTES:
            response = configuration_ProcessRegistrationList(config, control);
            break;

        case REMOVE_CONNECTION:
            response = configuration_ProcessRemoveTunnel(config, control, ingressId);
            break;

        case REMOVE_LISTENER:
            response = configuration_ProcessRemoveListener(config, control, ingressId);
            break;

        case REMOVE_ROUTE:
            response = configuration_ProcessUnregisterHicnPrefix(config, control);
            break;

        case CACHE_STORE:
            response = configuration_ProcessCacheStore(config, control);
            break;

        case CACHE_SERVE:
            response = configuration_ProcessCacheServe(config, control);
            break;

        case CACHE_CLEAR:
            response = configuration_ProcessCacheClear(config, control);
            break;

        case SET_STRATEGY:
            response = configuration_SetForwardingStrategy(config, control);
            break;

        case SET_WLDR:
            response = configuration_SetWldr(config, control);
            break;

        case ADD_PUNTING:
            response = configurationListeners_AddPunting(config, control, ingressId);
            break;

        case LIST_LISTENERS:
            response = configuration_ProcessListenersList(config, control);
            break;

        case MAPME_ENABLE:
            response = configuration_MapMeEnable(config, control);
            break;

        case MAPME_DISCOVERY:
            response = configuration_MapMeDiscovery(config, control);
            break;

        case MAPME_TIMESCALE:
            response = configuration_MapMeTimescale(config, control);
            break;

        case MAPME_RETX:
            response = configuration_MapMeRetx(config, control);
            break;

        case MAPME_SEND_UPDATE:
            response = configuration_MapMeSendUpdate(config, control, ingressId);
            break;

        case CONNECTION_SET_ADMIN_STATE:
            response = configuration_ConnectionSetAdminState(config, control);
            break;

#ifdef WITH_POLICY
        case ADD_POLICY:
            response = configuration_ProcessPolicyAdd(config, control);
            break;

        case LIST_POLICIES:
            response = configuration_ProcessPolicyList(config, control);
            break;

        case REMOVE_POLICY:
            response = configuration_ProcessPolicyRemove(config, control);
            break;

        case UPDATE_CONNECTION:
            response = configuration_UpdateConnection(config, control);
            break;

        case CONNECTION_SET_PRIORITY:
            response = configuration_ConnectionSetPriority(config, control);
            break;

        case CONNECTION_SET_TAGS:
            response = configuration_ConnectionSetTags(config, control);
            break;
#endif /* WITH_POLICY */

        default:
            break;
    }

    return response;
}

void configuration_ReceiveCommand(Configuration *config, command_id command,
        struct iovec *request, unsigned ingressId) {
    parcAssertNotNull(config, "Parameter config must be non-null");
    parcAssertNotNull(request, "Parameter request must be non-null");
    struct iovec *response =
        configuration_DispatchCommand(config, command, request, ingressId);
    configuration_SendResponse(config, response, ingressId);

    switch (command) {
        case LIST_CONNECTIONS:
        case LIST_ROUTES:  // case LIST_INTERFACES: case ETC...:
        case LIST_LISTENERS:
            parcMemory_Deallocate(
                    &response[1]
                    .iov_base);  // deallocate payload only if generated at fwd side
            break;
        default:
            break;
    }

    // deallocate received request. It coincides with response[0].iov_base memory
    // parcMemory_Deallocate(&request);    //deallocate header and payload (if
    // same sent by controller)
    parcMemory_Deallocate(&response);  // deallocate iovec pointer
}
