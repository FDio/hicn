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

#include <hicn/io/listener.h>     //the listener list
#include <hicn/base/listener_table.h>
#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>
#include <hicn/util/log.h>

#define ETHERTYPE 0x0801
#define DEFAULT_COST 1

#define make_ack(msg)  msg->header->messageType =  ACK_LIGHT
#define make_nack(msg) msg->header->messageType = NACK_LIGHT

#define msg_malloc_list(msg, N)                                         \
do {                                                                    \
    msg = malloc(sizeof((msg)->header) + n * sizeof((msg)->payload));   \
    (msg)->header->messageType = RESPONSE_LIGHT;                        \
    (msg)->header->length = (uint16_t)(N);                              \
} while(0);


struct configuration {
    Forwarder *forwarder;

    size_t maximumContentObjectStoreSize;

    // map from prefix (parcString) to strategy (parcString)
    PARCHashMap *strategy_map;

    // translates between a symblic name and a connection id
    SymbolicNameTable *symbolicNameTable;
};

// ========================================================================================

// conn_id = UINT_MAX when symbolicName is not found
static inline
    unsigned
_symbolic_to_conn_id(Configuration * config, const char * symbolicOrConnid,
        bool allow_self, unsigned ingress_id)
{
    unsigned conn_id;

    if (allow_self && strcmp(symbolicOrConnid, "SELF") == 0) {
        conn_id = ingress_id;
    } else if (utils_IsNumber(symbolicOrConnid)) {
        // case for conn_id as input
        // XXX type issue ! XXX No check, see man
        int id = atoi(symbolicOrConnid);
        if (id < 0)
            return CONNECTION_ID_INVALID;
        conn_id = id;

        connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
        if (!connection_table_validate_id(table, conn_id)) {
            ERROR("ConnID not found, check list connections");
            conn_id = CONNECTION_ID_INVALID;
        }
    } else {
        // case for symbolic as input: check if symbolic name can be resolved
        conn_id = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        if (connection_id_is_valid(conn_id)) {
            DEBUG("Resolved symbolic name '%s' to conn_id %u", symbolicOrConnid, conn_id);
        } else {
            WARN("Symbolic name '%s' could not be resolved", symbolicOrConnid);
        }
    }

    return conn_id;
}

#define symbolic_to_conn_id(config, symbolic) _symbolic_to_conn_id(config, symbolic, false, 0)

#define symbolic_to_conn_id_self(config, symbolic, ingress_id) \
    _symbolic_to_conn_id(config, symbolic, true, ingress_id)

connection_t *
getConnectionBySymbolicOrId(Configuration * config, const char * symbolicOrConnid)
{
    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    unsigned conn_id = symbolic_to_conn_id(config, symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        return NULL;

    /* conn_id is assumed validated here */
    return connection_table_at(table, conn_id);
}

// ========================================================================================

Configuration *
configuration_Create(Forwarder *forwarder)
{
    assert(forwarder);

    Configuration *config = malloc(sizeof(Configuration));
    if (!config)
        return NULL;

    config->forwarder = forwarder;
    config->maximumContentObjectStoreSize = 100000;
    config->strategy_map = parcHashMap_Create(); // XXX
    config->symbolicNameTable = symbolicNameTable_Create();

    return config;
}

void
configuration_Destroy(Configuration * config)
{
    assert(config);

    parcHashMap_Release(&(config->strategy_map));
    symbolicNameTable_Destroy(&config->symbolicNameTable);
    free(config);
}

/* Listener */

uint8_t *
configuration_on_listener_add(Configuration * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_listener_add_t * msg = packet;
    cmd_listener_add_t * control = &msg->payload;

    Forwarder * forwarder = configuration_GetForwarder(config);
    assert(forwarder);

    listener_table_t * table = forwarder_GetListenerTable(forwarder);
    assert(table);

    /* Verify that the listener DOES NOT exist */
    listener_t * listener = listener_table_get_by_name(table, control->symbolic);
    if (listener)
        goto NACK;

    address_t address;
    if (address_from_ip_port(&address, control->family, &control->address,
                control->port) < 0) {
        WARN("Unsupported address type for HICN (ingress id %u): "
                "must be either IPV4 or IPV6", ingressId);
        return false;
    }

    // NOTE: interface_name is expected NULL for hICN listener

    listener_t * listener = listener_create(control->listener_type, &address, control->interface_name, control->symbolic, forwarder);
    if (!listener)
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_listener_remove(Configuration *config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_listener_remove_t * msg = packet;
    cmd_listener_remove_t * control = &msg->payload;

    const char *symbolicOrListenerid = control->symbolicOrListenerid;
    off_t listener_id;
    listener_t * listener;

    listener_table_t * listener_table = forwarder_GetListenerTable(config->forwarder);

    // Factor like for connections
    if (utils_IsNumber(symbolicOrListenerid)) {
        // XXX no check
        int id = atoi(symbolicOrListenerid);
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
    connection_t * connection;
    connection_table_foreach(table, connection, {
        const address_pair_t * pair = connection_get_pair(connection);
        if (!address_equals(listener->get_address(listener),
                    address_pair_get_local(pair)))
            continue;

        unsigned conn_id = connection_table_get_connection_id(table, connection);
        /* Remove connection from the FIB */
        forwarder_RemoveConnectionIdFromRoutes(config->forwarder, conn_id);
        connection_table_remove_by_id(table, conn_id);

        /* Remove connection */
        connection_table_remove_by_id(table, conn_id);

        const char *symbolicConnection =
                symbolicNameTable_GetNameByIndex(config->symbolicNameTable, conn_id);
        symbolicNameTable_Remove(config->symbolicNameTable, symbolicConnection);
    });

    /* Remove listener */
    listener_table_remove_by_id(listener_table, listener_id);

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

static inline
void
fill_listener_command(Configuration * config, listener_t * listener,
        list_listeners_command * cmd)
{
    assert(config);
    assert(listener);
    asser(cmd);

    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;

    const address_t * addr = listener->get_address(listener);

    *cmd = (list_listeners_command) {
        .conn_id = (uint32_t)listener->getInterfaceIndex(listener),
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
    const char * interface_name = listener_interface_name(listener);
    snprintf(cmd->interface_name, SYMBOLIC_NAME_LEN, "%s", interface_name);
}

uint8_t *
configuration_on_listener_list(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    listener_table_t * table = forwarder_GetListenerTable(config->forwarder);
    size_t n = listener_table_len(table);

    msg_listener_list_reply_t * msg;
    msg_malloc_list(msg, n)
    if (!msg)
        return NULL;

    cmd_listener_list_item_t * payload = &msg->payload;
    listener_t * listener;
    listener_table_foreach(table, listener, {
        fill_listeners_command(config, listener, payload);
        payload++;
    });

    return (uint8_t*)msg;
}

/* Connection */

uint8_t *
configuration_on_connection_add(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_connection_add_t * msg = packet;
    cmd_connection_add_t * control = &msg->payload;

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

    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    connection_t * connection = connection_table_lookup(table, &pair);
#ifdef WITH_MAPME
    connection_event_t event;
#endif /* WITH_MAPME */

    if (!connection) {
        connection = connection_create(control->connection_type, pair, config->forwarder);
        if (!connection)
            ERROR("Failed to create %s connection",
                    connection_type_str(connection->type);
            goto NACK;
        }

        unsigned conn_id = connection_get_id(connection);
        symbolicNameTable_Add(config->symbolicNameTable, symbolicName, conn_id);
        conn = *conn_ptr;

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
    connection_SetTags(conn, control->tags);
    connection_SetPriority(conn, control->priority);
#endif /* WITH_POLICY */

    connection_SetAdminState(conn, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: new connection created through the control protocol */
    forwarder_onConnectionEvent(config->forwarder, conn, event);
#endif /* WITH_MAPME */

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}


/**
 * Add an IP-based tunnel.
 *
 * The call can fail if the symbolic name is a duplicate.  It could also fail if
 * there's an problem creating the local side of the tunnel (i.e. the local
 * socket address is not usable).
 *
 * @return true Tunnel added
 * @return false Tunnel not added (an error)
 */

uint8_t *
configuration_on_connection_remove(Configuration *config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_connection_remove_t * msg = packet;
    cmd_connection_remove_t * control = &msg->payload;

    unsigned conn_id = symbolic_to_conn_id_self(config, control->symbolicOrConnid,
            ingress_id);
    if (!ingress_id_is_valid(conn_id))
        goto NACK;

    /* Remove connection from the FIB */
    forwarder_RemoveConnectionIdFromRoutes(config->forwarder, conn_id);

    /* Remove connection */
    connection_table_t *table = forwarder_GetConnectionTable(config->forwarder);
    connection_table_remove_by_id(table, conn_id);

    /* Remove connection from symbolicNameTable */
    const char *symbolicConnection = symbolicNameTable_GetNameByIndex(config->symbolicNameTable, conn_id);
    symbolicNameTable_Remove(config->symbolicNameTable, symbolicConnection);

#ifdef WITH_MAPME
    /* Hook: new connection created through the control protocol */
    forwarder_onConnectionEvent(config->forwarder, NULL, CONNECTION_EVENT_DELETE);
#endif /* WITH_MAPME */

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

#define tolower_str(p) for ( ; *(p); ++(p)) *(p) = tolower(*(p))


void _strlwr(char *string) {
    char *p = string;
    while ((*p = tolower(*p))) {
        p++;
    }
}

static inline
void
fill_connections_command(Configuration * config, connection_t * connection,
        list_connections_command *cmd)
{

    assert(config);
    assert(connection);
    assert(cmd);

    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;
    const address_pair_t * pair = connection_GetAddressPair(connection);
    const char *connectionName = symbolicNameTable_GetNameByIndex(config->symbolicNameTable,
            connection_GetConnectionId(connection));

    *cmd = (list_connections_command) {
        .conn_id = connection_GetConnectionId(connection),
            .state = connection_GetState(connection),
            .connectionData = {
                .admin_state = connection_GetAdminState(connection),
                .connection_type = ioOperations_GetConnectionType(connection_GetIoOperations(connection)),
#ifdef WITH_POLICY
                .priority = connection_GetPriority(connection),
                .tags = connection_GetTags(connection),
#endif /* WITH_POLICY */
            }
    };

    snprintf(cmd->connectionName, SYMBOLIC_NAME_LEN, "%s", connectionName);
    tolower_str(cmd->connectionName);
    for ( ; *p; ++p) *p = tolower(*p);


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

uint8_t *
configuration_on_connection_list(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    connection_table_t *table = forwarder_GetConnectionTable(config->forwarder);
    size_t n = connection_table_len(table);

    msg_connection_list_reply__t * msg;
    msg_malloc_list(msg, n)
    if (!msg)
        return NULL;

    cmd_connection_list_item_t * payload = &msg->payload;
    connection_t * connection;
    connection_table_foreach(table, connection, {
        fill_connections_command(config, connection, payload);
        payload++;
    });

    return (uint8_t*)msg;
}

uint8_t *
configuration_on_connection_set_admin_state(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_connection_set_admin_state_t * msg = packet;
    cmd_connection_set_admin_state_t *control = &msg->payload;

    if ((control->admin_state != CONNECTION_STATE_UP) &&
            (control->admin_state != CONNECTION_STATE_DOWN))
        goto NACK;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_SetAdminState(conn, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            control->admin_state == CONNECTION_STATE_UP
            ? CONNECTION_EVENT_SET_UP
            : CONNECTION_EVENT_SET_DOWN);
#endif /* WITH_MAPME */

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}


uint8_t *
configuration_on_connection_update(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_update_t * msg = packet;
    cmd_connection_update_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_SetTags(conn, control->tags);
    connection_SetAdminState(conn, control->admin_state);
    if (control->priority > 0)
        connection_SetPriority(conn, control->priority);

    make_ack(packet);
    return packet;

NACK:
#endif /* WITH_POLICY */
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_connection_set_priority(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_set_priority_t * msg = packet;
    cmd_connection_set_priority_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_SetPriority(conn, control->priority);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            CONNECTION_EVENT_PRIORITY_CHANGED);
#endif /* WITH_MAPME */

    make_ack(packet);
    return packet;

NACK:
#endif /* WITH_POLICY */
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_connection_set_tags(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_set_tags_t * msg = packet;
    cmd_connection_set_tags_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_SetTags(conn, control->tags);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_onConnectionEvent(config->forwarder, conn,
            CONNECTION_EVENT_TAGS_CHANGED);
#endif /* WITH_MAPME */

    make_ack(packet);
    return packet;

NACK:
#endif /* WITH_POLICY */
    make_nack(packet);
    return packet;
}


/* Route */

uint8_t *
configuration_on_route_add(Configuration *config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_route_add_t * msg = packet;
    cmd_route_add_t * control = &msg->payload;

    unsigned ingress_id = symbolic_to_ingress_id_self(config,
            control->symbolicOrConnid, ingress_id);
    if (!connection_id_is_valid(ingress_id))
        goto NACK;

    if (!forwarder_add_or_update_route(config->forwarder, control, ingress_id))
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_route_remove(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_route_remove_t * msg = packet;
    cmd_route_remove_t * control = &msg->payload;

    unsigned conn_id = symbolic_to_conn_id(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    if (!forwarder_remove_route(config->forwarder, control, conn_id))
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_route_list(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

    // XXX TODO iterator !
    fib_entry_list_t *fibList = forwarder_GetFibEntries(config->forwarder);
    size_t fib_size = fib_entry_list_Length(fibList);

    /*
     * Two step approach to precompute the number of entries to allocate
     *
     * NOTE: we might have routes with no or multiple next hops.
     */
    size_t n;
    for (size_t i = 0; i < fib_size; i++) {
        const fib_entry_t *fib_entry = fib_entry_list_Get(fibList, i);
        const nexthops_t * nexthops = fib_entry_nexthops(fib_entry);
        assert(nexthops_len(nexthops) == nexthops_curlen(nexthops));
        n += nexthops_len(nexthops);
    }

    msg_route_list_reply_t * msg;
    msg_malloc_list(msg, n);
    if (!msg)
        return NULL;

    cmd_list_route_item_t * payload = &msg->payload;
    for (size_t i = 0; i < fib_size; i++) {
        const fib_entry_t *fib_entry = fib_entry_list_Get(fibList, i);

        const nexthops_t * nexthops = fib_entry_nexthops(fib_entry);
        assert(nexthops_len(nexthops) == nexthops_curlen(nexthops));
        size_t num_nexthops = nexthops_len(nexthops);

        if (num_nexthops == 0)
            continue;

        NameBitvector *prefix = name_GetContentName(fib_entry_GetPrefix(fib_entry));

        unsigned nexthop;
        nexthops_foreach(nexthops, nexthop, {

            address_t address;
            nameBitvector_ToAddress(prefix, &address);
            switch(address_family(&address)) {
                case AF_INET:
                    payload->family = AF_INET;
                    payload->address.v4.as_inaddr = address4_ip(&address);
                    break;
                case AF_INET6:
                    payload->family = AF_INET6;
                    payload->address.v6.as_in6addr = address6_ip(&address);
                    break;
                default:
                    break;
            }
            payload->conn_id = nexthop;
            payload->len = nameBitvector_GetLength(prefix);
            payload->cost = DEFAULT_COST;

            payload++;
        });
    }

    fib_entry_list_Destroy(&fibList);

    return (uint8_t*)msg;
}


/* Cache */

uint8_t *
configuration_on_cache_set_store(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_cache_set_store_t * msg = packet;
    cmd_cache_set_store_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    forwarder_cache_set_store_flag(config->forwarder, value);
    /* XXX Why do we need to check ? */
    if (forwarder_cache_get_store_flag(config->forwarder) != value)
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_cache_set_serve(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_cache_set_serve_t * msg = packet;
    cmd_cache_set_serve_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    forwarder_cache_set_serve_flag(config->forwarder, value);
    /* XXX Why do we need to check ? */
    if (forwarder_cache_get_serve_flag(config->forwarder) != value)
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_cache_clear(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    forwarder_cache_clear(config->forwarder);

    make_ack(packet);
    return packet;
}

/* Strategy */

uint8_t *
configuration_on_strategy_set(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_strategy_set_t * msg = packet;
    cmd_strategy_set_t * control = &ùsg->payload;

    const char *prefix = utils_PrefixLenToString( control->family,
            &control->address, &control->len);
    strategy_type_t strategy = control->strategy_type;
    strategy_type_t existingFwdStrategy =
        configuration_GetForwardingStrategy(config, prefix);

    strategy_options_t options;

    if (existingFwdStrategy == STRATEGY_TYPE_UNDEFINED ||
            strategy != existingFwdStrategy) {
        // means such a new strategy is not present in the hash table or has to be
        // updated
        _configuration_StoreFwdStrategy(config, prefix, strategy);
        Name *hicnPrefix = name_CreateFromAddress(control->family,
                control->address, control->len);

        switch(control->strategy_type) {
            case STRATEGY_TYPE_LOW_LATENCY:
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

                if (control->related_prefixes != 0) {
                    for(int i = 0; i < control->related_prefixes; i++)
                        name_Release(&related_prefixes[i]);
                }
                break;
            default:
                break;
        }
        name_Release(&hicnPrefix);
    }

    free(prefix);
    make_ack(packet);
    return packet;
}

/* WLDR */

uint8_t *
configuration_on_wldr_set(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_wldr_set_t * msg = packet;
    cmd_wldr_set_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    unsigned conn_id = symbolic_to_conn_id(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    connection_t * conn = connection_table_at(table, conn_id);

    if (value)
        connection_EnableWldr(conn);
    else
        connection_DisableWldr(conn);

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}


/* MAP-Me */

uint8_t *
configuration_on_mapme_enable(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_mapme_activator_t * msg = packet;
    cmd_mapme_activator_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    INFO("MAP-Me SET enable: %s", value ? "on" : "off");

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_mapme_set_disovery(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_mapme_activator_t * msg = packet;
    cmd_mapme_activator_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    INFO("MAP-Me SET discovery: %s", value ? "on" : "off");

    make_ack(packet);
    return packet;

NACK:
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_mapme_set_timescale(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_mapme_timing_t * msg = packet;
    cmd_mapme_timing_t * control = &msg->payload;

    INFO("MAP-Me SET timescale: %u", control->timePeriod);

    make_ack(packet);
    return packet;
}

uint8_t *
configuration_on_mapme_set_retx(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

    msg_mapme_timing_t * msg = packet;
    cmd_mapme_timing_t * control = &msg->payload;

    INFO("MAP-Me SET retx: %u", control->timePeriod);

    make_ack(packet);
    return packet;
}


uint8_t *
configuration_on_mapme_send_update(Configuration *config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_send_update_t * msg = packet;
    cmd_mapme_send_update_t * control = &msg->control;

    FIB * fib = forwarder_getFib(config->forwarder);
    if (!fib)
        goto NACK;
    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    if (!prefix)
        goto NACK;
    fib_entry_t *entry = fib_Contains(fib, prefix);
    name_Release(&prefix);
    if (!entry)
        goto NACK;

    const nexthops_t * nexthops = fib_entry_nexthops(entry);

    /* The command is accepted iif triggered by (one of) the producer of this prefix */
    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        if (nexthop != ingress_id)
            continue;
        MapMe * mapme = forwarder_getMapmeInstance(config->forwarder);
        mapme_send_updates(mapme, entry, nexthops);
        make_ack(packet);
        return packet;
    });

NACK:
    make_nack(packet);
    return packet;
}

/* Policy */

uint8_t *
configuration_on_policy_add(Configuration *config, uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_policy_add_t * msg = packet;
    cmd_policy_add_t * control = &msg->payload;

    if (!forwarder_add_or_update_policy(config->forwarder, control))
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
#endif /* WITH_POLICY */
    make_nack(packet);
    return packet;
}


uint8_t *
configuration_on_policy_remove(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_policy_remove_t * msg = packet;
    cmd_policy_remove_t * control = &msg->payload;

    if (!forwarder_RemovePolicy(config->forwarder, control))
        goto NACK;

    make_ack(packet);
    return packet;

NACK:
#endif /* WITH_POLICY */
    make_nack(packet);
    return packet;
}

uint8_t *
configuration_on_policy_list(Configuration *config,
        uint8_t * packet)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    fib_entry_list_t *fibList = forwarder_GetFibEntries(config->forwarder);

    size_t n = fib_entry_list_Length(fibList);

    msg_policy_list_reply_t * msg;
    msg_malloc_list(msg, n);
    if (!msg)
        return NULL;

    cmd_policy_list_item_t * payload = &msg->payload;

    for (size_t i = 0; i < n; i++) {
        const fib_entry_t *fib_entry = fib_entry_list_Get(fibList, i);

        NameBitvector *prefix = name_GetContentName(fib_entry_GetPrefix(entry));
        address_t address;
        nameBitvector_ToAddress(prefix, &address);

        switch(address_family(&address)) {
            case AF_INET:
                payload->family = AF_INET;
                payload->address.v4.as_inaddr = address4_ip(&address);
                break;

            case AF_INET6:
                payload->family = AF_INET6;
                payload->address.v6.as_in6addr = address6_ip(&address);
                break;

            default:
                break;
        }
        payload->len = nameBitvector_GetLength(prefix);
        payload->policy = fib_entry_get_policy(entry);

        payload++;
    }

    fib_entry_list_Destroy(&fibList);
    return (uint8_t*)msg;
#else
    return NULL;
#endif /* WITH_POLICY */
}

strategy_type_t
configuration_GetForwardingStrategy(Configuration *config,
        const char *prefix)
{
    PARCString *prefixStr = parcString_Create(prefix);
    const unsigned *val = parcHashMap_Get(config->strategy_map, prefixStr);
    parcString_Release(&prefixStr);

    if (val == NULL) {
        return STRATEGY_TYPE_UNDEFINED;
    } else {
        return (strategy_type_t)*val;
    }
}


// XXX NOTHING TO DO HERE ?
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


void configuration_SetObjectStoreSize(Configuration *config,
        size_t maximumObjectCount) {
    config->maximumContentObjectStoreSize = maximumObjectCount;

    forwarder_SetContentObjectStoreSize(config->forwarder,
            config->maximumContentObjectStoreSize);
}

Forwarder *configuration_GetForwarder(const Configuration *config) {
    return config->forwarder;
}


// ===========================
// Main functions that deal with receiving commands, executing them, and sending
// ACK/NACK

uint8_t *
configuration_DispatchCommand(Configuration *config, command_type_t command_type,
        uint8_t * packet, unsigned ingress_id)
{
    switch (command_type) {
#define _(l, u)                                                         \
        case COMMAND_TYPE_ ## u:                                        \
            return configuration_on_ ## l(config, packet, ingress_id);
    foreach_command_type
#undef _
        case COMMAND_TYPE_UNDEFINED:
        case COMMAND_TYPE_N:
            ERROR("Unexpected command type");
            break;
    }

    return response;
}

void configuration_ReceiveCommand(Configuration *config,
        command_type_t command_type, uint8_t * packet, unsigned conn_id)
{
    assert(config);
    assert(command_type_is_valid(command_type));
    assert(packet);

    bool nack = false;

    uint8_t * reply = configuration_DispatchCommand(config, command_type, reply, conn_id);
    if (!reply) {
        reply = packet;
        make_nack(reply);
        nack = true;
    }

    connection_table_t * table = forwarder_GetConnectionTable(config->forwarder);
    const connection_t *conn = connection_table_at(table, conn_id);
    connection_send_reply(connection, reply);

    switch (command_type) {
        case LIST_LISTENERS:
        case LIST_CONNECTIONS:
        case LIST_ROUTES:
        case LIST_POLICIES:
            if (!nack)
                free(reply);
            break;
        default:
            break;
    }
}
