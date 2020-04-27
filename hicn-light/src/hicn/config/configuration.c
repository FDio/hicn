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
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hicn/core/connection.h>
#include <hicn/core/connection_table.h>
#include <hicn/core/forwarder.h>
//#include <hicn/core/system.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#include <hicn/core/listener.h>     //the listener list
#include <hicn/core/listener_table.h>
#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>
#include <hicn/utils/punting.h>
#include <hicn/util/log.h>
#include <hicn/face.h>

#define ETHERTYPE 0x0801
#define DEFAULT_COST 1
#define DEFAULT_PORT 1234

#define make_ack(msg)  msg->header.messageType =  ACK_LIGHT
#define make_nack(msg) msg->header.messageType = NACK_LIGHT

#define msg_malloc_list(msg, N)                                         \
do {                                                                    \
    msg = malloc(sizeof((msg)->header) + N * sizeof((msg)->payload));   \
    (msg)->header.messageType = RESPONSE_LIGHT;                         \
    (msg)->header.length = (uint16_t)(N);                               \
} while(0);

/*
 * XXX TODO
 *
 * Currently the strategy map only stores the strategy type, but it should be
 * extended with strategy options.
 *
 * Or maybe we simply remove this map like in VPP.
 *
 * prefix_str -> strategy_type
 */
KHASH_INIT(strategy_map, const char *, unsigned, 0, str_hash, str_hash_eq);

struct configuration_s {
    forwarder_t * forwarder;

    size_t maximumContentObjectStoreSize;

    // map from prefix (parcString) to strategy (parcString)
    kh_strategy_map_t * strategy_map;

#if 0
    // translates between a symblic name and a connection id
    // XXX This might be moved as two indices in the listener and connection
    // tables to be widely reachable... this has nothing to do with
    // configuration.
    SymbolicNameTable *symbolic_nameTable;
#endif
};

// ========================================================================================

// conn_id = UINT_MAX when symbolic_name is not found
static inline
unsigned
_symbolic_to_conn_id(configuration_t * config, const char * symbolicOrConnid,
        bool allow_self, unsigned ingress_id)
{
    unsigned conn_id;
    const connection_table_t * table = forwarder_get_connection_table(config->forwarder);

    if (allow_self && strcmp(symbolicOrConnid, "SELF") == 0) {
        conn_id = ingress_id;
    } else if (utils_IsNumber(symbolicOrConnid)) {
        // case for conn_id as input
        // XXX type issue ! XXX No check, see man
        int id = atoi(symbolicOrConnid);
        if (id < 0)
            return CONNECTION_ID_UNDEFINED;
        conn_id = id;

        if (!connection_table_validate_id(table, conn_id)) {
            ERROR("ConnID not found, check list connections");
            conn_id = CONNECTION_ID_UNDEFINED;
        }
    } else {
        // case for symbolic as input: check if symbolic name can be resolved
        conn_id = connection_table_get_id_by_name(table, symbolicOrConnid);
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
getConnectionBySymbolicOrId(configuration_t * config, const char * symbolicOrConnid)
{
    connection_table_t * table = forwarder_get_connection_table(config->forwarder);
    unsigned conn_id = symbolic_to_conn_id(config, symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        return NULL;

    /* conn_id is assumed validated here */
    return connection_table_at(table, conn_id);
}

// ========================================================================================

configuration_t *
configuration_create(forwarder_t * forwarder)
{
    assert(forwarder);

    configuration_t * config = malloc(sizeof(configuration_t));
    if (!config)
        return NULL;

    config->forwarder = forwarder;
    config->maximumContentObjectStoreSize = 100000;
    config->strategy_map = kh_init_strategy_map();
#if 0
    config->symbolic_nameTable = symbolic_nameTable_Create();
#endif

    return config;
}

void
configuration_free(configuration_t * config)
{
    assert(config);

    kh_destroy_strategy_map(config->strategy_map);
#if 0
    symbolic_nameTable_Destroy(&config->symbolic_nameTable);
#endif
    free(config);
}

/* Listener */

uint8_t *
configuration_on_listener_add(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_listener_add_t * msg = (msg_listener_add_t *)packet;
    cmd_listener_add_t * control = &msg->payload;

    forwarder_t * forwarder = configuration_get_forwarder(config);
    assert(forwarder);

    listener_table_t * table = forwarder_get_listener_table(forwarder);
    assert(table);

    /* Verify that the listener DOES NOT exist */
    listener_t * listener = listener_table_get_by_name(table, control->symbolic);
    if (listener)
        goto NACK;

    address_t address;
    if (address_from_ip_port(&address, control->family, &control->address,
                control->port) < 0) {
        WARN("Unsupported address type for HICN (ingress id %u): "
                "must be either IPV4 or IPV6", ingress_id);
        return false;
    }

    // NOTE: interface_name is expected NULL for hICN listener
    face_type_t face_type;
    if (!face_type_is_defined(control->listener_type))
        goto NACK;
    face_type = (face_type_t)control->listener_type;


    listener = listener_create(face_type, &address, control->interface_name, control->symbolic, forwarder);
    if (!listener)
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_listener_remove(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_listener_remove_t * msg = (msg_listener_remove_t*)packet;
    cmd_listener_remove_t * control = &msg->payload;

    const char *symbolicOrListenerid = control->symbolicOrListenerid;
    off_t listener_id;
    listener_t * listener;

    listener_table_t * listener_table = forwarder_get_listener_table(config->forwarder);

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

    connection_table_t * table = forwarder_get_connection_table(config->forwarder);
    connection_t * connection;
    connection_table_foreach(table, connection, {
        const address_pair_t * pair = connection_get_pair(connection);
        if (!address_equals(listener_get_address(listener),
                    address_pair_get_local(pair)))
            continue;

        unsigned conn_id = connection_table_get_connection_id(table, connection);
        /* Remove connection from the FIB */
        forwarder_remove_connection_id_from_routes(config->forwarder, conn_id);

        /* Remove connection */
        connection_table_remove_by_id(table, conn_id);

#if 0
        const char *symbolicConnection =
                symbolic_nameTable_GetNameByIndex(config->symbolic_nameTable, conn_id);
        symbolic_nameTable_Remove(config->symbolic_nameTable, symbolicConnection);
#endif
    });

    /* Remove listener */
    listener_table_remove_by_id(listener_table, listener_id);

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

static inline
void
fill_listener_command(configuration_t * config, listener_t * listener,
        cmd_listener_list_item_t * cmd)
{
    assert(config);
    assert(listener);
    assert(cmd);

    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;

    const address_t * addr = listener_get_address(listener);

    cmd->id = (uint32_t)listener_get_id(listener);
    cmd->type = (uint8_t)listener_get_type(listener);

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

    const char * name = listener_get_name(listener);
    snprintf(cmd->name, SYMBOLIC_NAME_LEN, "%s", name);
    const char * interface_name = listener_get_interface_name(listener);
    snprintf(cmd->interface_name, SYMBOLIC_NAME_LEN, "%s", interface_name);
}

uint8_t *
configuration_on_listener_list(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    listener_table_t * table = forwarder_get_listener_table(config->forwarder);
    size_t n = listener_table_len(table);

    msg_listener_list_reply_t * msg;
    msg_malloc_list(msg, n)
    if (!msg)
        return NULL;

    cmd_listener_list_item_t * payload = &msg->payload;
    listener_t * listener;
    listener_table_foreach(table, listener, {
        fill_listener_command(config, listener, payload);
        payload++;
    });

    return (uint8_t*)msg;
}

/* Connection */

uint8_t *
configuration_on_connection_add(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_connection_add_t * msg = (msg_connection_add_t*)packet;
    cmd_connection_add_t * control = &msg->payload;

    const char *symbolic_name = control->symbolic;

    face_type_t face_type;
    if (!face_type_is_defined(control->type))
        goto NACK;
    face_type = (face_type_t)control->type;

    connection_table_t * table = forwarder_get_connection_table(config->forwarder);
    if (connection_table_get_by_name(table, symbolic_name)) {
        ERROR("Connection symbolic name already exists");
        goto NACK;
    }

    address_pair_t pair;
    if (address_pair_from_ip_port(&pair, control->family,
                &control->local_ip, control->local_port,
                &control->remote_ip, control->remote_port) < 0)
        goto NACK;

    connection_t * connection = connection_table_get_by_pair(table, &pair);
#ifdef WITH_MAPME
    connection_event_t event;
#endif /* WITH_MAPME */

    if (!connection) {
        connection = connection_create(face_type, symbolic_name, &pair, config->forwarder);
        if (!connection) {
            ERROR("Failed to create %s connection",
                    face_type_str(connection->type));
            goto NACK;
        }

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
    connection_set_tags(connection, control->tags);
    connection_set_priority(connection, control->priority);
#endif /* WITH_POLICY */

    connection_set_admin_state(connection, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: new connection created through the control protocol */
    forwarder_on_connection_event(config->forwarder, connection, event);
#endif /* WITH_MAPME */

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
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
configuration_on_connection_remove(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_connection_remove_t * msg = (msg_connection_remove_t*)packet;
    cmd_connection_remove_t * control = &msg->payload;

    unsigned conn_id = symbolic_to_conn_id_self(config, control->symbolicOrConnid,
            ingress_id);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    /* Remove connection from the FIB */
    forwarder_remove_connection_id_from_routes(config->forwarder, conn_id);

    /* Remove connection */
    connection_table_t *table = forwarder_get_connection_table(config->forwarder);
    connection_table_remove_by_id(table, conn_id);

#if 0
    /* Remove connection from symbolic_nameTable */
    const char *symbolicConnection = symbolic_nameTable_GetNameByIndex(config->symbolic_nameTable, conn_id);
    symbolic_nameTable_Remove(config->symbolic_nameTable, symbolicConnection);
#endif

#ifdef WITH_MAPME
    /* Hook: new connection created through the control protocol */
    forwarder_on_connection_event(config->forwarder, NULL, CONNECTION_EVENT_DELETE);
#endif /* WITH_MAPME */

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

static inline
void
tolower_str(char * str) {
    char * p = str;
    for (; *p; p++)
        *p = tolower(*p);
}

static inline
void
fill_connections_command(configuration_t * config, connection_t * connection,
        cmd_connection_list_item_t * cmd)
{

    assert(config);
    assert(connection);
    assert(cmd);

    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;
    const address_pair_t * pair = connection_get_pair(connection);
#if 0
    const char *name = symbolic_nameTable_GetNameByIndex(config->symbolic_nameTable,
            connection_get_id(connection));
#endif

    *cmd = (cmd_connection_list_item_t) {
        .id = connection_get_id(connection),
        .state = connection_get_state(connection),
        .admin_state = connection_get_admin_state(connection),
        .type = connection_get_type(connection),
#ifdef WITH_POLICY
        .priority = connection_get_priority(connection),
        .tags = connection_get_tags(connection),
#endif /* WITH_POLICY */
    };

    snprintf(cmd->name, SYMBOLIC_NAME_LEN, "%s", connection_get_name(connection));
    tolower_str(cmd->name);

    snprintf(cmd->interface_name, SYMBOLIC_NAME_LEN, "%s",
            connection_get_interface_name(connection));

    switch(pair->local.ss_family) {
        case AF_INET:
            cmd->family = AF_INET;

            sin = (struct sockaddr_in *)(&pair->local);
            cmd->local_port = sin->sin_port;
            cmd->local_ip.v4.as_inaddr = sin->sin_addr;

            sin = (struct sockaddr_in *)(&pair->remote);
            cmd->remote_port = sin->sin_port;
            cmd->remote_ip.v4.as_inaddr = sin->sin_addr;
            break;

        case AF_INET6:
            cmd->family = AF_INET6;

            sin6 = (struct sockaddr_in6 *)(&pair->local);
            cmd->local_port = sin6->sin6_port;
            cmd->local_ip.v6.as_in6addr = sin6->sin6_addr;

            sin6 = (struct sockaddr_in6 *)(&pair->remote);
            cmd->remote_port = sin6->sin6_port;
            cmd->remote_ip.v6.as_in6addr = sin6->sin6_addr;
            break;

        default:
            break;
    }
}

uint8_t *
configuration_on_connection_list(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    connection_table_t *table = forwarder_get_connection_table(config->forwarder);
    size_t n = connection_table_len(table);

    msg_connection_list_reply_t * msg;
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
configuration_on_connection_set_admin_state(configuration_t * config,
        uint8_t * packet, unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_connection_set_admin_state_t * msg = (msg_connection_set_admin_state_t *)packet;
    cmd_connection_set_admin_state_t *control = &msg->payload;

    if ((control->admin_state != FACE_STATE_UP) &&
            (control->admin_state != FACE_STATE_DOWN))
        goto NACK;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_set_admin_state(conn, control->admin_state);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_on_connection_event(config->forwarder, conn,
            control->admin_state == FACE_STATE_UP
            ? CONNECTION_EVENT_SET_UP
            : CONNECTION_EVENT_SET_DOWN);
#endif /* WITH_MAPME */

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}


uint8_t *
configuration_on_connection_update(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_update_t * msg = (msg_connection_update_t *)packet;
    cmd_connection_update_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_set_tags(conn, control->tags);
    connection_set_admin_state(conn, control->admin_state);
    if (control->priority > 0)
        connection_set_priority(conn, control->priority);

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif /* WITH_POLICY */
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_connection_set_priority(configuration_t * config,
        uint8_t * packet, unsigned ingress_id)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_set_priority_t * msg = (msg_connection_set_priority_t *)packet;
    cmd_connection_set_priority_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_set_priority(conn, control->priority);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_on_connection_event(config->forwarder, conn,
            CONNECTION_EVENT_PRIORITY_CHANGED);
#endif /* WITH_MAPME */

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif /* WITH_POLICY */
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_connection_set_tags(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_connection_set_tags_t * msg = (msg_connection_set_tags_t *)packet;
    cmd_connection_set_tags_t * control = &msg->payload;

    connection_t * conn = getConnectionBySymbolicOrId(config, control->symbolicOrConnid);
    if (!conn)
        goto NACK;

    connection_set_tags(conn, control->tags);

#ifdef WITH_MAPME
    /* Hook: connection event */
    forwarder_on_connection_event(config->forwarder, conn,
            CONNECTION_EVENT_TAGS_CHANGED);
#endif /* WITH_MAPME */

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif /* WITH_POLICY */
    make_ack(msg);
    return (uint8_t*)msg;
}


/* Route */

uint8_t *
configuration_on_route_add(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_route_add_t * msg = (msg_route_add_t *)packet;
    cmd_route_add_t * control = &msg->payload;

    unsigned conn_id = symbolic_to_conn_id_self(config,
            control->symbolicOrConnid, ingress_id);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len
    };

    if (!forwarder_add_or_update_route(config->forwarder, &prefix, conn_id))
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_route_remove(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_route_remove_t * msg = (msg_route_remove_t *)packet;
    cmd_route_remove_t * control = &msg->payload;

    unsigned conn_id = symbolic_to_conn_id(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len
    };

    if (!forwarder_remove_route(config->forwarder, &prefix, conn_id))
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_route_list(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    const fib_t * fib = forwarder_get_fib(config->forwarder);
    fib_entry_t * entry;

    /*
     * Two step approach to precompute the number of entries to allocate
     *
     * NOTE: we might have routes with no or multiple next hops.
     */
    size_t n = 0;
    fib_foreach_entry(fib, entry, {
        const nexthops_t * nexthops = fib_entry_get_nexthops(entry);
        assert(nexthops_get_len(nexthops) == nexthops_get_curlen(nexthops));
        n += nexthops_get_len(nexthops);
    });

    msg_route_list_reply_t * msg;
    msg_malloc_list(msg, n);
    if (!msg)
        return NULL;

    cmd_route_list_item_t * payload = &msg->payload;
    fib_foreach_entry(fib, entry, {
        const nexthops_t * nexthops = fib_entry_get_nexthops(entry);
        assert(nexthops_get_len(nexthops) == nexthops_get_curlen(nexthops));
        size_t num_nexthops = nexthops_get_len(nexthops);

        if (num_nexthops == 0)
            continue;

        NameBitvector *prefix = name_GetContentName(fib_entry_get_prefix(entry));

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
            payload->connection_id = nexthop;
            payload->len = nameBitvector_GetLength(prefix);
            payload->cost = DEFAULT_COST;

            payload++;
        });
    });

    return (uint8_t*)msg;
}


/* Cache */

uint8_t *
configuration_on_cache_set_store(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_cache_set_store_t * msg = (msg_cache_set_store_t *)packet;
    cmd_cache_set_store_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    forwarder_content_store_set_store(config->forwarder, value);
    /* XXX Why do we need to check ? */
    if (forwarder_content_store_get_store(config->forwarder) != value)
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_cache_set_serve(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_cache_set_serve_t * msg = (msg_cache_set_serve_t *)packet;
    cmd_cache_set_serve_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    forwarder_content_store_set_serve(config->forwarder, value);
    /* XXX Why do we need to check ? */
    if (forwarder_content_store_get_serve(config->forwarder) != value)
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_cache_clear(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_cache_clear_t * msg = (msg_cache_clear_t *)packet;

    forwarder_content_store_clear(config->forwarder);

    make_ack(msg);
    return (uint8_t*)msg;
}

/* Strategy */

strategy_type_t
configuration_get_strategy(configuration_t * config, const char *prefix)
{
    khiter_t k = kh_get_strategy_map(config->strategy_map, prefix);
    if (k == kh_end(config->strategy_map))
        return STRATEGY_TYPE_UNDEFINED;
    return kh_val(config->strategy_map, k);
}

uint8_t *
configuration_on_strategy_set(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_strategy_set_t * msg = (msg_strategy_set_t *)packet;
    cmd_strategy_set_t * control = &msg->payload;

    char prefix_s[MAXSZ_IP_PREFIX];
    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len,
    };
    int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, &prefix);
    assert(rc < MAXSZ_IP_PREFIX);
    if (rc < 0)
        goto NACK;

    strategy_type_t strategy = control->strategy_type;
    strategy_type_t existingFwdStrategy =
        configuration_get_strategy(config, prefix_s);

    strategy_options_t options;

    if (existingFwdStrategy == STRATEGY_TYPE_UNDEFINED ||
            strategy != existingFwdStrategy) {
        // means such a new strategy is not present in the hash table or has to be
        // updated
        int res;
        khiter_t k = kh_put_strategy_map(config->strategy_map, prefix_s, &res);
        kh_value(config->strategy_map, k) = strategy;

        Name *name_prefix = name_CreateFromAddress(control->family,
                control->address, control->len);
        // XXX TODO error handling

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
                    // XXX TODO error handling
                }
                forwarder_set_strategy(config->forwarder, name_prefix, strategy, &options);

                if (control->related_prefixes != 0) {
                    for(int i = 0; i < control->related_prefixes; i++)
                        name_Release(&related_prefixes[i]);
                }
                break;
            default:
                break;
        }
        name_Release(&name_prefix);
    }

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_nack(msg);
    return (uint8_t*)msg;
}

/* WLDR */

uint8_t *
configuration_on_wldr_set(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_wldr_set_t * msg = (msg_wldr_set_t *)packet;
    cmd_wldr_set_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    unsigned conn_id = symbolic_to_conn_id(config, control->symbolicOrConnid);
    if (!connection_id_is_valid(conn_id))
        goto NACK;

    connection_table_t * table = forwarder_get_connection_table(config->forwarder);
    connection_t * conn = connection_table_at(table, conn_id);

    if (value)
        connection_wldr_enable(conn, value);

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

/* Punting */

uint8_t *
configuration_on_punting_add(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
    msg_punting_add_t * msg = (msg_punting_add_t *)packet;
    cmd_punting_add_t * control = &msg->payload;

    if (ip_address_empty(&control->address))
        goto NACK;

    /* This is for hICN listeners only */
    // XXX add check !
    // comments:
    // EncapType: I use the Hicn encap since the punting is available only for
    // Hicn listeners LocalAddress: The only listern for which we need punting
    // rules is the main one, which has no address
    //              so I create a fake empty address. This need to be consistent
    //              with the address set at creation time
    address_t fakeaddr;
    memset(&fakeaddr, 0, sizeof(address_t));
    fakeaddr = ADDRESS_ANY(control->family, DEFAULT_PORT);

    forwarder_t * forwarder = configuration_get_forwarder(config);
    listener_table_t * table = forwarder_get_listener_table(forwarder);
    listener_t * listener = listener_table_get_by_address(table, FACE_TYPE_HICN, &fakeaddr);
    if (!listener) {
        ERROR("the main listener does not exist");
        goto NACK;
    }


    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len
    };
    char prefix_s[MAXSZ_IP_PREFIX];
    int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, &prefix);
    assert(rc < MAXSZ_IP_PREFIX);
    if (rc < 0)
        goto NACK;

    if (listener_punt(listener, prefix_s) < 0) {
        ERROR("error while adding the punting rule\n");
        goto NACK;
    }

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif
    make_ack(msg);
    return (uint8_t*)msg;
}

/* MAP-Me */

uint8_t *
configuration_on_mapme_enable(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_enable_t * msg = (msg_mapme_enable_t *)packet;
    cmd_mapme_enable_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    INFO("MAP-Me SET enable: %s", value ? "on" : "off");

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_mapme_set_discovery(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_set_discovery_t * msg = (msg_mapme_set_discovery_t *)packet;
    cmd_mapme_set_discovery_t * control = &msg->payload;

    if ((control->activate != 0) && (control->activate != 1))
        goto NACK;
    bool value = (bool)control->activate;

    INFO("MAP-Me SET discovery: %s", value ? "on" : "off");

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_mapme_set_timescale(configuration_t * config, uint8_t * packet,
    unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_set_timescale_t * msg = (msg_mapme_set_timescale_t *)packet;
    cmd_mapme_set_timescale_t * control = &msg->payload;

    INFO("MAP-Me SET timescale: %u", control->timePeriod);

    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_mapme_set_retx(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_set_retx_t * msg = (msg_mapme_set_retx_t *)packet;
    cmd_mapme_set_retx_t * control = &msg->payload;

    INFO("MAP-Me SET retx: %u", control->timePeriod);

    make_ack(msg);
    return (uint8_t*)msg;
}


uint8_t *
configuration_on_mapme_send_update(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    msg_mapme_send_update_t * msg = (msg_mapme_send_update_t *)packet;
    cmd_mapme_send_update_t * control = &msg->payload;

    fib_t * fib = forwarder_get_fib(config->forwarder);
    if (!fib)
        goto NACK;
    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    if (!prefix)
        goto NACK;
    fib_entry_t *entry = fib_contains(fib, prefix);
    name_Release(&prefix);
    if (!entry)
        goto NACK;

    /* The command is accepted iif triggered by (one of) the producer of this prefix */
    const nexthops_t * nexthops = fib_entry_get_nexthops(entry);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        if (nexthop != ingress_id)
            continue;
        mapme_t * mapme = forwarder_get_mapme(config->forwarder);
        mapme_send_to_all_nexthops(mapme, entry);
        make_ack(msg);
        return (uint8_t*)msg;
    });

NACK:
    make_ack(msg);
    return (uint8_t*)msg;
}

/* Policy */

uint8_t *
configuration_on_policy_add(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_policy_add_t * msg = (msg_policy_add_t *)packet;
    cmd_policy_add_t * control = &msg->payload;

    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len
    };

    if (!forwarder_add_or_update_policy(config->forwarder, &prefix, &control->policy))
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif /* WITH_POLICY */
    make_ack(msg);
    return (uint8_t*)msg;
}


uint8_t *
configuration_on_policy_remove(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

#ifdef WITH_POLICY
    msg_policy_remove_t * msg = (msg_policy_remove_t *)packet;
    cmd_policy_remove_t * control = &msg->payload;

    ip_prefix_t prefix = {
        .family = control->family,
        .address = control->address,
        .len = control->len
    };

    if (!forwarder_remove_policy(config->forwarder, &prefix))
        goto NACK;

    make_ack(msg);
    return (uint8_t*)msg;

NACK:
#endif /* WITH_POLICY */
    make_ack(msg);
    return (uint8_t*)msg;
}

uint8_t *
configuration_on_policy_list(configuration_t * config, uint8_t * packet,
        unsigned ingress_id)
{
    assert(config);
    assert(packet);

    const fib_t * fib = forwarder_get_fib(config->forwarder);
    assert(fib);
    size_t n = fib_get_size(fib);

#ifdef WITH_POLICY
    msg_policy_list_reply_t * msg;
    msg_malloc_list(msg, n);
    if (!msg)
        return NULL;

    cmd_policy_list_item_t * payload = &msg->payload;

    fib_entry_t * entry;

    fib_foreach_entry(fib, entry, {
        NameBitvector *prefix = name_GetContentName(fib_entry_get_prefix(entry));
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
    });

    return (uint8_t*)msg;
#else
    return NULL;
#endif /* WITH_POLICY */
}

size_t
configuration_content_store_get_size(configuration_t * config)
{
    return config->maximumContentObjectStoreSize;
}

void
configuration_content_store_set_size(configuration_t * config, size_t size)
{
    config->maximumContentObjectStoreSize = size;

    forwarder_content_store_set_size(config->forwarder,
            config->maximumContentObjectStoreSize);
}

forwarder_t *
configuration_get_forwarder(const configuration_t * config) {
    return config->forwarder;
}


// ===========================
// Main functions that deal with receiving commands, executing them, and sending
// ACK/NACK

uint8_t *
configuration_dispatch_command(configuration_t * config, command_type_t command_type,
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
    return NULL;
}

void configuration_receive_command(configuration_t * config,
        command_type_t command_type, uint8_t * packet, unsigned ingress_id)
{
    assert(config);
    assert(command_type_is_valid(command_type));
    assert(packet);

    bool nack = false;

    uint8_t * reply = configuration_dispatch_command(config, command_type, packet, ingress_id);
    if (!reply) {
        reply = packet;
        msg_header_t * hdr = (msg_header_t *)reply;
        make_nack(hdr);
        nack = true;
    }

    connection_table_t * table = forwarder_get_connection_table(config->forwarder);
    const connection_t *connection = connection_table_at(table, ingress_id);
    connection_send_packet(connection, reply, false);

    switch (command_type) {
        case COMMAND_TYPE_LISTENER_LIST:
        case COMMAND_TYPE_CONNECTION_LIST:
        case COMMAND_TYPE_ROUTE_LIST:
        case COMMAND_TYPE_POLICY_LIST:
            if (!nack)
                free(reply);
            break;
        default:
            break;
    }
}
