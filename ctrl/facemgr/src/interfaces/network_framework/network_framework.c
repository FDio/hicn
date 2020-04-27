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
 * \file network_framework.c
 * \brief Implementation of Network framework interface
 */

#include "Availability.h"

#include <sys/socket.h>
#include <arpa/inet.h>

#include <Network/Network.h>
#include <err.h>

#include <hicn/facemgr.h>
#include <hicn/util/token.h>
#include <hicn/util/log.h>
#include <hicn/util/map.h>

#include "../../common.h"
#include <hicn/face.h>
#include "../../interface.h"

#include "network_framework.h"

#if !defined(MAC_OS_X_VERSION_10_14)
#error "Network frameork requires MacOSX 10.14+"
#endif /* !defined(MAC_OS_X_VERSION_10_14) */


/*
 * Bonjour service discovery for hICN forwarder
 *
 * Possible values for BONJOUR_PROTOCOL:
 *      udp (default) : avoid potential handshake during connection setup.
 *      tcp
 *
 * Service advertisement / discovery on MacOSX
 *
 *      dns-sd -R hicn _hicn._tcp local 9695
 *      dns-sd -R hicn _hicn._udp local 9695
 *
 *      dns-sd -B _hicn._tcp local
 *      dns-sd -B _hicn._udp local
 *
 * Service discovery on Linux (various useful commandline arguments):
 *
 *      avahi-browse -pt _hicn._udp
 *      avahi-browse -rp _hicn._tcp
 */

#define BONJOUR_PROTOCOL udp
#define BONJOUR_SERVICE_DOMAIN "local"
#define BONJOUR_SERVICE_NAME "hicn node"

/* Generated variables */
#define BONJOUR_SERVICE_TYPE "_hicn._" STRINGIZE(BONJOUR_PROTOCOL)
#define BONJOUR_PROTOCOL_NAME STRINGIZE(BONJOUR_PROTOCOL)
#define nw_parameters_create_fn PPCAT(nw_parameters_create_secure_, BONJOUR_PROTOCOL)

#define DEFAULT_PORT 9695

typedef enum {
    INTERFACE_TYPE_OTHER,
    INTERFACE_TYPE_WIFI,
    INTERFACE_TYPE_CELLULAR,
    INTERFACE_TYPE_WIRED,
    INTERFACE_TYPE_LOOPBACK,
} _nw_interface_type_t;

const char * interface_type_str[] = {
    "OTHER", "WIFI", "CELLULAR", "WIRED", "LOOPBACK",
};

#if 1
typedef enum {
    PATH_STATUS_INVALID,
    PATH_STATUS_SATISTIED,
    PATH_STATUS_UNSATISFIED,
    PATH_STATUS_SATISFIABLE,
} _nw_path_status_t;
#endif

const char * path_status_str[] = {
    "INVALID", "SATISFIED", "UNSATISFIED", "SATISFIABLE",
};

const char * endpoint_type_str[] = {
    "INVALID", "ADDRESS", "HOST", "BONJOUR",
};

const char * connection_state_str[] = {
    "INVALID", "WAITING", "PREPARING", "READY", "FAILED", "CANCELLED",
};

int
cmp_iface(const nw_interface_t iface1, const nw_interface_t iface2)
{
    return INT_CMP(nw_interface_get_index(iface1), nw_interface_get_index(iface2));
}

//TYPEDEF_MAP(map_cnx, nw_interface_t, nw_connection_t, cmp_iface);

typedef struct {
    network_framework_cfg_t cfg;
    nw_path_monitor_t pm; /**< Main path monitor */
//    map_cnx_t map_cnx;    /**< Map: interface -> connection for face status */
} nf_data_t;

void
dump_interface(nw_interface_t interface, int indent)
{
    uint32_t index = nw_interface_get_index(interface);
    const char * name = nw_interface_get_name(interface);
    nw_interface_type_t type = nw_interface_get_type(interface);

    printfi(indent+1, "%d: %s [%s]\n", index, name, interface_type_str[type]);
}

void
dump_endpoint(nw_endpoint_t endpoint, int indent)
{
    if (!endpoint) {
        printfi(indent, "N/A\n");
        return;
    }

    nw_endpoint_type_t endpoint_type = nw_endpoint_get_type(endpoint);
    const char * hostname = nw_endpoint_get_hostname(endpoint);
    short port = nw_endpoint_get_port(endpoint);
    const struct sockaddr * address = nw_endpoint_get_address(endpoint);

    printfi(indent, "Type: %s\n", endpoint_type_str[endpoint_type]);
    printfi(indent, "Hostname: %s\n", hostname);
    printfi(indent, "Port: %d\n", port);

    if (address) {
        char *s = NULL;
        switch(address->sa_family) {
            case AF_INET: {
                              struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
                              s = malloc(INET_ADDRSTRLEN);
                              inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
                              break;
                          }
            case AF_INET6: {
                               struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
                               s = malloc(INET6_ADDRSTRLEN);
                               inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
                               break;
                           }
            default:
                           break;
        }
        printfi(indent, "IP address: %s\n", s);
        free(s);
    }
}

void
dump_path(nw_path_t path, int indent)
{
    /* nw_path_enumerate_interfaces : not interesting */
    nw_path_status_t path_status = nw_path_get_status(path);
    printfi(indent, "Status: %s\n", path_status_str[path_status]);
    printfi(indent, "Expensive: %s\n", nw_path_is_expensive(path) ? "true" : "false");
    printfi(indent, "IPv4 enabled: %s\n", nw_path_has_ipv4(path) ? "true" : "false");
    printfi(indent, "IPv6 enabled: %s\n", nw_path_has_ipv6(path) ? "true" : "false");
    printfi(indent, "DNS: %s\n", nw_path_has_dns(path) ? "true" : "false");
    printfi(indent, "Interfaces:\n");
    nw_path_enumerate_interfaces(path, (nw_path_enumerate_interfaces_block_t)^(nw_interface_t interface) {
        dump_interface(interface, indent+1);
        return true;
    });

    nw_endpoint_t local = nw_path_copy_effective_local_endpoint(path);
    printfi(indent, "Effective local endpoint:\n");
    dump_endpoint(local, indent+1);
    nw_release(local);

    nw_endpoint_t remote = nw_path_copy_effective_remote_endpoint(path);
    printfi(indent, "Effective remote endpoint:\n");
    dump_endpoint(remote, indent+1);
    nw_release(remote);
}

void
dump_connection(nw_connection_t connection, int indent)
{
    nw_endpoint_t remote = nw_connection_copy_endpoint(connection);
    nw_path_t path = nw_connection_copy_current_path(connection);

    printfi(indent, "Remote endpoint:\n");
    dump_endpoint(remote, indent+1);
    printfi(indent, "Path:\n");
    dump_path(path, indent+1);

    /*
    nw_connection_copy_protocol_metadata();
    nw_connection_get_maximum_datagram_size();
    */

    nw_release(remote);
    nw_release(path);
}

#if defined(MAC_OS_X_VERSION_10_15)
void
dump_browse_result(nw_browse_result_t result, int indent)
{
    /* Endpoint */
    nw_endpoint_t browse_endpoint = nw_browse_result_copy_endpoint(result);
    if (!browse_endpoint) {
        ERROR("[network_framework.dump_result] Failed to retrieve endpoint from Bonjour browse result");
        return;
    }
    printfi(indent + 1, "Endpoint:");
    dump_endpoint(browse_endpoint, indent + 2);

    /* Interfaces */
    printfi(indent + 1, "Interfaces:");
    nw_browse_result_enumerate_interfaces(result, (nw_browse_result_enumerate_interface_t) ^(nw_interface_t interface) {
        dump_interface(interface, indent + 2);
        return true;
    });
}
#endif /* defined(MAC_OS_X_VERSION_10_15) */

facelet_t *
facelet_create_from_connection(nw_connection_t connection)
{
    facelet_t * facelet;
    ip_address_t local_addr, remote_addr;
    uint16_t remote_port;

    nw_path_t path = nw_connection_copy_current_path(connection);
    nw_endpoint_t local = nw_path_copy_effective_local_endpoint(path);
    nw_endpoint_t remote = nw_path_copy_effective_remote_endpoint(path);
    __block nw_interface_t interface;

    const struct sockaddr * local_sa = nw_endpoint_get_address(local);
    const struct sockaddr * remote_sa = nw_endpoint_get_address(remote);

    assert (local_sa->sa_family == remote_sa->sa_family);
    switch(local_sa->sa_family) {
        case AF_INET:
            local_addr.v4.as_inaddr = ((struct sockaddr_in *)local_sa)->sin_addr;
            remote_addr.v4.as_inaddr = ((struct sockaddr_in *)remote_sa)->sin_addr;
            remote_port = ((struct sockaddr_in *)remote_sa)->sin_port;
            break;
        case AF_INET6:
            local_addr.v6.as_in6addr = ((struct sockaddr_in6 *)local_sa)->sin6_addr;
            remote_addr.v6.as_in6addr = ((struct sockaddr_in6 *)remote_sa)->sin6_addr;
            remote_port = ((struct sockaddr_in6 *)remote_sa)->sin6_port;
            break;
        default:
            ERROR("Unsupported address family: %d\n", local_sa->sa_family);
            return NULL;
    }


    /* Retrieving path interface type (a single one expected */
    nw_path_enumerate_interfaces(path, (nw_path_enumerate_interfaces_block_t)^(nw_interface_t path_interface) {
        interface = path_interface;
        return false;
    });

    const char * name = nw_interface_get_name(interface);
    netdevice_t netdevice;
    snprintf(netdevice.name, IFNAMSIZ, "%s", name);
    netdevice_update_index(&netdevice);

    netdevice_type_t netdevice_type;
    nw_interface_type_t type = nw_interface_get_type(interface);

    switch(type) {
        case INTERFACE_TYPE_OTHER:
            netdevice_type = NETDEVICE_TYPE_UNDEFINED;
            break;
        case INTERFACE_TYPE_WIFI:
            netdevice_type = NETDEVICE_TYPE_WIFI;
            break;
        case INTERFACE_TYPE_CELLULAR:
            netdevice_type = NETDEVICE_TYPE_CELLULAR;
            break;
        case INTERFACE_TYPE_WIRED:
            netdevice_type = NETDEVICE_TYPE_WIRED;
            break;
        case INTERFACE_TYPE_LOOPBACK:
            netdevice_type = NETDEVICE_TYPE_LOOPBACK;
            break;
        default:
            break;

    }

    nw_release(local);
    nw_release(remote);
    nw_release(path);

    facelet = facelet_create();
    if (!facelet)
        return NULL;

    facelet_set_netdevice(facelet, netdevice);
    facelet_set_netdevice_type(facelet, netdevice_type);
    facelet_set_family(facelet, local_sa->sa_family);
    facelet_set_local_addr(facelet, local_addr);
    facelet_set_remote_addr(facelet, remote_addr);
    facelet_set_remote_port(facelet, remote_port);

    return facelet;
}

void
on_connection_state_event(interface_t * interface, nw_interface_t iface,
        nw_connection_t cnx, nw_connection_state_t state, nw_error_t error)
{
#if 1
    DEBUG("Connection [new state = %s]:\n", connection_state_str[state]);
    nw_path_t path = nw_connection_copy_current_path(cnx);
    nw_path_enumerate_interfaces(path, (nw_path_enumerate_interfaces_block_t)^(nw_interface_t interface) {
        const char * name = nw_interface_get_name(interface);
        printf("NAME=%s\n", name);
        return true;
    });
#endif

    /* We should get enough information to create the face and set if up
     * asap */

    nw_endpoint_t remote = nw_connection_copy_endpoint(cnx);
    errno = error ? nw_error_get_error_code(error) : 0;

    switch(state) {
        case nw_connection_state_waiting:
            warn("connect to %s port %u (%s) failed, is waiting",
                    nw_endpoint_get_hostname(remote),
                    nw_endpoint_get_port(remote),
                    BONJOUR_PROTOCOL_NAME);
            break;

        case nw_connection_state_preparing:
            break;

        case nw_connection_state_ready:
            {
                printf("info:\n");
                warn("connection ready");
#if 1
            WITH_DEBUG({
                dump_connection(cnx, 1);
            });
#endif
            facelet_t * facelet = facelet_create_from_connection(cnx);
            if (!facelet)
                return;
            facelet_set_event(facelet, FACELET_EVENT_CREATE);
            interface_raise_event(interface, facelet);
            break;
            }
        case nw_connection_state_failed:
            /* Can we fail with bonjour, or are we always waiting ? */
            warn("connect to %s port %u (%s) failed",
                    nw_endpoint_get_hostname(remote),
                    nw_endpoint_get_port(remote),
                    BONJOUR_PROTOCOL_NAME);
            break;

        case nw_connection_state_cancelled:
            // Release the primary reference on the connection
            // that was taken at creation time
            nw_release(cnx);
            break;

        default: /* nw_connection_state_invalid */
            /* Should never be called */
            break;

    }

    nw_release(remote);

}

void
on_connection_path_event(interface_t * interface, nw_interface_t iface,
        nw_connection_t cnx, nw_path_t path)
{
#if 1
    DEBUG("Connection [path changed]:\n");
    WITH_DEBUG({
        dump_connection(cnx, 1);
    });
#endif
    /* redundant *//*
    DEBUG(1, "Path:\n");
    dump_path(path, 2);
    */
}

/**
 * Enumerate main path interfaces
 *
 * We need to create specific dummy connections for each newly discovered
 * interface
 *
 * Currently we only use Bonjour/TCP for remote hICN discovery and connection
 * path monitoring.
 */
void on_interface_event(interface_t * interface, nw_interface_t iface)
{
    /* We can create an hICN face on this interface that will be down until
     * connected
     * It is however possible to have two default gateways on the same
     * interface, or more, or even zero. Somehow we need a strategy, timers, etc
     * to properly do the job.
     *
     * We have to determine:
     *  - how many faces to build
     *  - the face type : hICN, tunnel (TCP/UDP)
     *  - the underlying protocol : v4, v6
     *
     * This depends on the configuration, end host and network capabilities.
     *
     * We can rely on several types of discovery:
     *  - DHCP
     *  - Bonjour
     *  - ...
     *
     * So far:
     * - bonjour discovery attempt, we expect to discover one hICN interface
     *   (how bonjour works with more than one is unclear), after a certain
     *   time, if none is discovered, we cannot do any tunnel face.
     */

    // OLD CODE

    /* nw_parameters_create_secure_{udp,tcp} */
    nw_parameters_t parameters = nw_parameters_create_fn(
                NW_PARAMETERS_DISABLE_PROTOCOL, /* no (d)tls */
                NW_PARAMETERS_DEFAULT_CONFIGURATION /* default udp/tcp */);

    if (!parameters)
        goto ERR_PARAMETERS;

    nw_parameters_require_interface(parameters, iface);
    nw_parameters_set_reuse_local_address(parameters, true);

#if defined(MAC_OS_X_VERSION_10_15)
    /*
     * Before being able to create a bonjour endpoint, we need to browse for
     * available services on the local network using the parameters specified
     * before.
     */
    nw_browse_descriptor_t descriptor = nw_browse_descriptor_create_bonjour_service(BONJOUR_SERVICE_TYPE, BONJOUR_SERVICE_DOMAIN);
    if (!descriptor) {
        ERROR("[network_framework.on_interface_event] Failed to create a bonjour browse descriptor");
        goto ERR_DESCRIPTOR;
    }

    nw_browser_t browser = nw_browser_create(descriptor, parameters);
    nw_browser_set_queue(browser, dispatch_get_main_queue());
    nw_browser_set_browse_results_changed_handler(browser, ^(nw_browse_result_t result, nw_browse_result_t result2, bool flag) {
        /* Dump result */
        printfi(0, "NEW BROWSE RESULT");
        printfi(1, "Result:");
        dump_browse_result(result, 2);
        printfi(1, "Result2:");
        dump_browse_result(result2, 2);
        printfi(1, "Flag: %s\n", (flag?"ON":"OFF"));

        /* Changes */
        nw_browse_result_change_t change = nw_browse_result_get_changes(result, result2);
        switch(change) {
            case nw_browse_result_change_identical:
                printfi(2, "The compared services are identical.");
                break;
            case nw_browse_result_change_result_added:
                printfi(2, "A new service was discovered.");
                break;

            case nw_browse_result_change_result_removed:
                printfi(2, "A previously discovered service was removed.");
                break;

            case nw_browse_result_change_txt_record_changed:
                printfi(2, "The service's associated TXT record changed.");
                break;

            case nw_browse_result_change_interface_added:
                printfi(2, "The service was discovered over a new interface.");
                break;

            case nw_browse_result_change_interface_removed:
                printfi(2, "The service was no longer discovered over a certain interface.");
                break;
        }
    });

    nw_browser_start(browser);
//#else
//#warning "Bonjour discovery only available in MacOS 10.15+"
#endif /* defined(MAC_OS_X_VERSION_10_15) */

    /*
     * Now that we have resolve the name of a bonjour remote, we can create a
     * connection to the corresponding endpoint identified by its name.
     */
    nw_endpoint_t endpoint;

    DEBUG("Creating bonjour service towards NAME=%s TYPE=%s DOMAIN=%s",
            BONJOUR_SERVICE_NAME, BONJOUR_SERVICE_TYPE, BONJOUR_SERVICE_DOMAIN);
    endpoint = nw_endpoint_create_bonjour_service(
            BONJOUR_SERVICE_NAME,
            BONJOUR_SERVICE_TYPE,
            BONJOUR_SERVICE_DOMAIN);

    if (!endpoint) {
        ERROR("[network_framework.on_interface_event] Failed to create bound Bonjour connection");
        goto ERR_ENDPOINT;
    }

    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    if (!connection)
        goto ERR_CONNECTION;

    nw_release(endpoint);
    nw_release(parameters);

    /* Remember not to recreate connection */
    // XXX TODO

    /* Setup connection handlers */

    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        on_connection_state_event(interface, iface, connection, state, error);
    });

    nw_connection_set_path_changed_handler(connection, ^(nw_path_t path) {
        on_connection_path_event(interface, iface, connection, path);
    });

    nw_connection_set_better_path_available_handler(connection, ^(bool value) {
#if 1
        DEBUG("Connection [better path = %s]\n", (value ? "true" : "false"));
        WITH_DEBUG({
            dump_connection(connection, 1);
        });
#endif
    });

    nw_connection_set_viability_changed_handler(connection, ^(bool value) {
#if 1
        DEBUG("Connection [viable = %s]\n", (value ? "true" : "false"));
        WITH_DEBUG({
            //dump_connection(connection, 1);
        });
#endif

        /*
         * This is the first time we have a connection with address and port
         * and thus the full identification of an hICN face
         */
        facelet_t * facelet = facelet_create_from_connection(connection);
        if (!facelet)
            return;
        facelet_set_event(facelet, value ? FACELET_EVENT_CREATE : FACELET_EVENT_DELETE);
        interface_raise_event(interface, facelet);

    });

    nw_connection_start(connection);

    nw_connection_set_queue(connection, dispatch_get_main_queue());
    nw_retain(connection); // Hold a reference until cancelled

#if 1
    DEBUG("Created Bonjour cnx on interface:");
    WITH_DEBUG({
        dump_interface(iface, 1);
    });
#endif

    return;

   nw_release(connection);
ERR_CONNECTION:
    nw_release(endpoint);
ERR_ENDPOINT:
#if defined(MAC_OS_X_VERSION_10_15)
    nw_release(descriptor);
ERR_DESCRIPTOR:
#endif /* defined(MAC_OS_X_VERSION_10_15) */
    nw_release(parameters);

ERR_PARAMETERS:
    return;
}

void on_path_event(interface_t * interface, nw_path_t path)
{
    /* Simplification: we handle path event only once.
     * Ideally, test whether we discover new interfaces or not
     */
#if 1
    DEBUG("Path [event]:\n");
    WITH_DEBUG({
        dump_path(path, 1);
    });
#endif

    nw_path_enumerate_interfaces(path, (nw_path_enumerate_interfaces_block_t)^(nw_interface_t iface) {
            on_interface_event(interface, iface);
            return true;
    });

}

int nf_initialize(interface_t * interface, void * cfg)
{
    nf_data_t * data = malloc(sizeof(nf_data_t));
    if (!data)
        goto ERR_MALLOC;

    if (cfg)
        data->cfg = * (network_framework_cfg_t *)cfg;

    data->pm = nw_path_monitor_create();
    if (!data->pm)
        goto ERR_PM;

    nw_path_monitor_set_queue(data->pm, dispatch_get_main_queue());
    nw_path_monitor_set_cancel_handler(data->pm, ^() { });
    nw_path_monitor_set_update_handler(data->pm, ^(nw_path_t path) {
            on_path_event(interface, path);
            });

    // XXX NEEDED ?
    nw_retain(data->pm);

    DEBUG("Starting network path monitor");
    nw_path_monitor_start(data->pm);

    interface->data = data;
    return 0;

ERR_PM:
    free(data);
ERR_MALLOC:
    return -1;
}

int nf_finalize(interface_t * interface)
{
    nf_data_t * data = (nf_data_t*)interface->data;
    if (data->pm) {
        nw_path_monitor_cancel(data->pm);
        data->pm = NULL;
    }
    return 0;
}

const interface_ops_t network_framework_ops = {
    .type = "network_framework",
    .initialize = nf_initialize,
    .finalize = nf_finalize,
    .on_event = NULL,
};
