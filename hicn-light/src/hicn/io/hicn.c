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
 * @file hicn.c
 * @brief Implementation of hicn face
 */

#include <errno.h>
#include <fcntl.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hicn/base/listener.h>
#include <hicn/base/connection.h>
#include <hicn/base/connection_table.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/mapme.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/socket/api.h>
#include <hicn/util/log.h>

#include "hicn.h"

#define IPv6 6
#define IPv4 4
#define MTU_SIZE 1500  // bytes
#define MAX_HICN_RETRY 5
#define DEFAULT_PORT 1234

// XXX #if !defined(__APPLE__) && !defined(__ANDROID__) && !defined(_WIN32) && \
    defined(PUNTING)

// XXX the socket helper should be moved here as we can have a single hicn
// listener

#if 0
static
const
address_pair_t *
_createRecvAddressPairFromPacket(const uint8_t *msgBuffer) {
    address_t * packetSrcAddr = NULL; /* This one is in the packet */
    address_t * localAddr = NULL; /* This one is to be determined */

    if (messageHandler_GetIPPacketType(msgBuffer) == IPv6_TYPE) {
        struct sockaddr_in6 addr_in6;
        addr_in6.sin6_family = AF_INET6;
        addr_in6.sin6_port = htons(DEFAULT_PORT);
        addr_in6.sin6_flowinfo = 0;
        addr_in6.sin6_scope_id = 0;
        memcpy(&addr_in6.sin6_addr,
                (struct in6_addr *)messageHandler_GetSource(msgBuffer), 16);
        packetSrcAddr = addressCreateFromInet6(&addr_in6);

        /* We now determine the local address used to reach the packet src address */
#ifndef _WIN32
        int sock = socket (AF_INET6, SOCK_DGRAM, 0);
#else
        int sock = (int)socket (AF_INET6, SOCK_DGRAM, 0);
#endif /* _WIN32 */
        if (sock < 0)
            goto ERR;

        struct sockaddr_in6 remote, local;
        memset(&remote, 0, sizeof(remote));
        remote.sin6_family = AF_INET6;
        remote.sin6_addr = addr_in6.sin6_addr;
        remote.sin6_port = htons(DEFAULT_PORT);

        socklen_t locallen = sizeof(local);
        if (connect(sock, (const struct sockaddr*)&remote, sizeof(remote)) == -1)
            goto ERR;
        if (getsockname(sock, (struct sockaddr*) &local, &locallen) == -1)
            goto ERR;

        local.sin6_port = htons(DEFAULT_PORT);
        localAddr = addressCreateFromInet6(&local);

        close(sock);

    } else if (messageHandler_GetIPPacketType(msgBuffer) == IPv4_TYPE) {
        struct sockaddr_in addr_in;
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(DEFAULT_PORT);
        memcpy(&addr_in.sin_addr,
                (struct in_addr *)messageHandler_GetSource(msgBuffer), 4);
        packetSrcAddr = addressCreateFromInet(&addr_in);

        /* We now determine the local address used to reach the packet src address */

#ifndef _WIN32
        int sock = socket (AF_INET, SOCK_DGRAM, 0);
#else
        int sock = (int)socket (AF_INET, SOCK_DGRAM, 0);
#endif /* _WIN32 */
        if (sock < 0) {
            perror("Socket error");
            goto ERR;
        }

        struct sockaddr_in remote, local;
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr = addr_in.sin_addr;
        remote.sin_port = htons(DEFAULT_PORT);

        socklen_t locallen = sizeof(local);
        if (connect(sock, (const struct sockaddr*)&remote, sizeof(remote)) == -1)
            goto ERR;
        if (getsockname(sock, (struct sockaddr*) &local, &locallen) == -1)
            goto ERR;

        local.sin_port = htons(DEFAULT_PORT);
        localAddr = addressCreateFromInet(&local);

        close(sock);
    }
    /* As this is a receive pair, we swap src and dst */
    return addressPair_Create(localAddr, packetSrcAddr);

ERR:
    perror("Socket error");
    return NULL;
}

static
bool _isEmptyAddressIPv6(address_t * address) {
    struct sockaddr_in6 *addr6 =
        parcMemory_AllocateAndClear(sizeof(struct sockaddr_in6));
    parcAssertNotNull(addr6, "parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(addr6));

    addressGetInet6(address, addr6);

    bool res = true;
    for (int i = 0; i < 16; ++i) {
        if (addr6->sin6_addr.s6_addr[i] != 0) {
            res = false;
        }
    }

    parcMemory_Deallocate((void **)&addr6);

    return res;
}

}

static
const Connection *
_lookupConnection(ListenerOps * listener, const address_pair_t *pair)
{
    HicnListener * hicn = (HicnListener*)listener->context;
    const connection_table_t * table = forwarder_GetConnectionTable(hicn->forwarder);
    const address_t * packetSourceAddress = address_pair_local(pair);

    if (hicn->connection_id != -1)
        return connection_table_get_by_id(table, hicn->connection_id);

    if (!packetSourceAddress)
        return NULL;

    // in this first check we try to retrieve the standard connection
    // generated by the hicn-light
    const address_pair_t new_pair = {
        .local = hicn->localAddress,
        .remote = *packetSourceAddress,
    };
    return *connection_table_lookup(table, &new_pair);
}


// XXX TODO : rely on libhicn
int
_createAddressFromPacket(const uint8_t *packet, address_t * address)
{
    if (messageHandler_GetIPPacketType(packet) == IPv6_TYPE) {
        struct sockaddr_in6 * sin6 = address6(address);
        *sin6 = (struct sockaddr_in6) {
            .sin6_family = AF_INET6,
            .sin6_port = htons(DEFAULT_PORT),
            .sin6_flowinfo = 0,
            .sin6_scope_id = 0,
        };
        memcpy(&sin6->sin6_addr,
                (struct in6_addr *)messageHandler_GetSource(packet), 16);
        return 0;
    } else if (messageHandler_GetIPPacketType(packet) == IPv4_TYPE) {
        struct sockaddr_in * sin = address4(address);
        *sin = (struct sockaddr_in) {
            .sin_family = AF_INET,
            .sin_port = htons(DEFAULT_PORT),
        };
        memcpy(&sin->sin_addr,
                (struct in_addr *)messageHandler_GetSource(packet), 4);
        return 0;
    } else {
        return -1;
    }
}

#endif

/******************************************************************************
 * Listener
 ******************************************************************************/

typedef struct {
    //address_t localAddress;  // this is the local address  or 0::0 in case of the
    // main listener this is the address used inside
    // forwarder to identify the listener. Notice that this
    // address is the same as the fisical interfaces on
    // which we create the TUN. it is NOT the TUN address
    // which is given by libhicn after the bind operation
    // However the user alway uses this address since is
    // the only one available at configuration time

    // XXX why do we need the id of the associated connection ?
    int connection_id;  // this is used only if the listener is used to receive
    // data packets we assume that 1 connection is associated
    // to one listener in this case so we set the
    // connection_id we the connection is create. if this id
    // is not set and a data packet is received, the packet is
    // dropped

    hicn_socket_helper_t * hicn_socket;

} listener_hicn_data_t;

static void _readcb(int fd, PARCEventType what, void * listener_void)
{
    listener_t * listener = listener_void;
    uint8_t packet[MTU_SIZE];

    int family = address_family(listener->address);
    if ((family != AF_INET) && (family != AF_INET6)) {
        /*
         * We need to discard the frame.  Read 1 byte.  This will clear it off
         * the stack.
         */
        int nread = read(fd, packet, 1);

        if (nread > 0) {
            DEBUG("Discarded frame from fd %d", fd);
        } else if (nread < 0) {
            ERROR("Error trying to discard frame from fd %d: (%d) %s", fd, errno,
                    strerror(errno));
        }
        return;
    }

    if (!(what & PARCEventType_Read))
        return;

    ssize_t n = read(fd, packet, MTU_SIZE);
    if (n < 0) {
        ERROR("read failed %d: (%d) %s", fd, errno, strerror(errno));
        return;
    }

    listener_process_packet(listener, packet, n);
}

bool
listener_hicn_bind(listener_t * listener, const address_t * address)
{
    assert(listener);
    assert(address);

    char *address_str = malloc(/* max */ INET6_ADDRSTRLEN);
    inet_ntop(address_family(address), address, address_str, /* max */ INET6_ADDRSTRLEN);
    int rc = hicn_bind(data->hicn_socket_helper, hicn->fd, address_str);
    if (rc < 0) {
        ERROR("hicn_bind failed %d %s", rc, hicn_socket_strerror(rc));
        free(address_str);
        return false;
    }

    free(address_str);
    return true;
}

static
int
listener_hicn_initialize(listener_t * listener)
{
    assert(listener);
    assert(data);
    assert(!*data);

    listener_hicn_data_t * data = listener->data;
    assert(data);
    // XXX
    hicn->conn_id = 0; // connection_id;
    hicn->connection_id = -1; // XXX different with conn_id ?

    data->helper = hicn_create();
    if (!data->helper)
        goto ERR_HELPER;

    if (address_empty(address)) {
        hicn->fd = hicn_socket(data->hicn_socket, symbolic, NULL);
    } else {
        char *local_addr = malloc(/* max */ INET6_ADDRSTRLEN);
        inet_ntop(address_family(address), address, local_addr, /* max */ INET6_ADDRSTRLEN);
        listener->fd = hicn_socket(data->hicn_socket, symbolic, local_addr);
        free(local_addr);
    }

    if (listener->fd < 0) {
        ERROR("HicnListener %s: error creating hICN listener", symbolic);
        goto ERR_FD;
    }

    // Set non-blocking flag
    int flags = fcntl(listener->fd, F_GETFL, NULL);
    if (flags != -1) {
        ERROR("fcntl failed to obtain file descriptor flags (%d)", errno);
        goto ERR_FLAGS;
    }

    if (fcntl(listener->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ERROR("fcntl failed to set file descriptor flags (%d)", errno);
        goto ERR_FLAGS;
    }

    return 0;

ERR_FLAGS:
    close(listener->fd);
ERR_FD:
    hicn_free(data->helper);
ERR_HELPER:
    return -1;
}

}

static
int
listener_hicn_finalize(listener_t * listener)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_HICN);

    Dispatcher * dispatcher = forwarder_GetDispatcher(listener->forwarder);
    dispatcher_DestroyNetworkEvent(dispatcher, &listener->event);

    // TODO destroy hicn_socket_helper
    // TODO free(data) (like in other classes)

    hicn_free(data->helper);

    return 0;
}

static
int
listener_hicn_punt(const listener_t * listener, const char * prefix_s)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_HICN);
    assert(prefix_s);

    listener_hicn_data_t * data = listener->data;
    assert(data);

    for (int retry = 0; retry < MAX_HICN_RETRY, retry++) {
        if (hicn_listen(data->hicn_socket_helper, hicn->fd, prefix_s) >= 0)
            return 0;
        sleep(1);
    }
    ERROR("hicn_listen failed %d %s", res, hicn_socket_strerror(res));
    return -1;
}

static
int
listener_hicn_get_socket(const listener_t * listener, const address_pair_t * pair)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_HICN);
    assert(pair);

    /* ... */

    return -1;

}

DECLARE_LISTENER(hicn);

/******************************************************************************
 * Connection
 ******************************************************************************/

typedef struct {
    /* ... */
} connection_hicn_data_t;

static
int
connection_hicn_initialize(connection_t * connection,
        const char * interface_name, int fd, const address_pair_t * pair,
        bool local, unsigned connection_id, void **pdata)
{

    assert(connection);
    assert(connection_get_type(connection) == FACE_TYPE_HICN);
    assert(interface_name);
    assert(address_pair);
    assert(data);
    assert(!*data);

    connection_hicn_data_t * data = malloc(sizof(connection_hicn_data_t));
    if (!data)
        return -1;
    *pdata = data;

    /* ... */

    return 0;
}

static
int
connection_hicn_send(const connection_t * connection, const address_t * address,
        msgbuf_t * msgbuf, bool queue)
{
    assert(connection);
    assert(address);
    /* msgbuf can be NULL */

    connection_hicn_data_t * data = connection->data;
    assert(data);

    /* ... */

    return true;
}

static
bool
connection_hicn_sendv(const connection_t * connection, struct iovec * iov,
        size_t size)
{

    assert(connetion);
    assert(iov);

    connection_hicn_data_t * data = connection->data;
    assert(data);

    /* ... */

    return true;
}

static
void
connection_hicn_send_packet(const connection_t * connection, const uint8_t * packet)
{
    assert(ops);
    assert(packet);

    /* ... */
}

DECLARE_CONNECTION(hicn);
