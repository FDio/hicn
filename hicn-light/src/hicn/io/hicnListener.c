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

#include <errno.h>
#include <fcntl.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <hicn/io/hicnConnection.h>
#include <hicn/io/hicnListener.h>

#include <hicn/core/connection.h>
#include <hicn/base/connection_table.h>
#include <hicn/core/forwarder.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/mapme.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/io/listener.h>
#include <hicn/socket/api.h>
#include <hicn/util/log.h>

#define IPv6 6
#define IPv4 4
#define MTU_SIZE 1500  // bytes
#define MAX_HICN_RETRY 5
#define DEFAULT_PORT 1234


typedef struct {

} listener_hicn_data_t;

struct hicn_listener {

    char *listener_name;

    Forwarder *forwarder;

    PARCEvent *hicn_event;
    int hicn_fd;  // this is the file descriptor got from hicn library

    address_t localAddress;  // this is the local address  or 0::0 in case of the
    // main listener this is the address used inside
    // forwarder to identify the listener. Notice that this
    // address is the same as the fisical interfaces on
    // which we create the TUN. it is NOT the TUN address
    // which is given by libhicn after the bind operation
    // However the user alway uses this address since is
    // the only one available at configuration time

    unsigned family;

    int connection_id;  // this is used only if the listener is used to receive
    // data packets we assume that 1 connection is associated
    // to one listener in this case so we set the
    // connection_id we the connection is create. if this id
    // is not set and a data packet is received, the packet is
    // dropped

    unsigned conn_id;
};

static void _destroy(ListenerOps **listenerOpsPtr);
static const char *_getListenerName(const ListenerOps *ops);
static const char *_getInterfaceName(const ListenerOps *ops);
static unsigned _getInterfaceIndex(const ListenerOps *ops);
static const address_t * _getListenAddress(const ListenerOps *ops);
static EncapType _getEncapType(const ListenerOps *ops);
static int _getSocket(const ListenerOps *ops, const address_pair_t * pair);
static unsigned _createNewConnection(ListenerOps *listener, int fd, const address_pair_t *pair);
static const Connection * _lookupConnection(ListenerOps * listener, const address_pair_t *pair);
static void _hicnListener_readcb(int fd, PARCEventType what, void *listener_void);
static int  _createAddressFromPacket(const uint8_t * packet, address_t * address);
static void _handleWldrNotification(ListenerOps *listener, const uint8_t *msgBuffer);
static void _readFrameToDiscard(HicnListener *hicn, int fd);

static
ListenerOps _hicnTemplate = {
    .context = NULL,
    .destroy = &_destroy,
    .getInterfaceIndex = &_getInterfaceIndex,
    .getListenAddress = &_getListenAddress,
    .getEncapType = &_getEncapType,
    .getSocket = &_getSocket,
    .getInterfaceName = &_getInterfaceName,
    .getListenerName = &_getListenerName,
    .createConnection = &_createNewConnection,
};


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
        int sock = socket (AF_INET6, SOCK_DGRAM, 0);
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

        int sock = socket (AF_INET, SOCK_DGRAM, 0);
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
#endif

// XXX TODO need to put some code in common to all packet types
static
void
_receivePacket(ListenerOps * listener, int fd)
{
    HicnListener * hicn = (HicnListener*)listener->context;
    msgbuf_t msgbuf;
    uint8_t packet[MTU_SIZE];

    /***************************************/
    ssize_t readLength = read(fd, packet, MTU_SIZE);
    if (readLength < 0) {
        ERROR("read failed %d: (%d) %s", fd, errno, strerror(errno));
        return;
    }

    size_t packetLength = messageHandler_GetTotalPacketLength(packet);
    if (readLength != packetLength)
        return;

    if (messageHandler_IsTCP(packet)) {
        MessagePacketType type;
        unsigned connid = 0;

        if (messageHandler_IsData(packet)) {
            type = MessagePacketType_ContentObject;
            if (hicn->connection_id == -1)
                return;
            connid = hicn->connection_id;

        } else if (messageHandler_IsInterest(packet)) {
            // notice that the connections for the interest (the one that we create at
            // run time) uses as a local address 0::0, so the main tun
            type = MessagePacketType_Interest;

            address_t packet_addr;
            if (_createAddressFromPacket(packet, &packet_addr) < 0)
                return;

            address_pair_t pair_find = {
                .local = packet_addr,
                .remote = /* dummy */ hicn->localAddress,
            };
            const Connection *conn = _lookupConnection(listener, &pair_find);
            if (!conn) {
                address_pair_t pair = {
                    .local = hicn->localAddress,
                    .remote = packet_addr,
                };
                connid = _createNewConnection(listener, fd, &pair);
            } else {
                connid = connection_GetConnectionId(conn);
            }

        } else {
            ERROR("Got a packet that is not a data nor an interest, drop it!");
            return;
        }

        msgbuf_from_packet(&msgbuf, packet, type, connid, ticks_now());
        forwarder_Receive(hicn->forwarder, &msgbuf, 1);

    } else if (messageHandler_IsWldrNotification(packet)) {
        address_t packet_addr;
        if (_createAddressFromPacket(packet, &packet_addr) < 0)
            return;

        address_pair_t pair_find = {
            .local = packet_addr,
            .remote = /* dummy */ hicn->localAddress,
        };
        const Connection *conn = _lookupConnection(listener, &pair_find);
        if (!conn)
            return;

        msgbuf_from_packet(&msgbuf, packet, MessagePacketType_WldrNotification,
                connection_GetConnectionId(conn), ticks_now());
        connection_HandleWldrNotification(conn, &msgbuf);

    } else {

        // TODO XXX XXX XXX XXX
#if 0
        const address_pair_t * pair = _createRecvaddress_pair_t * FromPacket(packet);
        if (!pair)
            return false;
#endif

        // XXX ~0 is wrong, we need the right connection ID if it exists no ?
        // check with code
        #if 0
        forwarder_handleHooks(hicn->forwarder, packet, listener, fd, connid, ~0, NULL);
        #endif
    }
}

static
void _hicnListener_readcb(int fd, PARCEventType what, void *listener_void) {
    ListenerOps * listener = (ListenerOps *)listener_void;
    HicnListener *hicn = (HicnListener *)listener->context;

    if (hicn->family == IPv4 || hicn->family == IPv6) {
        if (what & PARCEventType_Read) {
            _receivePacket(listener, fd);
        }
    } else {
        _readFrameToDiscard(hicn, fd);
    }
}

// XXX TODO !!
#if 0
static
bool
_isEmptyAddressIPv4(address_t * address) {
    return (strcmp("inet4://0.0.0.0:1234", addressToString(address)) == 0);
}
#endif

ListenerOps *
hicnListener_Create(Forwarder *forwarder, char *symbolic, address_t * address)
{
    HicnListener *hicn = calloc(1, sizeof(HicnListener));
    if (!hicn)
        goto ERR_MALLOC_HICN;

    hicn->forwarder = forwarder;
    hicn->listener_name = strdup(symbolic);

    // XXX
    hicn->conn_id = 0; // connection_id;
    hicn->family = address_family(address);

    hicn->connection_id = -1; // XXX different with conn_id ?

    hicn_socket_helper_t *hicnSocketHelper =
        forwarder_GetHicnSocketHelper(forwarder);

    if (address_empty(address)) {
        hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, NULL);
    } else {
        char *local_addr = malloc(/* max */ INET6_ADDRSTRLEN);
        inet_ntop(address_family(address), address, local_addr, /* max */ INET6_ADDRSTRLEN);

        hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, local_addr);

        free(local_addr);
    }

    if (hicn->hicn_fd < 0) {
        ERROR("HicnListener %s: error creating hICN listener", symbolic);
        goto ERR_FD;
    }

    // Set non-blocking flag
    int flags = fcntl(hicn->hicn_fd, F_GETFL, NULL);
    if (flags != -1) {
        ERROR("fcntl failed to obtain file descriptor flags (%d)", errno);
        goto ERR_FLAGS;
    }

    if (fcntl(hicn->hicn_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ERROR("fcntl failed to set file descriptor flags (%d)", errno);
        goto ERR_FLAGS;
    }

    ListenerOps *ops = calloc(1, sizeof(ListenerOps));
    if (!ops)
        goto ERR_MALLOC_OPS;

    memcpy(ops, &_hicnTemplate, sizeof(ListenerOps));
    ops->context = hicn;

    hicn->hicn_event = dispatcher_CreateNetworkEvent(
            forwarder_GetDispatcher(forwarder), true, _hicnListener_readcb,
            (void *)ops, hicn->hicn_fd);
    dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
            hicn->hicn_event);


    DEBUG("HicnListener %s created", symbolic);

    return ops;

ERR_MALLOC_OPS:
ERR_FLAGS:
    close(hicn->hicn_fd);
ERR_FD:
    free(hicn->listener_name);
    free(hicn);
ERR_MALLOC_HICN:
    return NULL;
}

bool
_hicnListener_Bind(ListenerOps *ops, const address_t * remote_addr)
{
    HicnListener *hicn = (HicnListener *)ops->context;
    hicn_socket_helper_t *hicnSocketHelper =
        forwarder_GetHicnSocketHelper(hicn->forwarder);

    char *remote_addr_str = malloc(/* max */ INET6_ADDRSTRLEN);
    inet_ntop(address_family(remote_addr), remote_addr, remote_addr_str, /* max */ INET6_ADDRSTRLEN);
    int rc = hicn_bind(hicnSocketHelper, hicn->hicn_fd, remote_addr_str);
    if (rc < 0) {
        ERROR("hicn_bind failed %d %s", rc, hicn_socket_strerror(rc));
        free(remote_addr_str);
        return false;
    }

    free(remote_addr_str);
    return true;
}

bool
hicnListener_Punting(ListenerOps *ops, const char *prefix)
{
    HicnListener *hicn = (HicnListener *)ops->context;
    hicn_socket_helper_t *hicnSocketHelper =
        forwarder_GetHicnSocketHelper(hicn->forwarder);

    int res = hicn_listen(hicnSocketHelper, hicn->hicn_fd, prefix);
    int retry = 0;

    while (res < 0 && retry < MAX_HICN_RETRY) {
        sleep(1);
        res = hicn_listen(hicnSocketHelper, hicn->hicn_fd, prefix);
        retry++;
    }

    if (res < 0) {
        ERROR("hicn_listen failed %d %s", res, hicn_socket_strerror(res));
        return false;
    }

    return true;
}

bool
hicnListener_SetConnectionId(ListenerOps *ops, unsigned connId)
{
    HicnListener *hicn = (HicnListener *)ops->context;
    if (hicn) {
        hicn->connection_id = connId;
        return true;
    }
    return false;
}

static
void
_hicnListener_Destroy(HicnListener **listenerPtr)
{
    assert(listenerPtr);
    assert(*listenerPtr);

    HicnListener *hicn = *listenerPtr;

    dispatcher_DestroyNetworkEvent(forwarder_GetDispatcher(hicn->forwarder),
            &hicn->hicn_event);
    parcMemory_Deallocate((void **)&hicn);
    *listenerPtr = NULL;
}

static
void
_destroy(ListenerOps **listenerOpsPtr) {
    ListenerOps *ops = *listenerOpsPtr;
    HicnListener *hicn = (HicnListener *)ops->context;
    _hicnListener_Destroy(&hicn);
    parcMemory_Deallocate((void **)&ops);
    *listenerOpsPtr = NULL;
}

static
const char *
_getListenerName(const ListenerOps *ops) {
    HicnListener *hicn = (HicnListener *)ops->context;
    return hicn->listener_name;
}

static
const char *
_getInterfaceName(const ListenerOps *ops) {
    const char *interfaceName = "";
    return interfaceName;
}

static
unsigned
_getInterfaceIndex(const ListenerOps *ops) {
    HicnListener *hicn = (HicnListener *)ops->context;
    return hicn->conn_id;
}

static
const address_t *
_getListenAddress(const ListenerOps *ops) {
    HicnListener *hicn = (HicnListener *)ops->context;
    return &hicn->localAddress;
}

static
EncapType
_getEncapType(const ListenerOps *ops) {
    return ENCAP_HICN;
}

static
int
_getSocket(const ListenerOps *ops, const address_pair_t * pair)
{
    HicnListener *hicn = (HicnListener *)ops->context;
    return hicn->hicn_fd;
}

// ===============================

static
void
_readFrameToDiscard(HicnListener *hicn, int fd) {
    // we need to discard the frame.  Read 1 byte.  This will clear it off the
    // stack.
    uint8_t buffer;
    int nread = read(fd, &buffer, 1);

    if (nread > 0) {
        DEBUG("Discarded frame from fd %d", fd);
    } else if (nread < 0) {
        ERROR("Error trying to discard frame from fd %d: (%d) %s", fd, errno,
                strerror(errno));
    }
}

static
unsigned
_createNewConnection(ListenerOps * listener, int fd, const address_pair_t *pair)
{
    HicnListener * hicn = (HicnListener *)listener->context;
    bool isLocal = false;

    // udpConnection_Create takes ownership of the pair
    IoOperations *ops = hicnConnection_Create(hicn->forwarder, listener->getInterfaceName(listener), fd, pair, isLocal);
    Connection *conn = connection_Create(ops);

    connection_table_t * table = forwarder_GetConnectionTable(hicn->forwarder);
    connection_table_add(table, conn);
    unsigned connid = ioOperations_GetConnectionId(ops);

    return connid;
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

////////////////////////////////////////////////////////////////////////////////

#if 0
static
listener_t *
listener_hicn_initialize(listener_type_t type, void * options)
{

}

static
void
listener_hicn_finalize(listener_t * listener)
{

}

DECLARE_LISTENER(hicn);
#endif
