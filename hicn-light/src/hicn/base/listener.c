/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * @file listener.c
 * @brief Implementation of hICN listeners
 */

#include <string.h> // strdup

listener_t *
listener_create(listener_type_t * type, const address_t * address,
        const char * interface_name, const char * symbolic, Forwarder * forwarder)
{
    const listener_table_t * table = forwarder_GetListenerTable(forwarder);

    listener_t * listener;
    listener_table_allocate(table, listener);

    unsigned listener_id = listener_table_get_listener_id(table, listener);

    return listener_initialize(listener, type, listener_id, symbolic, address, interface_name, forwarder);
}

int
listener_initialize(listener_t * listener, listener_type_t type,
        unsigned listener_id, const char * name, const address_t * address, const char * interface_name, const Forwarder * forwarder)
{
    int rc;

    assert(listener);
    assert(forwarder);

    *listener = {
        .id = listener_id,
        .name = strdup(name),
        .type = type,
        .interface_name = strdup(interface_name),
        .interface_index = ,
        .family = ,
        .fd = 0,
        .address = *address,
        .forwarder = forwarder,
    };

    listener->data = malloc(listener_vft[listener->type]->data_size);
    if (!listener->data)
        goto ERR_DATA;

    assert(listener_has_valid_type(listener));

    rc = listener_vft[listener->type]->initialize(listener);
    if (rc < 0)
        goto ERR_VFT;

    listener->fd = listener_vft[listener->type]->make_socket(address, NULL, interface_name);
    if (listener->fd < 0) {
        ERROR("Error creating UDP socket: (%d) %s", errno, strerror(errno));
        ERR_FD;
    }
    return 0;
    assert(listener->fd > 0);

    // XXX data should be pre-allocated here

    if (loop_register_fd(MAIN_LOOP, fd, listener,
                listener_vft[listener_->type]->read_callback, NULL) < 0)
        goto ERR_REGISTER_FD;

    // XXX TODO
    //char *str = addressToString(listener->local_addr);
    DEBUG("%s UdpListener %p created for address %s", listener_type_str(listener),
            listener, "N/A");
    free(str);

    return 0;

ERR_REGISTER_FD:
#ifndef _WIN32
    close(listener->fd);
#else
    closesocket(listener->fd);
#endif
ERR_FD:
ERR_VFT:
    free(listener->data);
ERR_DATA:
    free(listener->interface_name);
    free(listener->name);
    return -1;
}

int
listener_finalize(listener_t * listener)
{
    assert(listener);
    assert(listener_has_valid_type(listener));

    loop_unregister_fd(MAIN_LOOP, listener->fd);

#ifndef _WIN32
    close(listener->fd);
#else
    closesocket(listener->fd);
#endif

    listener_vft[listener->type]->finalize(listener);

    free(listener->data);
    free(listener->interface_name);
    free(listener->name);

    return 0;
}

int listener_get_socket(const listener_t * listener, const address_t * local,
        const address_t * remote, const char * interface_name)
{
    assert(listener);
    assert(listener_has_valid_type(listener));
    assert(pair);

    return listener_vft[listener->type]->get_socket(listener, local, remote,
            interface_name);
}

unsigned listener_create_connection(const listener_t * listener, int fd,
        const address_pair_t * pair)
{
    assert(listener);
    assert(listener_has_valid_type(listener));
    assert(fd > 0);
    assert(pair);

    // XXX TODO This code is likely common with connection creation code

    connection_table_t * table = forwarder_GetConnectionTable(udp->forwarder);
    Connection ** conn_ptr;
    connection_table_allocate(table, conn_ptr, pair);

    unsigned connid = connection_table_get_connection_id(table, conn_ptr);

    bool local = address_is_local(address_pair_local(pair));

    int rc = connection_initialize(*conn_ptr, interface_name, fd, pair, local, connid);
    if (rc < 0)
        return ~0; // XXX how to return an error

    // This was already commented:
    // connection_AllowWldrAutoStart(*conn_ptr);

    return connid;
}

/*
 * This code is not yet appropriate for batching and is thus not used in UDP,
 * but we might evolve towards supporting both
 */
void
listener_process_packet(const listener_t * listener, const uint8_t * packet,
        size_t size)
{
    size_t packetLength = messageHandler_GetTotalPacketLength(packet);
    if (readLength != packetLength)
        return;

    if (messageHandler_IsTCP(packet)) {
        MessagePacketType type;
        unsigned connid = 0;

        if (messageHandler_IsData(packet)) {
            type = MESSAGE_TYPE_DATA;
            if (hicn->connection_id == -1)
                return;
            connid = hicn->connection_id;

        } else if (messageHandler_IsInterest(packet)) {
            // notice that the connections for the interest (the one that we create at
            // run time) uses as a local address 0::0, so the main tun
            type = MESSAGE_TYPE_INTEREST;

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

        msgbuf_from_packet(&msgbuf, packet, MESSAGE_TYPE_WLDR_NOTIFICATION,
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

int
listener_punt(const listener_t * listener, const char * prefix_s)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_HICN);
    assert(prefix_s);

    return listener_vft[listener_get_type(listener)]->punt(listener, prefix_s);
}

#if 0
void
_listener_callback(evutil_socket_t fd, short what, void * arg)
{
    fd_callback_data_t * data = arg;
    data->callback(data->owner, fd, data->data);
}

int
listener_register_fd(listener_t * listener, int fd, fd_callback_t callback, void * data)
{
    fd_callback_data_t callback_data = {
        .fd = fd,
        .owner = listener,
        .callback = callback,
        .data = data,
    };

    return loop_register_fd(MAIN_LOOP, fd, listener, _listener_callback, callback_data);
}

int
listener_unregister_fd(listener_t * listener, int fd)
{
    return loop_unregister_fd(MAIN_LOOP, fd);
}
#endif

void
listener_setup_all(const forwarder_t * forwarder, uint16_t port, const char *localPath)
{
#if 0
    InterfaceSet *set = system_Interfaces(forwarder);

    size_t interfaceSetLen = interfaceSetLength(set);
    for (size_t i = 0; i < interfaceSetLen; i++) {
        Interface *iface = interfaceSetGetByOrdinalIndex(set, i);

        const AddressList *addresses = interfaceGetAddresses(iface);
        size_t addressListLen = addressListLength(addresses);

        for (size_t j = 0; j < addressListLen; j++) {
            const address_t *address = addressListGetItem(addresses, j);

            // Do not start on link address
            char listenerName[SYMBOLIC_NAME_LEN];
#ifdef __ANDROID__
            snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%zu", i);
#else
            snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%ld", i);
#endif
            // XXX TODO      if (addressGetType(address) != ADDR_LINK) {
            _setupTcpListener(forwarder, listenerName, address,
                    (char *)interfaceGetName(iface));
            //      }
        }
    }

    interfaceSetDestroy(&set);
#endif
}

// XXX TODO
void
listener_setup_local_ipv4(const forwarder_t * forwarder,  uint16_t port)
{
#if 0
    address_t address = ADDRESS4_LOCALHOST(port);

    _setupUdpListener(forwarder, "lo_udp", &address, "lo");
    _setupTcpListener(forwarder, "lo_tcp", &address, "lo");
#endif
}
