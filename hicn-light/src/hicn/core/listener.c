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

#include <hicn/util/log.h>

#include "forwarder.h"
#include "listener_vft.h"
#include "../base/loop.h"
#include "../io/base.h"

listener_t *
listener_create(face_type_t type, const address_t * address,
        const char * interface_name, const char * name, forwarder_t * forwarder)
{
    const listener_table_t * table = forwarder_get_listener_table(forwarder);

    listener_t * listener;
    listener_key_t key = {
        .type = type,
        .address = *address,
    };
    listener_table_allocate(table, listener, &key, name);

    unsigned listener_id = listener_table_get_listener_id(table, listener);

    listener_initialize(listener, type, name, listener_id, address, interface_name, forwarder);
    return listener;
}

int
listener_initialize(listener_t * listener, face_type_t type, const char * name,
        unsigned listener_id, const address_t * address,
        const char * interface_name, forwarder_t * forwarder)
{
    int rc;

    assert(listener);
    assert(forwarder);

    *listener = (listener_t) {
        .id = listener_id,
        .name = strdup(name),
        .type = type,
        .interface_name = strdup(interface_name),
        //.interface_index = ,
        //.family = ,
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

    listener->fd = listener_vft[listener->type]->get_socket(listener, address, NULL, interface_name);
    if (listener->fd < 0) {
        ERROR("Error creating listener fd: (%d) %s", errno, strerror(errno));
        goto ERR_FD;
    }
    assert(listener->fd > 0);

    // XXX data should be pre-allocated here

    loop_fd_event_create(&listener->event_data, MAIN_LOOP, listener->fd, listener,
                (fd_callback_t)listener_read_callback, NULL);

    if (!listener->event_data) {
        goto ERR_REGISTER_FD;
    }

    if (loop_fd_event_register(listener->event_data) < 0) {
        goto ERR_REGISTER_FD;
    }

    // XXX TODO
    //char *str = addressToString(listener->local_addr);
    DEBUG("%s UdpListener %p created for address %s",
            face_type_str(listener->type), listener, "N/A");
    //free(str);

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

    loop_event_unregister(listener->event_data);

#ifndef _WIN32
    close(listener->fd);
#else
    closesocket(listener->fd);
#endif

    listener_vft[listener->type]->finalize(listener);

    free(listener->data);
    free(listener->interface_name);
    free(listener->name);
    loop_event_free(listener->event_data);

    return 0;
}

int listener_get_socket(const listener_t * listener, const address_t * local,
        const address_t * remote, const char * interface_name)
{
    assert(listener);
    assert(listener_has_valid_type(listener));
    assert(local);
    assert(remote);

    return listener_vft[listener->type]->get_socket(listener, local, remote,
            interface_name);
}

// XXX CHANGE : we now get the fd directly from the listener
unsigned listener_create_connection(const listener_t * listener,
        const address_pair_t * pair)
{
    assert(listener);
    assert(listener_has_valid_type(listener));
    assert(pair);

    // XXX TODO This code is likely common with connection creation code
    const char * name = NULL;

    connection_table_t * table = forwarder_get_connection_table(listener->forwarder);
    connection_t * connection;
    connection_table_allocate(table, connection, pair, name);

    unsigned connid = connection_table_get_connection_id(table, connection);

    bool local = address_is_local(address_pair_get_local(pair));

    int fd = listener_get_socket(listener, address_pair_get_local(pair),
            address_pair_get_remote(pair), NULL); // XXX interfacename was not specified

    // XXX here we use the same interface name as the listener
    int rc = connection_initialize(connection, listener->type, name,
            listener->interface_name, fd, pair, local, connid, listener->forwarder);
    if (rc < 0)
        return ~0; // XXX how to return an error

    // This was already commented:
    // connection_AllowWldrAutoStart(*conn_ptr);

    return connid;
}

int
listener_punt(const listener_t * listener, const char * prefix_s)
{
    assert(listener);
    assert(listener_get_type(listener) == FACE_TYPE_HICN);
    assert(prefix_s);

    return listener_vft[listener_get_type(listener)]->punt(listener, prefix_s);
}


ssize_t
listener_read_single(listener_t * listener)
{
    assert(listener);

    size_t processed_size;
    size_t total_size = 0;

    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(listener->forwarder);

    for (;;) {

        msgbuf_t * msgbuf = NULL;
        if (!msgbuf_pool_get(msgbuf_pool, msgbuf))
            return 0;

        address_pair_t pair;
        pair.local = *listener_get_address(listener);

        ssize_t n = listener_vft[listener->type]->read_single(listener->fd, msgbuf,
                address_pair_get_remote(&pair));
        if (n < 1)
            return 0;

        /* Process received packet */
        processed_size = forwarder_receive(listener->forwarder, listener,
                msgbuf, &pair, ticks_now());
        if (processed_size <= 0)
            break;

        total_size += processed_size;
    }

    /*
     * Even through the current listener does not allow batching, the connection
     * on which we went packets might do batching (even without sendmmsg), and
     * we need to inform the system that we want to proceed to sending packets.
     */
    forwarder_flush_connections(listener->forwarder);
    return total_size;

}

ssize_t
listener_read_batch(listener_t * listener)
{
    assert(listener);

    size_t processed_size;
    size_t total_size = 0;

    forwarder_t * forwarder = listener->forwarder;
    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    /* Receive messages in the loop as long as we manage to fill the buffers */
    int r = 0;
    do {
        /* Prepare the msgbuf and address pair arrays */
        msgbuf_t * msgbuf[MAX_MSG];
        if (!msgbuf_pool_getn(msgbuf_pool, msgbuf, MAX_MSG))
            break;

        address_pair_t pair[MAX_MSG];
        address_t * address_remote[MAX_MSG];
        for (unsigned i = 0; i < MAX_MSG; i++)
            address_remote[i] = address_pair_get_remote(&pair[i]);

        ssize_t n = listener_vft[listener->type]->read_batch(listener->fd,
                msgbuf, address_remote, MAX_MSG);
        // XXX error check

        for (unsigned i = 0; i < n; i++) {
            processed_size = forwarder_receive(forwarder, listener, msgbuf[i],
                    &pair[i], ticks_now());
            if (processed_size <= 0)
                break;

            total_size += processed_size;
        }

    } while(r == MAX_MSG); /* backpressure based on queue size ? */

    /*
     * Signal to the forwarder that we reached the end of a batch and we need to
     * flush connections out
     */
    forwarder_flush_connections(forwarder);

    return total_size;

}

ssize_t
listener_read_callback(listener_t * listener, int fd, void * user_data)
{
    // XXX make a single callback and arbitrate between read and readbatch
    assert(listener);
    assert(fd == listener->fd);

    if (listener_vft[listener->type]->read_batch)
        return listener_read_batch(listener);

    return listener_read_single(listener);
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
    // XXX memset
    address_t address = ADDRESS4_LOCALHOST(port);

    _setupUdpListener(forwarder, "lo_udp", &address, "lo");
    _setupTcpListener(forwarder, "lo_tcp", &address, "lo");
#endif
}
