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
 * @file dummy.c
 * @brief Implementation of dummy face
 */

#include <hicn/base/listener.h>
#include <hicn/base/connection.h>
#include <hicn/util/log.h>

#include "dummy.h"

/******************************************************************************
 * Listener
 ******************************************************************************/

typedef struct {
    /* ... */
} listener_dummy_data_t;

static void _readcb(int fd, PARCEventType what, void * listener_void)
{
    /* ... */
}

static
int
listener_dummy_initialize(listener_t * listener, void **pdata)
{
    assert(listener);
    assert(data);
    assert(!*data);

    listener_dummy_data_t * data = malloc(sizof(listener_dummy_data_t));
    if (!data)
        return -1;
    *pdata = data;

    /* ... */

    Dispatcher * dispatcher = forwarder_GetDispatcher(listener->forwarder);
    listener->event = dispatcher_CreateNetworkEvent(dispatcher,
            true, _readcb, (void*)listener, listener->fd);
    dispatcher_StartNetworkEvent(dispatcher, listener->event);

    return 0;
}

static
int
listener_dummy_finalize(listener_t * listener)
{
    assert(listener);
    assert(listener_get_type(listener) == LISTENER_TYPE_UDP);

    Dispatcher * dispatcher = forwarder_GetDispatcher(listener->forwarder);
    dispatcher_DestroyNetworkEvent(dispatcher, &listener->event);

    return 0;
}

static
int
listener_dummy_get_socket(const listener_t * listener, const address_pair_t * pair)
{
    assert(listener);
    assert(listener_get_type(listener) == LISTENER_TYPE_UDP);
    assert(pair);

    /* ... */

    return -1;

}



DECLARE_LISTENER(dummy);

/******************************************************************************
 * Connection
 ******************************************************************************/

typedef struct {
    /* ... */
} connection_dummy_data_t;

static
int
connection_dummy_initialize(connection_t * connection,
        const char * interface_name, int fd, const address_pair_t * pair,
        bool local, unsigned connection_id, void **pdata)
{

    assert(connection);
    assert(connection->type == CONNECTION_TYPE_UDP);
    assert(interface_name);
    assert(address_pair);
    assert(data);
    assert(!*data);

    connection_dummy_data_t * data = malloc(sizof(connection_dummy_data_t));
    if (!data)
        return -1;
    *pdata = data;

    /* ... */

    return 0;
}

static
int
connection_dummy_send(const connection_t * connection, const address_t * address,
        msgbuf_t * msgbuf, bool queue)
{
    assert(connection);
    assert(address);
    /* msgbuf can be NULL */

    connection_dummy_data_t * data = connection->data;
    assert(data);

    /* ... */

    return true;
}

static
bool
connection_dummy_sendv(const connection_t * connection, struct iovec * iov,
        size_t size)
{

    assert(connetion);
    assert(iov);

    connection_dummy_data_t * data = connection->data;
    assert(data);

    /* ... */

    return true;
}

static
void
connection_dummy_send_packet(const connection_t * connection, const uint8_t * packet)
{
    assert(ops);
    assert(packet);

    /* ... */
}

DECLARE_CONNECTION(dummy);
