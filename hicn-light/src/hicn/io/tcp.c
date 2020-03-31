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
 * Common activity for STREAM based listeners.
 */

#include <errno.h>
#ifndef _WIN32
#include <unistd.h> // fcntl
#endif /* _WIN32 */
#include <fcntl.h> // fcntl
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <hicn/core/connection.h>
#include <hicn/core/connection_vft.h>
#include <hicn/core/listener.h>
#include <hicn/core/listener_vft.h>
#include <hicn/core/msgbuf.h>
#include <hicn/core/forwarder.h>

#include <hicn/core/messageHandler.h>

#include <hicn/utils/commands.h>
#include <hicn/util/log.h>

#include <hicn/hicn.h>
// 128 KB output queue
#define OUTPUT_QUEUE_BYTES (128 * 1024)

#define RECV_BUFLEN 8192
#define MTU 1500

// XXX TODO what is exactly an eventqueue
// XXX TODO can't we write directly to the socket ?

/******************************************************************************
 * Listener
 ******************************************************************************/

typedef struct {
} listener_tcp_data_t;

static
int
listener_tcp_initialize(listener_t * listener)
{

    ERROR("[listener_tcp_initialize] Not implemented");

    return 0;
}

static
void
listener_tcp_finalize(listener_t * listener)
{

    ERROR("[listener_tcp_finalize] Not implemented");
}

static
int
listener_tcp_punt(const listener_t * listener, const char * prefix_s)
{
    ERROR("[listener_tcp_punt] Not implemented");
    return -1;
}

static
int
listener_tcp_get_socket(const listener_t * listener, const address_t * local,
        const address_t * remote, const char * interface_name)
{

    ERROR("[listener_tcp_get_socket] Not implemented");
    return -1;

}

static
void
listener_tcp_read_callback(listener_t * listener, int fd, void * data)
{
    ERROR("[listener_tcp_read_callback] Not implemented");

}

DECLARE_LISTENER(tcp);

/******************************************************************************
 * Connection
 ******************************************************************************/


typedef struct {
    /* Partial receive buffer */
    u8 buf[RECV_BUFLEN];
    size_t roff; /**< Read offset */
    size_t woff; /**< Write offset */


    // XXX this should be initialized with the header length, and tells what we
    // expect to receive next...
    size_t next_len;
    struct bufferevent * bufferevent;
} connection_tcp_data_t;

// XXX This seems more a listener code !
// XXX we must have accept to the connection table to spawn new ones !!
// XXX equivalent to initialize
int
connection_tcp_accept(connection_t * connection, forwarder_t *forwarder, int fd,
        address_pair_t *pair, bool local, unsigned connection_id)
{
    assert(connection);
    assert(forwarder);

    *connection = (connection_t) {
        .id = connection_id,
        .interface_name = NULL,
        .type = FACE_TYPE_TCP,
        .pair = *pair,
        .fd = fd,
        .local = local,
        // As we are accepting a connection, we begin in the UP state
        .state = FACE_STATE_UP,
        .admin_state = FACE_STATE_UP,
#ifdef WITH_POLICY
        .priority = 0,
#endif /* WITH_POLICY */

        .forwarder = forwarder,
        .closed = false,
    };

    // XXX this new connection needs to be registered
    //char *str = pair_ToString(udp->pair);
    INFO("%s connection %p created for address %s (local=%s)",
            face_type_str(connection->type), connection, "N/A",
            connection_is_local(connection) ? "true" : "false");
    //free(str);

    return 0;
}

int
make_socket(address_pair_t * pair)
{
#ifndef _WIN32
    int fd = socket(address_family(&pair->local), SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        goto ERR_SOCKET;
    }
#else
    SOCKET fd = socket(address_family(&pair->local), SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) {
        perror("socket");
        goto ERR_SOCKET;
    }
#endif /* _WIN32 */

    /* Set non-blocking flag */
#ifndef _WIN32
    int flags = fcntl(fd, F_GETFL, NULL);
    if (flags == -1) {
        perror("F_GETFL");
        goto ERR;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("F_SETFL");
        goto ERR;
    }
#else
    if (ioctlsocket(fd, FIONBIO, &(u_long){1}) != NO_ERROR) {
        perror("ioctlsocket");
        goto ERR;
    }
#endif /* _WIN32 */

    if (bind(fd, address_sa(&pair->local), address_socklen(&pair->local)) == -1) {
        perror("bind");
        goto ERR;
    }

    if (connect(fd, address_sa(&pair->remote), address_socklen(&pair->remote)) < 0) {
      perror("connect");
      goto ERR;
    }


    return 0;

ERR:
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif

ERR_SOCKET:
  return -1;

}

static
int
connection_tcp_initialize(connection_t * connection)
{
    assert(connection);
    assert(connection->type = FACE_TYPE_TCP);

    connection_tcp_data_t * data = connection->data;
    assert(data);

    data->roff = 0;
    data->woff = 0;

    connection->fd = make_socket(connection_get_pair(connection));
    if (connection->fd < 0) {
        ERROR("Error creating TCP socket");
        return -1;
    }

    //char *pair_str = address_pair_ToString(pair);
    INFO("%s connection %p connect for address pair %s",
            face_type_str(connection->type), connection, "N/A");
    //free(pair_str);

    return 0;
}

// XXX a part needs to be handled in the connection.c
static
void
connection_tcp_finalize(connection_t * connection)
{
    if (!connection->closed) {
        connection->closed = true;
        // XXX need to delete the connection like previously in the connection
        // manager
    }

    INFO("%s connection %p destroyed", face_type_str(connection->type),
            connection);
    // XXX need to release the "connection"
}

#if 0
static
bool
connection_tcp_sendv(connnection_t * connection, struct iovec * iov,
        size_t size)
{
    assert(connection);
    assert(iov);

    if (!connection_is_up(connection)) {
        ERROR("Connection #%u tried to send to down connection (up=%d closed=%d)",
                connection_get_id(connection),
                connection_get_up(connection) ? "true" : "false",
                connection_get_closed(connection) ? "true" : "false");
        return false;
    }

    PARCEventBuffer *buffer =
        parcEventBuffer_GetQueueBufferOutput(connection->events);
    size_t buffer_backlog = parcEventBuffer_GetLength(buffer);
    parcEventBuffer_Destroy(&buffer);

    if (buffer_backlog >= OUTPUT_QUEUE_BYTES) {
        WARN("Connection #%u Writing to buffer backlog %zu bytes DROP MESSAGE",
                connection_get_id(connection), buffer_backlog);
        return false;
    }

#if 0
    /* DEBUG */
    size_t length = 0;
    for (int i = 0; i < size; i++)
        length += message[i].iov_len;
    DEBUG("Connection #%u writing %zu bytes to buffer with backlog %zu bytes",
            connection_get_id(connection), length, buffer_backlog);
#endif

    /* Write directly into the parcEventQueue without passing through message */
    for (int i = 0; i < size; i++) {
        if (parcEventQueue_Write(conn->events, iov[i].iov_base,
                    iov[i].iov_len) != 0)
            return false;
    }

    return true;
}
#endif

/**
 * @function streamConnection_Send
 * @abstract Non-destructive send of the message.
 * @discussion
 *   Send uses message_CopyToStreamBuffer, which is a non-destructive write.
 *   The send may fail if there's no buffer space in the output queue.
 *
 * @param dummy is ignored.  A stream has only one peer.
 * @return <#return#>
 */
// XXX address not used anywhere
// XXX too much repeated code with sendv here
static
int
connection_tcp_send(const connection_t * connection, //const address_t * address,
        msgbuf_t * msgbuf, bool queue)
{
    assert(connection);
    assert(address);
    /* msgbuf can be NULL */

    /* No need to flush */
    if (!msgbuf)
        return true;

    if (!connection_is_up(connection)) {
        ERROR("Connection #%u tried to send to down connection (up=%d closed=%d)",
                connection_get_id(connection),
                connection_is_up(connection) ? "true" : "false",
                connection_is_closed(connection) ? "true" : "false");
        return false;
    }

    // XXX TODO write to fd
#if 0
    PARCEventBuffer *buffer =
        parcEventBuffer_GetQueueBufferOutput(connection->events);
    size_t buffer_backlog = parcEventBuffer_GetLength(buffer);
    parcEventBuffer_Destroy(&buffer);

    if (buffer_backlog >= OUTPUT_QUEUE_BYTES) {
        WARN("Connection #%u Writing to buffer backlog %zu bytes DROP MESSAGE",
                connection_get_id(connection), buffer_backlog);
        return false;
    }

    DEBUG("Connection #%u Writing %zu bytes to buffer with backlog %zu bytes",
            connection_get_id(connection), msgbuf_len(message), buffer_backlog);

    return (parcEventQueue_Write(connection->events, msgbuf_packet(message),
                msgbuf_len(message)) == 0);
#endif
    return true;
}

static
int
connection_tcp_send_packet(const connection_t * connection,
        const uint8_t * packet, size_t size)
{
    /* Not implemented for local connections */
    // XXX shall we set the pointer to NULL and add a check ?

    ERROR("[connection_tcp_send_packet] Not implemented");

    return -1;
}

// =================================================================
// the actual I/O functions

// not needed anymore ?
#if 0
// XXX this is called iif there is sufficient data to read, otherwise it raises
// an assertion error. This was a problem before I guess
static
int
connection_tcp_read_message(connection_t * connection, msgbuf_t * msgbuf)
{
    assert(connection);
    assert(msgbuf);

    connection_tcp_data_t * data = connection->data;
    assert(data);

    size_t n = evbuffer_get_length(data->evbuffer);
    // XXX this check was wrong
    // parcAssertTrue(n >= sizeof(header_control_message),
            "Called with too short an input: %zu", n);

    // XXX WTF
    if (stream->next_len == 0) {
        // this linearizes the first messageHandler_GetIPv6HeaderLength() bytes of the
        // input buffer's iovecs and returns a pointer to it.
        uint8_t *fh = parcEventBuffer_Pullup(data->evbuffer, sizeof(header_control_message));

        // Calculate the total message size based on the fixed header
        stream->next_len = messageHandler_GetTotalPacketLength(fh);
    }
    // This is not an ELSE statement.  We can both start a new message then
    // check if there's enough bytes to read the whole thing.

    if (n < stream->next_len)
        return -1;

    uint8_t packet_type;
    if (messageHandler_IsInterest(packet)) {
        packet_type = MESSAGE_TYPE_INTEREST;
    } else if (messageHandler_IsData(packet)) {
        packet_type = MESSAGE_TYPE_DATA;
    } else {
        ERROR("Dropped packet that is not interest nor data");
        goto ERR;
    }

    if (evbuffer_remove(data->evbuffer, data->packet, data->next_len) < 0)
        return -1;

    msgbuf_from_packet(msgbuf, data->packet, packet_type, stream->id,
            ticks_now());

    // now reset message length for next packet
    data->next_len = 0;
    return 0;

ERR:
    evbuffer_drain(data->evbuffer, data->next_len);
    return -1;
}
#endif

/**
 * @function conn_readcb
 * @abstract Event callback for reads
 * @discussion
 *   Will read messages off the input.  Continues reading as long as we
 *   can get a header to determine the next message length or as long as we
 *   can read a complete message.
 *
 *   This function manipulates the read low water mark.  (1) read a fixed header
 * plus complete message, then set the low water mark to FIXED_HEADER_LEN.  (2)
 * read a fixed header, but not a complete message, then set low water mark to
 * the total mesage length.  Using the low water mark like this means the buffer
 * event will only trigger on meaningful byte boundaries when we can get actual
 *   work done.
 *
 * @param <#param1#>
 * @return <#return#>
 */
static
void
connection_tcp_read_callback(connection_t * connection, int fd, void * user_data)
{
    assert(!!(what & PARCEventType_Read));
    assert(connection_void);

    connection_tcp_data_t * data = connection->data;
    assert(RECV_BUFLEN - data->woff > MTU);

    /* No batching here as code is not expected to receive much throughput */
    for (;;) {
        ssize_t n = recv(connection->fd, data->buf + data->woff,
                RECV_BUFLEN - data->woff, 0);
        if (n == 0) /* EOF */
            return; // XXX close connection
        if (n < 0) {
            if (errno == EWOULDBLOCK)
                break;
            perror("recv");
            return; // XXX close connection
        }
        data->woff += n;

        /* Process */
        uint8_t * packet = data->buf + data->roff;
        size_t size = data->woff - data->roff; /* > 0 */

        ssize_t used = listener_read_callback(connection->forwarder, NULL, fd,
                address_pair_get_local(&connection->pair), packet, size);
        if (used < 0)
            return; // XXX close connection ?
        if (used == 0)
            break; /* We would have received more if there was still packets to be read */
        data->roff += used;
        assert(data->roff <= data->woff);

        if (data->roff == data->woff) {
            /* Reset state whenever possible to avoid memcpy's */
            data->roff = 0;
            data->woff = 0;
            return;
        }
    }

    /* Make sure there is enough remaining space in the buffer */
    if (RECV_BUFLEN - data->woff < MTU) {
        /*
         * There should be no overlap provided a sufficiently large BUFLEN, but
         * who knows.
         */
        memmove(data->buf, data->buf + data->roff, data->woff - data->roff);
        data->woff -= data->roff;
        data->roff = 0;
    }

    return;
}

#if 0
static
void
connection_tcp_callback(connection_t * connection, int fd, void * user_data)
{
    if (events & PARCEventQueueEventType_Connected) {
        INFO("Connection %u is connected", stream->id);

        // if the stream was closed, do not transition to an UP state
        if (!stream->isClosed) {
            _setConnectionState(stream, true);
        }
    } else if (events & PARCEventQueueEventType_EOF) {
        INFO("connid %u closed.", stream->id);

        parcEventQueue_Disable(stream->events, PARCEventType_Read);

        _setConnectionState(stream, false);

        if (!stream->isClosed) {
            stream->isClosed = true;
            // XXX TODO destroy the connection
        }
    } else if (events & PARCEventQueueEventType_Error) {
        ERROR("Got an error on the connection %u: %s", stream->id,
                strerror(errno));

        parcEventQueue_Disable(stream->events,
                PARCEventType_Read | PARCEventType_Write);

        _setConnectionState(stream, false);

        if (!stream->isClosed) {
            stream->isClosed = true;
            // XXX TODO destroy the connection
        }
    }
    /* None of the other events can happen here, since we haven't enabled
     * timeouts */
}
#endif

DECLARE_CONNECTION(tcp)
