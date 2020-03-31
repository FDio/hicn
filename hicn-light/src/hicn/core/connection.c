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
 * @file connection.c
 * @brief Implementation of hICN connections
 */

#include <assert.h>

#include <hicn/core/forwarder.h>
#include <hicn/util/log.h>
#include <hicn/core/wldr.h>

#include "connection.h"
#include "connection_vft.h"

#define _conn_var(x) _connection_ ## x

#if 0

/* Accessors */

static inline
unsigned
connection_get_id(const connection_t * connection)
{
    return connection->id;
}

static inline
char *
connection_get_name(const connection_t * connection)
{
    return connection->name;
}

static inline
face_type_t
connection_get_type(const connection_t * connection)
{
    return connection->type;
}

static inline
address_pair_t *
connection_get_pair(const connection_t * connection)
{
    return connection->pair;
}

static inline
bool
connection_is_up(const connection_t * connection)
{
    return connection->up;
}

static inline
bool
connection_is_local(const connection_t * connection)
{
    return connection->local;
}

static inline
face_state_t
connection_get_state(const connection_t * connection)
{
    return connection->state;
}

static inline
void
connection_set_state(connection_t * connection, face_state_t state)
{
    connection->state = state;
}

static inline
face_state_t
connection_get_admin_state(const connection_t * connection)
{
    return connection->admin_state;
}

static inline
void
connection_set_admin_state(connection_t * connection, face_state_t state)
{
    connection->admin_state = state;
}

static inline
const char *
connection_get_interface_name(const connection_t * connection)
{
    return connection->interface_name;
}

#ifdef WITH_POLICY

static inline
uint32_t
connection_get_priority(const connection_t * connection)
{
    connection->priority = priority;
}

static inline
void
connection_set_priority(connection_t * connection, uint32_t priority)
{
    connection->priority = priority;
}

static inline
policy_tags_t
connection_get_tags(const connection_t * connection)
{
    return connection->tags;
}

static inline
void
connection_set_tags(connection_t * connection, policy_tags_t tags)
{
    connection->tags = tags;
}

#endif /* WITH_POLICY */

/* API */

#endif

connection_t *
connection_create_on_listener(const listener_t * listener, const char * name,
        const address_pair_t * pair, forwarder_t * forwarder)
{
    const connection_table_t * table = forwarder_get_connection_table(forwarder);

    connection_t * connection;
    connection_table_allocate(table, connection, pair, name);

    unsigned connection_id = connection_table_get_connection_id(table, connection);

    const char * interface_name = listener_get_interface_name(listener);
    // XXX This should not be there !
    int fd = listener_get_socket(listener, address_pair_get_local(pair),
            address_pair_get_remote(pair), NULL);
    bool local = address_is_local(&pair->local);

    if (connection_initialize(connection, listener->type, name, interface_name, fd, pair, local,
                connection_id, forwarder) < 0) {
        connection_table_deallocate(table, connection);
        return NULL;
    }

    return connection;
}


// This is called by configuration
// XXX different wit create on listener : when listener receives a new
// connection
// !
connection_t *
connection_create(face_type_t type, const char * name,
        const address_pair_t * pair, forwarder_t * forwarder)
{
    assert(face_type_is_valid(type));
    assert(pair);
    assert(forwarder);

    listener_table_t * table = forwarder_get_listener_table(forwarder);
    listener_t *listener = listener_table_get_by_address(table, type, &pair->local);
    if (!listener) {
        // XXX TODO
        //char *str = addressToString(localAddress);
        ERROR("Could not find listener to match address N/A");
        //parcMemory_Deallocate((void **)&str);
        return NULL;
    }

    return connection_create_on_listener(listener, name, pair, forwarder);
}

#if 0

    const char * interface_name = listener->getInterfaceName(listener);
    int fd = listener->getSocket(listener, pair);
    bool is_local = address_is_local(&pair->local);


    return udpConnection_Create(forwarder, interface_name, fd, pair, is_local, connid);

    // alternatively
    //
}
#endif

/**
 * @brief Initializes a connection
 *
 * @param [out] connection - Allocated connection buffer (eg. from pool) to be
 *      initialized.
 * @param [in] forwarder - forwarder_t to which the connection is associated. This
 *      parameter needs to be non-NULL for connections receiving packets, such
 *      as TCP connections which are very close to UDP listeners, and unlike
 *      bound UDP connections).
 * @return 0 if no error, -1 otherwise
 */
int
connection_initialize(connection_t * connection, face_type_t type, const char * name,
        const char * interface_name, int fd, const address_pair_t * pair,
        bool local, unsigned connection_id, forwarder_t * forwarder)
{
    int rc;

    assert(connection);
    /* Interface name can be NULL eg always for TCP connnections */
    assert(pair);
    assert(address_pair_valid(pair));

    *connection = (connection_t) {
        .id = connection_id,
        .name = strdup(name),
        .type = type,
        .interface_name = strdup(interface_name),
        .pair = *pair,
        .fd = fd,
//        .up = true,
        .local = local,
        // XXX UDP should start UP, TCP DOWN until remove side answer ?
        .state = FACE_STATE_UNDEFINED,
        .admin_state = FACE_STATE_UP,
#ifdef WITH_POLICY
        .priority = 0,
#endif /* WITH_POLICY */

        .forwarder = forwarder,
        .closed = false,

        /* WLDR */
        .wldr = NULL,
        .wldr_autostart = true,
    };

    connection->data = malloc(connection_vft[connection->type]->data_size);
    if (!connection->data)
        goto ERR_DATA;

    assert(connection_has_valid_type(connection));

    rc = connection_vft[connection->type]->initialize(connection);
    if (rc < 0) {
        goto ERR_VFT;
    }

    // XXX uncertain  as fd is created by the listener !!
    // XXX check whether it is registered !
#if 0
    connection->fd = connection_vft[connection->type]->get_socket(connection, address, NULL, interface_name);
    if (connection->fd < 0) {
        ERROR("Error creating connection fd: (%d) %s", errno, strerror(errno));
        goto ERR_FD;
    }

    // XXX data should be pre-allocated here

    if (loop_register_fd(MAIN_LOOP, connection->fd, connection,
                connection_vft[connection->type]->read_callback, NULL) < 0)
        goto ERR_REGISTER_FD;
#endif

    // XXX TODO
    //char *str = pair_ToString(udp->pair);
    DEBUG("%s connection %p created for address %s (local=%s)",
            face_type_str(connection->type), connection, "N/A",
            connection_is_local(connection) ? "true" : "false");
    //free(str);
    //
    return 0;

#if 0
ERR_REGISTER_FD:
#ifndef _WIN32
    close(connection->fd);
#else
    closesocket(connection->fd);
#endif
ERR_FD:
#endif
ERR_VFT:
    free(connection->data);
ERR_DATA:
    free(connection->interface_name);
    free(connection->name);
    return -1;
}

int
connection_finalize(connection_t * connection)
{
    assert(connection);

    if (connection->wldr)
        wldr_free(connection->wldr);

    connection_vft[connection->type]->finalize(connection);

    free(connection->interface_name);
    free(connection);

    DEBUG("%s connection %p destroyed", face_type_str(connection->type),
            connection);

    return 0;
}

#if 0
// XXX put in common the validation and processing of commands with UDP and hICN
// listeners !
command_type_t
_isACommand(PARCEventBuffer *input)
{
    size_t bytesAvailable = parcEventBuffer_GetLength(input);
    parcAssertTrue(bytesAvailable >= sizeof(header_control_message),
            "Called with too short an input: %zu", bytesAvailable);

    uint8_t *msg = parcEventBuffer_Pullup(input, bytesAvailable);

    message_type_t message_type = message_type_from_uchar(msg[0]);
    //if (!message_type_is_valid(message_type))
    if (message_type != REQUEST_LIGHT)
        return COMMAND_TYPE_N;

    return command_type_from_uchar(msg[1]);
}

// XXX new function to process all incoming bytes
// result : consumed, discard/invalid, wait for more
// PRE: buffer has at least 8 bytes (to get the length of all packets)
// This function is only used to make decisions
/**
 * \return the number of consumed bytes, or a negative value in case of error
 */
// XXX mutualize with listener_process_buffer
size_t
connection_process_buffer(connection_t * connection, const uint8_t * buffer, size_t size)
{
    size_t expected;

    /* Too small a packet is not useful to decide between a control message and
     * an hICN packet, the size of a control message is enough to test for both
     * pakcet types */
    if (size < sizeof(header_control_message))
        return 0;

    /* We expect complete packets most of the time, so don't bother with state */
    message_type_t message_type = message_type_from_uchar(msg[0]);
    if (message_type == REQUEST_LIGHT) {
        command_type_t command_type = command_type_from_uchar(msg[1]);
        if (!command_type_is_valid(command_type))
            break;
        expected = sizeof(header_control_message) +
            command_get_payload_len(command_type);
        if (size < expected)
            return 0;
        forwarder_receive_command(connection->forwarder, command_type, packet,
                connection->id);
        return expected;
    }

    if (!messageHandler_IsValidHicnPacket(packet)) {
        WARN("Connection #%u: Malformed packet received",
                connection_get_id(connection));
        return -1;
    }

    /* Check that we have a full packet */
    expected = messageHandler_GetTotalPacketLength(packet),
    if (size < expected)
        return 0;

    msgbuf_t msgbuf;
    MessagePacketType packet_type;
    if (messageHandler_IsInterest(message->messageHead)) {
        packet_type = MESSAGE_TYPE_INTEREST;
    } else if (messageHandler_IsData(message->messageHead)) {
        packet_type = MESSAGE_TYPE_DATA;
    } else {
        ERROR("Dropped packet that is not interest nor data");
        return -1;
    }

    // this is an Hicn packet (here we should distinguish between IPv4 and
    // IPv6 tryReadMessage may set nextMessageLength
    msgbuf_from_packet(&msgbuf, packet, expected, packet_type,
            connection_get_id(connection), ticks_now());
    forwarder_receive(connection->forwarder, &msgbuf, 1);

    return size;
}

int
connection_read_message(connection_t * connection, msgbuf_t * msgbuf)
{
    assert(connection);
    assert(face_type_is_valid(connection->type));
    assert(msgbuf);

    return connection_vft[connection->type]->read_message(connection, msgbuf);
}

uint8_t *
connection_read_packet(connection_t * connection)
{
    assert(connection);
    assert(face_type_is_valid(connection->type));

    return connection_vft[connection->type]->read_packet(connection);
}
#endif

int
connection_send_packet(const connection_t * connection, const uint8_t * packet,
    size_t size)
{
    assert(connection);
    assert(face_type_is_valid(connection->type));
    assert(packet);

    return connection_vft[connection->type]->send_packet(connection, packet, size);
}

// ALL DEPRECATED CODE HERE TO BE UPDATED

// XXX nexthops null ?? to be removed ???
bool
_connection_send(const connection_t * connection, msgbuf_t * msgbuf, bool queue)
{
    return connection_vft[connection->type]->send(connection, msgbuf, queue);
}

bool
connection_send(const connection_t * connection, msgbuf_t * msgbuf, bool queue)
{
    assert(connection);

    /* NULL message means flush */
    if (!msgbuf)
        return _connection_send(connection, NULL, false);

    if (!connection_is_up(connection))
        return false;

    if (msgbuf_get_type(msgbuf) == MESSAGE_TYPE_DATA) {
        uint8_t conn_id = (uint8_t)connection_get_id(connection);
        msgbuf_update_pathlabel(msgbuf, conn_id);
    }

    if (connection->wldr)
        wldr_set_label(connection->wldr, msgbuf);
    else
        msgbuf_reset_wldr_label(msgbuf);

    return _connection_send(connection, msgbuf, queue);
}

/*
 * here the wldr header is alreay set: this message is a retransmission or a
 * notification
 *
 * we need to recompute the path label since we always store a pointer to
 * the same message if this message will be sent again to someone else, the
 * new path label must be computed starting from the orignal label. Note
 * that we heve the same problem in case of PIT aggregation. That case is
 * handled inside the MessageProcessor. This is specific to WLDR
 * retransmittions. This is done only for data packets
 */
bool
connection_resend(const connection_t * connection, msgbuf_t * msgbuf, bool
        notification)
{
    assert(connection);
    assert(msgbuf);

    bool ret = false;

    if (!connection_is_up(connection))
        return ret;

    if (msgbuf_get_type(msgbuf) == MESSAGE_TYPE_DATA) {
      uint8_t conn_id = (uint8_t)connection_get_id(connection);
      uint32_t old_path_label = msgbuf_get_pathlabel(msgbuf);
      msgbuf_update_pathlabel(msgbuf, conn_id);
      ret = _connection_send(connection, msgbuf, false); /* no queueing */
      msgbuf_set_pathlabel(msgbuf, old_path_label);
    } else {
      ret = _connection_send(connection, msgbuf, false); /* no queueing */
    }

  return ret;
}

#if 0
bool connection_sendv(const connection_t * conn, struct iovec *msg,
    size_t size) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  parcAssertNotNull(msg, "Parameter message must be non-null");

  return ioOperations_SendIOVBuffer(conn->ops, msg, size);
}

void connection_probe(connection_t * conn, uint8_t * probe) {
  ioOperations_SendProbe(conn->ops, probe);
}

void connection_hangle_probe(connection_t * conn, uint8_t *probe){
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  parcAssertNotNull(probe, "Parameter pkt must be non-null");

  if(messageHandler_IsInterest(probe)){
    messageHandler_CreateProbeReply(probe, HF_INET6_TCP);
    ioOperations_SendProbe(conn->ops, probe);
  }
}
#endif


/* WLDR */

void
connection_wldr_allow_autostart(connection_t * connection, bool value)
{
    connection->wldr_autostart = value;
}

bool
connection_wldr_autostart_is_allowed(connection_t * connection)
{
    return connection->wldr_autostart;
}

void
connection_wldr_enable(connection_t * connection, bool value)
{
    if (connection_is_local(connection))
        return;
    if (value) {
        if (connection->wldr)
            return;
        connection->wldr = wldr_create();
    } else {
        if (!connection->wldr)
            return;
        wldr_free(connection->wldr);
    }
}

bool
connection_has_wldr(const connection_t * connection)
{
    return !!connection->wldr;
}

void
connection_wldr_detect_losses(const connection_t * connection, msgbuf_t * msgbuf)
{
    if (!connection->wldr)
        return;
    wldr_detect_losses(connection->wldr, connection, msgbuf);
}

void
connection_wldr_handle_notification(const connection_t * connection, msgbuf_t * msgbuf)
{
    if (!connection->wldr)
        return;
    wldr_handle_notification(connection->wldr, connection, msgbuf);
}
