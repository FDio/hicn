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

#include "connection.h"
#include "connection_vft.h"

connection_t *
connection_create_on_listener(const listener_t * listener, const address_pair_t * pair,
        const Forwarder * forwarder)
{
    const connection_table_t * table = forwarder_GetConnectionTable(forwarder);

    Connection * connection;
    connection_table_allocate(table, connection);

    unsigned connection_id = connection_table_get_connection_id(table, connection);

    const char * interface_name = listener->getInterfaceName(listener);
    // XXX This should not be there !
    int fd = listener->getSocket(listener, pair);
    bool local = address_is_local(&pair->local);

    return connection_initialize(connection, interface_name, fd, pair, local, connection_id);
}


// This is called by configuration
// XXX different wit create on listener : when listener receives a new
// connection
// !
connection_t *
connection_create(face_type_t type, const address_pair_t * pair,
        Forwarder * forwarder)
{
    assert(face_type_is_valid(type));
    assert(pair);
    assert(forwarder);

    listener_table_t * table = forwarder_GetListenerTable(forwarder);
    ListenerOps *listener = listener_table_lookup(table, type, &pair->local);
    if (!listener) {
        // XXX TODO
        //char *str = addressToString(localAddress);
        ERROR("Could not find listener to match address N/A");
        //parcMemory_Deallocate((void **)&str);
        return NULL;
    }

    return connection_create_on_listener(listener, pair, forwarder);
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
 * @param [in] forwarder - Forwarder to which the connection is associated. This
 *      parameter needs to be non-NULL for connections receiving packets, such
 *      as TCP connections which are very close to UDP listeners, and unlike
 *      bound UDP connections).
 * @return 0 if no error, -1 otherwise
 */
int
connection_initialize(connection_t * connection, face_type_t type,
        const char * interface_name, int fd, const address_pair_t * pair,
        bool local, unsigned connection_id, Forwarder * forwarder)
{
    int rc;

    assert(connection);
    /* Interface name can be NULL eg always for TCP connnections */
    assert(pair);
    assert(address_pair_valid(pair));

    *connection = {
        .id = connection_id,
        .interface_name = strdup(interface_name),
        .type = type,
        .pair = *pair,
        .fd = fd,
//        .up = true,
        .local = local,
        // XXX UDP should start UP, TCP DOWN until remove side answer ?
        .state = CONNECTION_STATE_UNDEFINED,
        .admin_state = CONNECTION_STATE_UP,
#ifdef WITH_POLICY
        .priority = 0,
#endif /* WITH_POLICY */

        .forwarder = forwarder,
        .closed = false,
    };

    rc = connection_vft[connection->type]->initialize(connection);
    if (rc < 0) {
        ERROR("Error initializing %s connection %p for address %s (local=%s)",
            face_type_str(connection->type), connection, "N/A",
            connection_is_local(connection) ? "true" : "false");
        return -1;
    }
    // XXX TODO
    //char *str = pair_ToString(udp->pair);
    DEBUG("%s connection %p created for address %s (local=%s)",
            face_type_str(connection->type), connection, "N/A",
            connection_is_local(connection) ? "true" : "false");
    //free(str);
    return 0;
}

int
connection_finalize(connection_t * connection)
{
    assert(connection);

    connection_vft[connection->type]->finalize(connection);

    free(connection->interface_name);
    free(connection);

    DEBUG("%s connection %p destroyed", face_type_str(connection->type),
            udp);

    return 0;
}

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
        switch(
        if (!command_type_is_valid(command_type))
            break;
        expected = sizeof(header_control_message) +
            command_get_payload_len(command_type);
        if (size < expected)
            return 0;
        forwarder_ReceiveCommand(connection->forwarder, command_type, packet,
                connection->id);
        return expected;
        }
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
        packet_type = MessagePacketType_Interest;
    } else if (messageHandler_IsData(message->messageHead)) {
        packet_type = MessagePacketType_ContentObject;
    } else {
        ERROR("Dropped packet that is not interest nor data");
        return -1;
    }

    // this is an Hicn packet (here we should distinguish between IPv4 and
    // IPv6 tryReadMessage may set nextMessageLength
    msgbuf_from_packet(&msgbuf, packet, expected, packet_type,
            connection_get_id(connection), ticks_now());
    forwarder_Receive(connection->forwarder, &msgbuf, 1);

    return size;
}

int
connection_read_message(connection_t * connection, msgbuf_t * msgbuf)
{
    assert(connection);
    assert(face_type_is_valid(connection);
    assert(msgbuf);

    return connection_vft[face_type]->read_message(connection, msgbuf);
}

uint8_t *
connection_read_packet(connection_t * connection)
{
    assert(connection);
    assert(face_type_is_valid(connection);

    return connection_vft[face_type]->read_packet(connection);
}

uint8_t *
connection_send_packet(const connection_t * connection, const uint8_t * packet)
{

}
