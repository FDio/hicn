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
 * @file connection.h
 * @brief Wrapper for different types of connections
 *
 * A connection wraps a specific set of {@link IoOperations}.  Those operations
 * allow for input and output.  Connections get stored in the Connection Table.
 *
 */

#ifndef connection_h
#define connection_h
#include <src/config.h>
#include <src/io/ioOperations.h>
#include <src/utils/address.h>

// packet types for probing
#define PACKET_TYPE_PROBE_REQUEST 5
#define PACKET_TYPE_PROBE_REPLY 6

struct connection;
typedef struct connection Connection;

/**
 * Creates a connection object.
 */
Connection *connection_Create(IoOperations *ops);

/**
 * @function connection_Release
 * @abstract Releases a reference count, destroying on last release
 * @discussion
 *   Only frees the memory on the final reference count.  The pointer will
 *   always be NULL'd.
 */
void connection_Release(Connection **connectionPtr);

/**
 * @function connection_Acquire
 * @abstract A reference counted copy.
 * @discussion
 *   A shallow copy, they share the same memory.
 */
Connection *connection_Acquire(Connection *connection);

/**
 * @function connection_Send
 * @abstract Sends the message on the connection
 * @return true if message sent, false if connection not up
 */
bool connection_Send(const Connection *conn, Message *message);

/**
 * @function connection_SendCommandResponse
 * @abstract Sends a response (ack/nack) for a command
 */
bool connection_SendCommandResponse(const Connection *conn, struct iovec *msg);

/**
 * Return the `IoOperations` instance associated with the specified `Connection`
 * instance.
 * @param [in] connection The allocated connection
 * @return a pointer to the IoOperations instance associated by th specified
 * connection.
 */
IoOperations *connection_GetIoOperations(const Connection *conn);

/**
 * Returns the unique identifier of the connection
 * Calls the underlying IoOperations to fetch the connection id
 * @param [in] connection The allocated connection
 * @return unsigned The unique connection id
 */
unsigned connection_GetConnectionId(const Connection *conn);

/**
 * Returns the (remote, local) address pair that describes the connection
 * @param [in] connection The allocated connection
 * @return non-null The connection's remote and local address
 * @return null Should never return NULL
 */
const AddressPair *connection_GetAddressPair(const Connection *conn);

/**
 * Checks if the connection is in the "up" state
 * @param [in] connection The allocated connection
 * @return true The connection is in the "up" state
 * @return false The connection is not in the "up" state
 */
bool connection_IsUp(const Connection *conn);

/**
 * Checks if the connection is to a Local/Loopback address
 *
 * A local connection is PF_LOCAL (PF_UNIX) and a loopback connection is
 * 127.0.0.0/8 or ::1 for IPv6.
 *
 * @param [in] connection The allocated connection
 *
 * @retval true The connection is local or loopback
 * @retval false The connection is not local or loopback
 */
bool connection_IsLocal(const Connection *conn);

/**
 * Returns an opaque pointer representing the class of the Io Operations
 *
 * Returns an opaque pointer that an implementation can use to detect if
 * the connection is based on that class.
 *
 * @param [in] conn The Connection to analyze
 *
 * @return non-null An opaque pointer for each concrete implementation
 */
const void *connection_Class(const Connection *conn);

bool connection_ReSend(const Connection *conn, Message *message,
                       bool notification);

void connection_Probe(Connection *conn);

void connection_HandleProbe(Connection *conn, uint8_t *message,
                            Ticks actualTime);

uint64_t connection_GetDelay(Connection *conn);

void connection_AllowWldrAutoStart(Connection *conn, bool allow);

void connection_EnableWldr(Connection *conn);

void connection_DisableWldr(Connection *conn);

bool connection_HasWldr(const Connection *conn);

bool connection_WldrAutoStartAllowed(const Connection *conn);

void connection_DetectLosses(Connection *conn, Message *message);

void connection_HandleWldrNotification(Connection *conn, Message *message);
#endif  // connection_h
