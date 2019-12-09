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
#include <hicn/hicn-light/config.h>
#include <hicn/core/connectionState.h>
//#include <hicn/io/ioOperations.h>
#include <hicn/base/address_pair.h>
#include <hicn/base/msgbuf.h>

typedef enum {
    CONN_GRE,
    CONN_TCP,
    CONN_UDP,
    CONN_MULTICAST,
    CONN_L2,
    CONN_HICN
} connection_type_t;

#ifdef WITH_MAPME
typedef enum {
  CONNECTION_EVENT_CREATE,
  CONNECTION_EVENT_DELETE,
  CONNECTION_EVENT_UPDATE,
  CONNECTION_EVENT_SET_UP,
  CONNECTION_EVENT_SET_DOWN,
  CONNECTION_EVENT_PRIORITY_CHANGED,
  CONNECTION_EVENT_TAGS_CHANGED,
} connection_event_t;

#endif /* WITH_MAPME */

#ifdef WITH_POLICY
#include <hicn/policy.h>
#endif /* WITH_POLICY */

struct connection;
typedef struct connection Connection;

#define CONNECTION_ID_INVALID UINT32_MAX
#define connection_id_is_valid(id) (id != CONNECTION_ID_INVALID)

/**
 * Creates a connection object.
 */
Connection *connection_Create(void /* IoOperations */ * ops);

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
bool connection_Send(const Connection *conn, msgbuf_t *message, bool queue);

/**
 * @function connection_SendIOVBuffer
 * @abstract Sends an IOV buffer
 */
bool connection_SendIOVBuffer(const Connection *conn, struct iovec *msg,
    size_t size);

/**
 * @function connection_SendBuffer
 * @abstract Sends a buffer
 */
bool connection_SendBuffer(const Connection *conn, u8 * buffer, size_t length);

/**
 * Return the `IoOperations` instance associated with the specified `Connection`
 * instance.
 * @param [in] connection The allocated connection
 * @return a pointer to the IoOperations instance associated by th specified
 * connection.
 */
void /* IoOperations */ * connection_GetIoOperations(const Connection *conn);

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
const address_pair_t * connection_GetAddressPair(const Connection *conn);

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

bool connection_ReSend(const Connection *conn, msgbuf_t *message,
                       bool notification);

void connection_Probe(Connection *conn, uint8_t *probe);

void connection_HandleProbe(Connection *conn, uint8_t *message);

void connection_AllowWldrAutoStart(Connection *conn, bool allow);

void connection_EnableWldr(Connection *conn);

void connection_DisableWldr(Connection *conn);

bool connection_HasWldr(const Connection *conn);

bool connection_WldrAutoStartAllowed(const Connection *conn);

void connection_DetectLosses(Connection *conn, msgbuf_t *message);

void connection_HandleWldrNotification(const Connection *conn, msgbuf_t *message);

connection_state_t connection_GetState(const Connection *conn);

void connection_SetState(Connection *conn, connection_state_t state);

connection_state_t connection_GetAdminState(const Connection *conn);

void connection_SetAdminState(Connection *conn, connection_state_t admin_state);

#ifdef WITH_POLICY
uint32_t connection_GetPriority(const Connection *conn);

void connection_SetPriority(Connection *conn, uint32_t priority);
#endif /* WITH_POLICY */

const char * connection_GetInterfaceName(const Connection * conn);

#ifdef WITH_POLICY
void connection_AddTag(Connection *conn, policy_tag_t tag);
void connection_RemoveTag(Connection *conn, policy_tag_t tag);
policy_tags_t connection_GetTags(const Connection *conn);
void connection_SetTags(Connection *conn, policy_tags_t tags);
void connection_ClearTags(Connection *conn);
int connection_HasTag(const Connection *conn, policy_tag_t tag);
#endif /* WITH_POLICY */

#endif  // connection_h
