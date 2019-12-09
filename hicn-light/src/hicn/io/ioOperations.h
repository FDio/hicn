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
 * Defines the interface all connections use to communicate with the forwarder.
 */

/**
 * I/O is built around a callback structure.  The connection table contains an
 * operations structure built around function pointers.  These allow the
 * connection table to be agnostic about underlying connections.
 */

#ifndef io_h
#define io_h

#include <hicn/base/msgbuf.h>
#include <hicn/base/address.h>
#include <hicn/base/address_pair.h>
#include <hicn/core/connectionState.h>
#include <hicn/core/ticks.h>
#include <hicn/utils/commands.h> // list_connections_type

// packet types for probing
#define PACKET_TYPE_PROBE_REQUEST 5
#define PACKET_TYPE_PROBE_REPLY 6

struct io_ops;
typedef struct io_ops IoOperations;

/**
 * @typedef IoOperations
 * @abstract The IO Operations structure abstracts an connection's properties
 * and send() method
 * @constant context Implementation specific opaque data, passed back on each
 * call
 * @constant send function pointer to send a message, does not destroy the
 * message
 * @constant getRemoteAddress function pointer to return the "to" address
 * associated with the connection. Some connections might not have a specific
 * peer, such as multicast, where its the group address.
 * @constant isUp test if the connection is up, ready to send a message.
 * @constant isLocal test if the connection is local to the host.
 * @constant getConnectionId returns the hicn-light id for the connection.
 * @constant destroy releases a refernce count on the connection and possibly
 * destroys the connection.
 * @constant class A unique identifier for each class that instantiates
 * IoOperations.
 * @constant getConnectionType Returns the type of connection (TCP, UDP, L2,
 * etc.) of the underlying connection.
 * @constant getState Returns the current state of the connection (redundant
 * with isUp for added for completeness of the API).
 * @constant setState Allows to mark the current state of a connection.
 * @constant getAdminState Returns the administrative state of a connection (as
 * requested by the user, which might occasionally differ from the current
 * state).
 * @constant setAdminState Allows to set the administrative state of a
 * connection.
 * @constant getInterfaceName Returns the interface name associated to a
 * connection.
 * @discussion <#Discussion#>
 */
struct io_ops {
  void *closure;
  bool (*send)(IoOperations *ops, const address_t *nexthop, msgbuf_t *message, bool queue);
  bool (*sendIOVBuffer)(IoOperations *ops, struct iovec *message, size_t
      size);
  const address_t *(*getRemoteAddress)(const IoOperations *ops);
  const address_pair_t *(*getAddressPair)(const IoOperations *ops);
  bool (*isUp)(const IoOperations *ops);
  bool (*isLocal)(const IoOperations *ops);
  unsigned (*getConnectionId)(const IoOperations *ops);
  void (*destroy)(IoOperations **opsPtr);
  const void *(*class)(const IoOperations *ops);
  list_connections_type (*getConnectionType)(const IoOperations *ops);
  void (*sendProbe)(IoOperations *ops, uint8_t *message);
  connection_state_t (*getState)(const IoOperations *ops);
  void (*setState)(IoOperations *ops, connection_state_t state);
  connection_state_t (*getAdminState)(const IoOperations *ops);
  void (*setAdminState)(IoOperations *ops, connection_state_t admin_state);
#ifdef WITH_POLICY
  uint32_t (*getPriority)(const IoOperations *ops);
  void (*setPriority)(IoOperations *ops, uint32_t priority);
#endif /* WITH_POLICY */
  const char * (*getInterfaceName)(const IoOperations *ops);
};

/**
 * Returns the closure of the interface
 *
 * The creator of the closure sets this parameter to store its state.
 *
 * @param [in] ops A concrete instance of the interface
 *
 * @return The value set by the concrete instance of the interface.
 *
 * Example:
 * @clode
 * {

 * }
 * @endcode
 */
void *ioOperations_GetClosure(const IoOperations *ops);

/**
 * Release all memory related to the interface and implementation
 *
 * This function must release all referenced memory in the concrete
 * implementation and memory related to the IoOperations.  It should NULL the
 * input parameter.
 *
 * @param [in,out] opsPtr Pointer to interface.  Will be NULLed.
 *
 * Example:
 * @code
 *
 *   static void
 *   _etherConnection_InternalRelease(_EtherState *etherConnState)
 *   {
 *      // release internal state of _EtherState
 *   }
 *
 *   static void
 *   _etherConnection_Release(IoOperations **opsPtr)
 *   {
 *      IoOperations *ops = *opsPtr;
 *
 *      _EtherState *etherConnState = (_EtherState *)
 * ioOperations_GetClosure(ops);
 *      _etherConnection_InternalRelease(etherConnState);
 *
 *      parcMemory_Deallocate((void **) &ops);
 *   }
 *
 *   IoOperations *
 *   etherConnection_Create(Forwarder *forwarder, GenericEther *ether,
 * address_pair_t *pair)
 *   {
 *      size_t allocationSize = sizeof(_EtherState) + sizeof(IoOperations);
 *      IoOperations *ops = parcMemory_AllocateAndClear(allocationSize);
 *      if (ops) {
 *         // fill in other interface functions
 *         ops->destroy = &_etherConnection_Release;
 *         ops->closure = (uint8_t *) ops + sizeof(IoOperations);
 *
 *         _EtherState *etherConnState = ioOperations_GetClosure(ops);
 *         // fill in Ethernet state
 *      }
 *      return ops;
 *   }
 * @endcode
 */
void ioOperations_Release(IoOperations **opsPtr);

/**
 * Sends the specified Message out this connection
 *
 * The the implementation of send may queue the message, it must acquire a
 * reference to it.
 *
 * @param [in] ops The connection implementation.
 * @param [in] nexthop On multiple access networks, this parameter might be
 * used, usually NULL.
 * @param [in] message The message to send.  If the message will be queued, it
 * will be acquired.
 *
 * @return true The message was sent or queued
 * @retrun false An error occured and the message will not be sent or queued
 *
 * Example:
 * @code
 * {
 *     if (ioOperations_IsUp(conn->ops)) {
 *        return ioOperations_Send(conn->ops, NULL, message);
 *     }
 * }
 * @endcode
 */
bool ioOperations_Send(IoOperations *ops, const address_t *nexthop,
    msgbuf_t *message, bool queue);

bool ioOperations_SendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size);

/**
 * A connection is made up of a local and a remote address.  This function
 * returns the remote address.
 *
 * Represents the destination endpoint of the communication.
 *
 * @param [in] ops The connection implementation.
 *
 * @return non-null The remote address
 * @return null The connection does not have a remote address
 *
 * Example:
 * @code
 * {
 *    address_t *local =  addressCreateFromLink((uint8_t []) { 0x01, 0x02, 0x03,
 * 0x04, 0x05, 0x06 }, 6); address_t *remote = addressCreateFromLink((uint8_t [])
 * { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, 6); address_pair_t *pair =
 * addressPair_Create(local, remote); IoOperations *ops =
 * etherConnection_Create(forwarder, ether, pair);
 *
 *    const address_t *test = ioOperations_GetRemoteAddress(ops);
 *    parcAssertTrue(addressEquals(test, remote), "Wrong remote address");
 *    ioOperations_Release(&ops);
 *    addressPair_Release(&pair);
 *    addressDestroy(&local);
 *    addressDestroy(&remote);
 * }
 * @endcode
 */
const address_t *ioOperations_GetRemoteAddress(const IoOperations *ops);

/**
 * A connection is made up of a local and a remote address.  This function
 * returns the address pair.
 *
 * Represents the destination endpoint of the communication.
 *
 * @param [in] ops The connection implementation.
 *
 * @return non-null The address pair
 * @return null An error.
 *
 * Example:
 * @code
 * {
 *    address_t *local =  addressCreateFromLink((uint8_t []) { 0x01, 0x02, 0x03,
 * 0x04, 0x05, 0x06 }, 6); address_t *remote = addressCreateFromLink((uint8_t [])
 * { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, 6); address_pair_t *pair =
 * addressPair_Create(local, remote); IoOperations *ops =
 * etherConnection_Create(forwarder, ether, pair);
 *
 *    const address_pair_t *test = ioOperations_GetAddressPair(ops);
 *    parcAssertTrue(addressPair(test, pair), "Wrong address pair");
 *    ioOperations_Release(&ops);
 *    addressPair_Release(&pair);
 *    addressDestroy(&local);
 *    addressDestroy(&remote);
 * }
 * @endcode
 */
const address_pair_t *ioOperations_GetAddressPair(const IoOperations *ops);

/**
 * Returns true if the underlying connection is in operation
 *
 * An UP connection is able to send and receive packets. If a subsystem needs to
 * take actions when a connection goes UP or DOWN, it should subscribe as a
 * Missive listener.
 *
 * @param [in] ops The connection implementation.
 *
 * @return true The connection is UP
 * @return false The connection is not UP
 *
 * Example:
 * @code
 * {
 *     if (ioOperations_IsUp(conn->ops)) {
 *        return ioOperations_Send(conn->ops, NULL, message);
 *     }
 * }
 * @endcode
 */
bool ioOperations_IsUp(const IoOperations *ops);

/**
 * If the remote address is local to this system, returns true
 *
 * Will return true if an INET or INET6 connection is on localhost.  Will return
 * true for AF_UNIX.  An Ethernet connection is not local.
 *
 * @param [in] ops The connection implementation.
 *
 * @return true The remote address is local to the system
 * @return false The remote address is not local
 *
 * Example:
 * @code
 * {
 *     // Is the ingress connection remote?  If so check for non-zero and
 * decrement if (!ioOperations(ingressConnectionOps) { uint8_t hoplimit =
 * message_GetHopLimit(interestMessage); if (hoplimit == 0) {
 *           // error
 *        } else {
 *           hoplimit--;
 *        }
 *        // take actions on hoplimit
 *     }
 * }
 * @endcode
 */
bool ioOperations_IsLocal(const IoOperations *ops);

/**
 * Returns the connection ID represented by this IoOperations in the
 * ConnectionTable.
 *
 * <#Paragraphs Of Explanation#>
 *
 * @param [in] ops The connection implementation.
 *
 * @return number The connection ID in the connection table.
 *
 * Example:
 * @code
 * {
 *     unsigned id = ioOperations_GetConnectionId(ingressIoOps);
 *     const Connection *conn =
 * connectionTable_FindById(forwarder->connectionTable, id);
 * }
 * @endcode
 */
unsigned ioOperations_GetConnectionId(const IoOperations *ops);

/**
 * A pointer that represents the class of the connection
 *
 * Each concrete implementation has a class pointer that is unique to the
 * implementation (not instance). Each implementation is free to choose how to
 * determine the value, so long as it is unique on the system. This is a
 * system-local value.
 *
 * @param [in] ops The connection implementation.
 *
 * @return non-null A pointer value unique to the implementation (not instance).
 *
 * Example:
 * @code
 *   bool
 *   etherConnection_IsInstanceOf(const Connection *conn)
 *   {
 *      bool result = false;
 *      if (conn != NULL) {
 *         IoOperations *ops = connection_GetIoOperations(conn);
 *         const void *class = ioOperations_Class(ops);
 *         result = (class == _etherConnection_Class(ops));
 *      }
 *      return result;
 *   }
 * @endcode
 */
const void *ioOperations_Class(const IoOperations *ops);

/**
 * Returns the transport type of the connection (TCP, UDP, L2, etc.).
 *
 * TCP and AF_UNIX are both stream connections and will both return
 * "Connection_TCP". Ethernet will return "Connection_L2".
 *
 * @param [in] ops The connection implementation.
 *
 * @return Connection_TCP A TCP4, TCP6, or AF_UNIX connection
 * @return Connection_UDP A UDP4 or UDP6 connection
 * @return Connection_L2 An Ethernet connection
 *
 * Example:
 * @code
 * {
 *     ConnectionType type =
 * ioOperations_GetConnectionType(connection_GetIoOperations(connection));
 *     Connection *Conn =
 * Connection_Create(connection_GetConnectionId(connection), localAddress,
 * remoteAddress, type);
 * }
 * @endcode
 */
list_connections_type ioOperations_GetConnectionType(const IoOperations *ops);

void ioOperations_SendProbe(IoOperations *ops, uint8_t *message);


/**
 * Returns the current state of the connection
 *
 * @param [in] ops The connection implementation.
 *
 * @return Connection state (connection_state_t).
 */
connection_state_t ioOperations_GetState(const IoOperations *ops);

/**
 * Sets the current state of the connection
 *
 * @param [in] ops The connection implementation.
 * @param [in] state New state to set (connection_state_t).
 */
void ioOperations_SetState(IoOperations *ops, connection_state_t state);

/**
 * Returns the administrative state of the connection
 *
 * @param [in] ops The connection implementation.
 *
 * @return Connection state (connection_state_t).
 */
connection_state_t ioOperations_GetAdminState(const IoOperations *ops);

/**
 * Sets the administrative state of the connection
 *
 * @param [in] ops The connection implementation.
 * @param [in] state New state to set (connection_state_t).
 */
void ioOperations_SetAdminState(IoOperations *ops, connection_state_t admin_state);

#ifdef WITH_POLICY
/**
 * Returns the priority of the connection
 *
 * @param [in] ops The connection implementation.
 *
 * @return Connection state (uint32_t).
 */
uint32_t ioOperations_GetPriority(const IoOperations *ops);

/**
 * Sets the priority of the connection
 *
 * @param [in] ops The connection implementation.
 * @param [in] state New state to set (uint32_t).
 */
void ioOperations_SetPriority(IoOperations *ops, uint32_t priority);
#endif /* WITH_POLICY */

/**
 * Sets the interface name associated to the connection.
 *
 * @param [in] ops The connection implementation.
 * @return the name associated to the connection (const char *)
 */
const char * ioOperations_GetInterfaceName(const IoOperations *ops);

#endif  // io_h
