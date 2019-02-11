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

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <src/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <src/core/messageHandler.h>

#include <src/io/udpConnection.h>
#include <src/io/udpListener.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <src/core/connection.h>
#include <src/core/forwarder.h>
#include <src/core/messagePacketType.h>

#ifdef WITH_MAPME
#include <src/core/mapMe.h>
#endif /* WITH_MAPME */

#define IPv4 4
#define IPv6 6

struct udp_listener {
  Forwarder *forwarder;
  Logger *logger;

  PARCEvent *udp_event;
  SocketType udp_socket;
  uint16_t port;

  unsigned id;
  Address *localAddress;
};

static void _destroy(ListenerOps **listenerOpsPtr);
static unsigned _getInterfaceIndex(const ListenerOps *ops);
static const Address *_getListenAddress(const ListenerOps *ops);
static EncapType _getEncapType(const ListenerOps *ops);
static int _getSocket(const ListenerOps *ops);

static ListenerOps udpTemplate = {.context = NULL,
                                  .destroy = &_destroy,
                                  .getInterfaceIndex = &_getInterfaceIndex,
                                  .getListenAddress = &_getListenAddress,
                                  .getEncapType = &_getEncapType,
                                  .getSocket = &_getSocket};

static void _readcb(int fd, PARCEventType what, void *udpVoid);

ListenerOps *udpListener_CreateInet6(Forwarder *forwarder,
                                     struct sockaddr_in6 sin6) {
  ListenerOps *ops = NULL;

  UdpListener *udp = parcMemory_AllocateAndClear(sizeof(UdpListener));
  parcAssertNotNull(udp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(UdpListener));
  udp->forwarder = forwarder;
  udp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  udp->localAddress = addressCreateFromInet6(&sin6);
  udp->id = forwarder_GetNextConnectionId(forwarder);

  udp->udp_socket = (SocketType)socket(AF_INET6, SOCK_DGRAM, 0);
  parcAssertFalse(udp->udp_socket < 0, "Error opening UDP socket: (%d) %s",
                  errno, strerror(errno));

  int failure = 0;
#ifndef _WIN32
  // Set non-blocking flag
  int flags = fcntl(udp->udp_socket, F_GETFL, NULL);
  parcAssertTrue(flags != -1,
                 "fcntl failed to obtain file descriptor flags (%d)", errno);
  failure = fcntl(udp->udp_socket, F_SETFL, flags | O_NONBLOCK);
  parcAssertFalse(failure, "fcntl failed to set file descriptor flags (%d)",
                  errno);
#else
  // Set non-blocking flag
  u_long mode = 1;
  int result = ioctlsocket(udp->udp_socket, FIONBIO, &mode);
  if (result != NO_ERROR) {
    parcAssertTrue(result != NO_ERROR,
                   "ioctlsocket failed to set file descriptor");
  }
#endif

  int one = 1;
  // don't hang onto address after listener has closed
  failure = setsockopt(udp->udp_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                       (socklen_t)sizeof(one));
  parcAssertFalse(failure, "failed to set REUSEADDR on socket(%d)", errno);

  failure = bind(udp->udp_socket, (struct sockaddr *)&sin6, sizeof(sin6));
  if (failure == 0) {
    udp->udp_event =
        dispatcher_CreateNetworkEvent(forwarder_GetDispatcher(forwarder), true,
                                      _readcb, (void *)udp, udp->udp_socket);
    dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                                 udp->udp_event);

    ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
    parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(ListenerOps));
    memcpy(ops, &udpTemplate, sizeof(ListenerOps));
    ops->context = udp;

    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
      char *str = addressToString(udp->localAddress);
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "UdpListener %p created for address %s", (void *)udp, str);
      parcMemory_Deallocate((void **)&str);
    }
  } else {
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Error)) {
      int myerrno = errno;
      char *str = addressToString(udp->localAddress);
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                 "Error binding UDP socket to address %s: (%d) %s", str,
                 myerrno, strerror(myerrno));
      parcMemory_Deallocate((void **)&str);
    }
#ifndef _WIN32
    close(udp->udp_socket);
#else
    closesocket(udp->udp_socket);
#endif
    addressDestroy(&udp->localAddress);
    logger_Release(&udp->logger);
    parcMemory_Deallocate((void **)&udp);
  }

  return ops;
}

ListenerOps *udpListener_CreateInet(Forwarder *forwarder,
                                    struct sockaddr_in sin) {
  ListenerOps *ops = NULL;

  UdpListener *udp = parcMemory_AllocateAndClear(sizeof(UdpListener));
  parcAssertNotNull(udp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(UdpListener));
  udp->forwarder = forwarder;
  udp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  udp->localAddress = addressCreateFromInet(&sin);
  udp->id = forwarder_GetNextConnectionId(forwarder);

  udp->udp_socket = (SocketType)socket(AF_INET, SOCK_DGRAM, 0);
  parcAssertFalse(udp->udp_socket < 0, "Error opening UDP socket: (%d) %s",
                  errno, strerror(errno));

  int failure = 0;
#ifndef _WIN32
  // Set non-blocking flag
  int flags = fcntl(udp->udp_socket, F_GETFL, NULL);
  parcAssertTrue(flags != -1,
                 "fcntl failed to obtain file descriptor flags (%d)", errno);
  failure = fcntl(udp->udp_socket, F_SETFL, flags | O_NONBLOCK);
  parcAssertFalse(failure, "fcntl failed to set file descriptor flags (%d)",
                  errno);
#else
  u_long mode = 1;
  int result = ioctlsocket(udp->udp_socket, FIONBIO, &mode);
  if (result != NO_ERROR) {
    parcAssertTrue(result != NO_ERROR,
                   "ioctlsocket failed to set file descriptor");
  }
#endif

  int one = 1;
  // don't hang onto address after listener has closed
  failure = setsockopt(udp->udp_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&one,
                       (socklen_t)sizeof(one));
  parcAssertFalse(failure, "failed to set REUSEADDR on socket(%d)", errno);

  failure = bind(udp->udp_socket, (struct sockaddr *)&sin, sizeof(sin));
  if (failure == 0) {
    udp->udp_event =
        dispatcher_CreateNetworkEvent(forwarder_GetDispatcher(forwarder), true,
                                      _readcb, (void *)udp, udp->udp_socket);
    dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                                 udp->udp_event);

    ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
    parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(ListenerOps));
    memcpy(ops, &udpTemplate, sizeof(ListenerOps));
    ops->context = udp;

    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
      char *str = addressToString(udp->localAddress);
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "UdpListener %p created for address %s", (void *)udp, str);
      parcMemory_Deallocate((void **)&str);
    }
  } else {
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Error)) {
      int myerrno = errno;
      char *str = addressToString(udp->localAddress);
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                 "Error binding UDP socket to address %s: (%d) %s", str,
                 myerrno, strerror(myerrno));
      parcMemory_Deallocate((void **)&str);
    }

    close(udp->udp_socket);
    addressDestroy(&udp->localAddress);
    logger_Release(&udp->logger);
    parcMemory_Deallocate((void **)&udp);
  }

  return ops;
}

static void udpListener_Destroy(UdpListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");

  UdpListener *udp = *listenerPtr;

  if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "UdpListener %p destroyed", (void *)udp);
  }

#ifndef _WIN32
  close(udp->udp_socket);
#else
  closesocket(udp->udp_socket);
#endif

  addressDestroy(&udp->localAddress);
  dispatcher_DestroyNetworkEvent(forwarder_GetDispatcher(udp->forwarder),
                                 &udp->udp_event);
  logger_Release(&udp->logger);
  parcMemory_Deallocate((void **)&udp);
  *listenerPtr = NULL;
}

static void _destroy(ListenerOps **listenerOpsPtr) {
  ListenerOps *ops = *listenerOpsPtr;
  UdpListener *udp = (UdpListener *)ops->context;
  udpListener_Destroy(&udp);
  parcMemory_Deallocate((void **)&ops);
  *listenerOpsPtr = NULL;
}

static unsigned _getInterfaceIndex(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->id;
}

static const Address *_getListenAddress(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->localAddress;
}

static EncapType _getEncapType(const ListenerOps *ops) { return ENCAP_UDP; }

static int _getSocket(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return (int)udp->udp_socket;
}

// =====================================================================

/**
 * @function _constructAddressPair
 * @abstract Creates the address pair that uniquely identifies the connection
 * @discussion
 *   The peerIpAddress must be of AF_INET or AF_INET6 family.
 *
 * @param <#param1#>
 * @return Allocated MetisAddressPair, must be destroyed
 */
static AddressPair *_constructAddressPair(UdpListener *udp,
                                          struct sockaddr *peerIpAddress,
                                          socklen_t peerIpAddressLength) {
  Address *remoteAddress;

  switch (peerIpAddress->sa_family) {
    case AF_INET:
      remoteAddress =
          addressCreateFromInet((struct sockaddr_in *)peerIpAddress);
      break;

    case AF_INET6:
      remoteAddress =
          addressCreateFromInet6((struct sockaddr_in6 *)peerIpAddress);
      break;

    default:
      parcTrapIllegalValue(peerIpAddress,
                           "Peer address unrecognized family for IP: %d",
                           peerIpAddress->sa_family);
  }

  AddressPair *pair = addressPair_Create(udp->localAddress, remoteAddress);
  addressDestroy(&remoteAddress);

  return pair;
}

/**
 * @function _lookupConnectionId
 * @abstract  Lookup a connection in the connection table
 * @discussion
 *   Looks up the connection in the connection table and returns the connection
 * id if it exists.
 *
 * @param outputConnectionIdPtr is the output parameter
 * @return true if connection found and outputConnectionIdPtr set
 */
static bool _lookupConnectionId(UdpListener *udp, AddressPair *pair,
                                unsigned *outputConnectionIdPtr) {
  ConnectionTable *connTable = forwarder_GetConnectionTable(udp->forwarder);

  const Connection *conn = connectionTable_FindByAddressPair(connTable, pair);
  if (conn) {
    *outputConnectionIdPtr = connection_GetConnectionId(conn);
    return true;
  } else {
    *outputConnectionIdPtr = 0;
    return false;
  }
}

/**
 * @function _createNewConnection
 * @abstract Creates a new Metis connection for the peer
 * @discussion
 *   PRECONDITION: you know there's not an existing connection with the address
 * pair
 *
 *   Creates a new connection and adds it to the connection table.
 *
 * @param <#param1#>
 * @return The connection id for the new connection
 */

static unsigned _createNewConnection(UdpListener *udp, int fd,
                                     const AddressPair *pair) {
  bool isLocal = false;

  // metisUdpConnection_Create takes ownership of the pair
  IoOperations *ops = udpConnection_Create(udp->forwarder, fd, pair, isLocal);
  Connection *conn = connection_Create(ops);
  // connection_AllowWldrAutoStart(conn);

  connectionTable_Add(forwarder_GetConnectionTable(udp->forwarder), conn);
  unsigned connid = ioOperations_GetConnectionId(ops);

  return connid;
}

static void _handleProbeMessage(UdpListener *udp, uint8_t *msgBuffer) {
  // TODO
  parcMemory_Deallocate((void **)&msgBuffer);
}

static void _handleWldrNotification(UdpListener *udp, unsigned connId,
                                    uint8_t *msgBuffer) {
  const Connection *conn = connectionTable_FindById(
      forwarder_GetConnectionTable(udp->forwarder), connId);
  if (conn == NULL) {
    return;
  }

  Message *message = message_CreateFromByteArray(
      connId, msgBuffer, MessagePacketType_WldrNotification,
      forwarder_GetTicks(udp->forwarder), forwarder_GetLogger(udp->forwarder));

  connection_HandleWldrNotification((Connection *)conn, message);

  message_Release(&message);
}

static Message *_readMessage(UdpListener *udp, int fd,
                      AddressPair *pair, uint8_t * packet, bool * processed) {

  Message *message = NULL;

  unsigned connid = 0;
  bool foundConnection = _lookupConnectionId(udp, pair, &connid);

  if (messageHandler_IsTCP(packet)) {
    *processed = true;
    MessagePacketType pktType;

    if (messageHandler_IsData(packet)) {
      pktType = MessagePacketType_ContentObject;
      if (!foundConnection) {
        parcMemory_Deallocate((void **)&packet);
        return message;
      }
    } else if (messageHandler_IsInterest(packet)) {
      pktType = MessagePacketType_Interest;
      if (!foundConnection) {
        connid = _createNewConnection(udp, fd, pair);
      }
    } else {
      printf("Got a packet that is not a data nor an interest, drop it!\n");
      parcMemory_Deallocate((void **)&packet);
      return message;
    }

    message = message_CreateFromByteArray(
        connid, packet, pktType, forwarder_GetTicks(udp->forwarder),
        forwarder_GetLogger(udp->forwarder));

    if (message == NULL) {
      parcMemory_Deallocate((void **)&packet);
    }
  } else if (messageHandler_IsWldrNotification(packet)) {
    *processed = true;
    _handleWldrNotification(udp, connid, packet);
  } else if (messageHandler_IsLoadBalancerProbe(packet)) {
    *processed = true;
    _handleProbeMessage(udp, packet);
  }
#ifdef WITH_MAPME
  else if (mapMe_isMapMe(packet)) {
    *processed = true;
    forwarder_ProcessMapMe(udp->forwarder, packet, connid);
  }
#endif /* WITH_MAPME */

  return message;
}

static void _readCommand(UdpListener *udp, int fd,
                        AddressPair *pair,
                        uint8_t * command) {

  if (*command != REQUEST_LIGHT){
    printf("the message received is not a command, drop\n");
    return;
  }

  command_id id = *(command + 1);

  if ( id < 0 || id >= LAST_COMMAND_VALUE){
    printf("the message received is not a valid command, drop\n");
    return;
  }

  unsigned connid = 0;
  bool foundConnection = _lookupConnectionId(udp, pair, &connid);
  if(!foundConnection){
    connid = _createNewConnection(udp, fd, pair);
  }

  struct iovec *request;
  if (!(request = (struct iovec *) parcMemory_AllocateAndClear(
              sizeof(struct iovec) * 2))) {
    return;
  }

  request[0].iov_base = command;
  request[0].iov_len = sizeof(header_control_message);
  request[1].iov_base = command + sizeof(header_control_message);
  request[1].iov_len = payloadLengthDaemon(id);

  forwarder_ReceiveCommand(udp->forwarder, id, request, connid);
  parcMemory_Deallocate((void **) &command);
  parcMemory_Deallocate((void **) &request);
}


static bool _receivePacket(UdpListener *udp, int fd,
                           AddressPair *pair,
                           uint8_t * packet) {
  bool processed = false;
  Message *message = _readMessage(udp, fd, pair,
                                   packet, &processed);
  if (message) {
    forwarder_Receive(udp->forwarder, message);
  }
  return processed;
}

static void _readcb(int fd, PARCEventType what, void *udpVoid) {
  UdpListener *udp = (UdpListener *)udpVoid;

  if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "%s socket %d what %s%s%s%s data %p", __func__, fd,
               (what & PARCEventType_Timeout) ? " timeout" : "",
               (what & PARCEventType_Read) ? " read" : "",
               (what & PARCEventType_Write) ? " write" : "",
               (what & PARCEventType_Signal) ? " signal" : "", udpVoid);
  }

  if (what & PARCEventType_Read) {
    struct sockaddr_storage peerIpAddress;
    socklen_t peerIpAddressLength = sizeof(peerIpAddress);

    //packet it deallocated by _receivePacket or _readCommand
    uint8_t * packet = parcMemory_AllocateAndClear(1500); //max MTU
     ssize_t readLength = recvfrom(fd, packet, 1500, 0,
      (struct sockaddr *)&peerIpAddress, &peerIpAddressLength);

    if(readLength < 0) {
      printf("unable to read the message\n");
      return;
    }

    AddressPair *pair = _constructAddressPair(
      udp, (struct sockaddr *)&peerIpAddress, peerIpAddressLength);

    bool done = _receivePacket(udp, fd, pair, packet);
    if(!done){
      _readCommand(udp, fd, pair, packet);
    }

    addressPair_Release(&pair);
  }
}
