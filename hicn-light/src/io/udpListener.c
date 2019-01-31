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

  udp->udp_socket = socket(AF_INET6, SOCK_DGRAM, 0);
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

  udp->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
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

// void
// udpListener_SetPacketType(ListenerOps *ops, MessagePacketType type)
//{
//    return;
//}

// =====================================================================

/**
 * @function peekMesageLength
 * @abstract Peek at the next packet to learn its length by reading the fixed
 * header
 * @discussion
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return <#return#>
 */
static size_t _peekMessageLength(UdpListener *udp, int fd,
                                 struct sockaddr *peerIpAddress,
                                 socklen_t *peerIpAddressLengthPtr) {
  // to be fast I try to use just ipv6, this needs to be validated for ipv4

  size_t packetLength = 0;

  uint8_t *fixedHeader = (uint8_t *)malloc(
      sizeof(uint8_t) * messageHandler_GetIPHeaderLength(IPv6));

  // peek at the UDP packet and read in the fixed header.
  // Also returns the socket information for the remote peer

  ssize_t res = recvfrom(
      fd, fixedHeader, messageHandler_GetIPHeaderLength(IPv6), MSG_PEEK,
      (struct sockaddr *)peerIpAddress, peerIpAddressLengthPtr);

  if (res == messageHandler_GetIPHeaderLength(IPv6)) {
    packetLength =
        messageHandler_GetTotalPacketLength((const uint8_t *)&fixedHeader);
  } else {
    if (res < 0) {
      printf("error while readin packet\n");
    }
  }

  free(fixedHeader);

  return packetLength;
}

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

static Message *_readMessage(UdpListener *udp, int fd, size_t packetLength,
                             AddressPair *pair) {
  uint8_t *msgBuffer = parcMemory_AllocateAndClear(packetLength);

  ssize_t readLength = read(fd, msgBuffer, packetLength);

  Message *message = NULL;

  if (readLength < 0) {
    printf("read failed %d: (%d) %s\n", fd, errno, strerror(errno));
    return message;
  }

  unsigned connid = 0;
  bool foundConnection = _lookupConnectionId(udp, pair, &connid);

  if (readLength == packetLength) {
    // we need to check if it is a valid packet
    if (messageHandler_IsTCP(msgBuffer)) {
      MessagePacketType pktType;

      if (messageHandler_IsData(msgBuffer)) {
        pktType = MessagePacketType_ContentObject;
        if (!foundConnection) {
          parcMemory_Deallocate((void **)&msgBuffer);
          return message;
        }
      } else if (messageHandler_IsInterest(msgBuffer)) {
        pktType = MessagePacketType_Interest;
        if (!foundConnection) {
          connid = _createNewConnection(udp, fd, pair);
        }
      } else {
        printf("Got a packet that is not a data nor an interest, drop it!\n");
        parcMemory_Deallocate((void **)&msgBuffer);
        return message;
      }

      message = message_CreateFromByteArray(
          connid, msgBuffer, pktType, forwarder_GetTicks(udp->forwarder),
          forwarder_GetLogger(udp->forwarder));

      if (message == NULL) {
        parcMemory_Deallocate((void **)&msgBuffer);
      }
    } else if (messageHandler_IsWldrNotification(msgBuffer)) {
      _handleWldrNotification(udp, connid, msgBuffer);
    } else if (messageHandler_IsLoadBalancerProbe(msgBuffer)) {
      _handleProbeMessage(udp, msgBuffer);
    }
#ifdef WITH_MAPME
    else if (mapMe_isMapMe(msgBuffer)) {
      forwarder_ProcessMapMe(udp->forwarder, msgBuffer, connid);
    }
#endif /* WITH_MAPME */
  }

  return message;
}

static void _receivePacket(UdpListener *udp, int fd, size_t packetLength,
                           struct sockaddr_storage *peerIpAddress,
                           socklen_t peerIpAddressLength) {
  AddressPair *pair = _constructAddressPair(
      udp, (struct sockaddr *)peerIpAddress, peerIpAddressLength);

  Message *message = _readMessage(udp, fd, packetLength, pair);
  addressPair_Release(&pair);

  if (message) {
    forwarder_Receive(udp->forwarder, message);
  } else {
    return;
  }
}

static void _readFrameToDiscard(UdpListener *udp, int fd) {
  // we need to discard the frame.  Read 1 byte.  This will clear it off the
  // stack.
  uint8_t buffer;
  ssize_t nread = read(fd, &buffer, 1);

  if (nread == 1) {
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "Discarded frame from fd %d", fd);
    }
  } else if (nread < 0) {
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Error)) {
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                 "Error trying to discard frame from fd %d: (%d) %s", fd, errno,
                 strerror(errno));
    }
  }
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

    size_t packetLength = _peekMessageLength(
        udp, fd, (struct sockaddr *)&peerIpAddress, &peerIpAddressLength);

    if (packetLength > 0) {
      _receivePacket(udp, fd, packetLength, &peerIpAddress,
                     peerIpAddressLength);
    } else {
      _readFrameToDiscard(udp, fd);
    }
  }
}
