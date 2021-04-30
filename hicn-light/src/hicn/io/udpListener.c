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
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <hicn/core/messageHandler.h>

#include <hicn/io/udpConnection.h>
#include <hicn/io/udpListener.h>

#include <parc/algol/parc_Network.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/messagePacketType.h>

#define IPv4 4
#define IPv6 6

struct udp_listener {
  char *listenerName;
  Forwarder *forwarder;
  Logger *logger;

  PARCEvent *udp_event;
  SocketType udp_socket;
  uint16_t port;

  unsigned id;
  char *interfaceName;
  Address *localAddress;
};

static void _destroy(ListenerOps **listenerOpsPtr);
static const char *_getListenerName(const ListenerOps *ops);
static unsigned _getInterfaceIndex(const ListenerOps *ops);
static const Address *_getListenAddress(const ListenerOps *ops);
static EncapType _getEncapType(const ListenerOps *ops);
static const char *_getInterfaceName(const ListenerOps *ops);
static int _getSocket(const ListenerOps *ops);
static unsigned _createNewConnection(ListenerOps *listener, int fd, const AddressPair *pair);
static const Connection * _lookupConnection(ListenerOps * listener, const AddressPair *pair);

static ListenerOps udpTemplate = {
  .context = NULL,
  .destroy = &_destroy,
  .getInterfaceIndex = &_getInterfaceIndex,
  .getListenAddress = &_getListenAddress,
  .getEncapType = &_getEncapType,
  .getSocket = &_getSocket,
  .getListenerName = &_getListenerName,
  .createConnection = &_createNewConnection,
  .lookupConnection = &_lookupConnection,
  .getInterfaceName = &_getInterfaceName,
};


static void _readcb(int fd, PARCEventType what, void * listener_void);

#ifdef __ANDROID__
extern int bindSocket(int sock, const char* ifname);
#endif

ListenerOps *udpListener_CreateInet6(Forwarder *forwarder, char *listenerName,
                                     struct sockaddr_in6 sin6, const char *interfaceName) {
  ListenerOps *ops = NULL;

  UdpListener *udp = parcMemory_AllocateAndClear(sizeof(UdpListener));
  parcAssertNotNull(udp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(UdpListener));
  udp->forwarder = forwarder;
  udp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  udp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));
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
#ifdef __linux__
    if (strncmp("lo", interfaceName, 2) != 0) {
      int ret = setsockopt(udp->udp_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       interfaceName, strlen(interfaceName) + 1);
      if (ret < 0) {
        logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "setsockopt(%d, SO_BINDTODEVICE, %s) failed (%d) %s",
                   udp->udp_socket, interfaceName, errno, strerror(errno));
#ifdef __ANDROID__
        ret = bindSocket(udp->udp_socket, interfaceName);
        if (ret < 0) {
          logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "bindSocket(%d, %s) failed", udp->udp_socket, interfaceName);
          close(udp->udp_socket);
          addressDestroy(&udp->localAddress);
          logger_Release(&udp->logger);
          parcMemory_Deallocate((void **)&udp);
          return NULL;
        } else {
          logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "bindSocket(%d, %s) success", udp->udp_socket, interfaceName);
        }
#else
        close(udp->udp_socket);
        addressDestroy(&udp->localAddress);
        logger_Release(&udp->logger);
        parcMemory_Deallocate((void **)&udp);
        return NULL;
#endif
      }
    }
#endif

    ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
    parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(ListenerOps));
    memcpy(ops, &udpTemplate, sizeof(ListenerOps));
    ops->context = udp;

    udp->udp_event =
        dispatcher_CreateNetworkEvent(forwarder_GetDispatcher(forwarder), true,
                                      _readcb, (void*)ops, udp->udp_socket);
    dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                                 udp->udp_event);

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
    parcMemory_Deallocate((void **)&udp->listenerName);
    parcMemory_Deallocate((void **)&udp->interfaceName);
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

ListenerOps *udpListener_CreateInet(Forwarder *forwarder, char *listenerName,
                                    struct sockaddr_in sin, const char *interfaceName) {
  ListenerOps *ops = NULL;

  UdpListener *udp = parcMemory_AllocateAndClear(sizeof(UdpListener));
  parcAssertNotNull(udp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(UdpListener));
  udp->forwarder = forwarder;
  udp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  udp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));
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
#ifdef __linux__
    if (strncmp("lo", interfaceName, 2) != 0) { 
      int ret = setsockopt(udp->udp_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       interfaceName, strlen(interfaceName) + 1);
      if (ret < 0) {
        logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "setsockopt(%d, SO_BINDTODEVICE, %s) failed (%d) %s",
                   udp->udp_socket, interfaceName, errno, strerror(errno));
#ifdef __ANDROID__
        ret = bindSocket(udp->udp_socket, interfaceName);
        if (ret < 0) {
          logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "bindSocket(%d, %s) failed", udp->udp_socket, interfaceName);
          close(udp->udp_socket);
          addressDestroy(&udp->localAddress);
          logger_Release(&udp->logger);
          parcMemory_Deallocate((void **)&udp);
          return NULL;
        } else {
          logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                   "bindSocket(%d, %s) success", udp->udp_socket, interfaceName);
        }
#else
        close(udp->udp_socket);
        addressDestroy(&udp->localAddress);
        logger_Release(&udp->logger);
        parcMemory_Deallocate((void **)&udp);
        return NULL;
#endif
      }
    }
#endif
    ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
    parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(ListenerOps));
    memcpy(ops, &udpTemplate, sizeof(ListenerOps));
    ops->context = udp;

    udp->udp_event =
        dispatcher_CreateNetworkEvent(forwarder_GetDispatcher(forwarder), true,
                                      _readcb, (void *)ops, udp->udp_socket);
    dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                                 udp->udp_event);


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
    parcMemory_Deallocate((void **)&udp->listenerName);
    parcMemory_Deallocate((void **)&udp->interfaceName);
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

static void udpListener_Destroy(UdpListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");

  UdpListener *udp = *listenerPtr;

  if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "UdpListener %p destroyed", (void *)udp);
  }

  parcMemory_Deallocate((void **)&udp->listenerName);
  parcMemory_Deallocate((void **)&udp->interfaceName);
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

static const char *_getListenerName(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->listenerName;
}

static const char *_getInterfaceName(const ListenerOps *ops) {
  UdpListener *udp = (UdpListener *)ops->context;
  return udp->interfaceName;
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

static const Connection * _lookupConnection(ListenerOps * listener,
                                const AddressPair *pair) {
  UdpListener * udp = (UdpListener *)listener->context;
  ConnectionTable *connTable = forwarder_GetConnectionTable(udp->forwarder);
  return connectionTable_FindByAddressPair(connTable, pair);

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

static unsigned _createNewConnection(ListenerOps * listener, int fd,
                                     const AddressPair *pair) {
  UdpListener * udp = (UdpListener *)listener->context;

  //check it the connection is local
  bool isLocal = false;
  const Address *localAddress = addressPair_GetLocal(pair);
  if(addressGetType(localAddress) == ADDR_INET){
    struct sockaddr_in tmpAddr;
    addressGetInet(localAddress, &tmpAddr);
    if(parcNetwork_IsSocketLocal((struct sockaddr *)&tmpAddr))
      isLocal = true;
  }else{
    struct sockaddr_in6 tmpAddr6;
    addressGetInet6(localAddress, &tmpAddr6);
    if(parcNetwork_IsSocketLocal((struct sockaddr *)&tmpAddr6))
      isLocal = true;
  }

  // metisUdpConnection_Create takes ownership of the pair
  IoOperations *ops = udpConnection_Create(udp->forwarder, udp->interfaceName, fd, pair, isLocal);
  Connection *conn = connection_Create(ops);
  // connection_AllowWldrAutoStart(conn);

  connectionTable_Add(forwarder_GetConnectionTable(udp->forwarder), conn);
  unsigned connid = ioOperations_GetConnectionId(ops);

  return connid;
}

static void _handleWldrNotification(UdpListener *udp, unsigned connId,
                                    uint8_t *msgBuffer) {
  const Connection *conn = connectionTable_FindById(
      forwarder_GetConnectionTable(udp->forwarder), connId);
  if (conn == NULL) {
    parcMemory_Deallocate((void **)&msgBuffer);
    return;
  }

  Message *message = message_CreateFromByteArray(
      connId, msgBuffer, MessagePacketType_WldrNotification,
      forwarder_GetTicks(udp->forwarder), forwarder_GetLogger(udp->forwarder));

  connection_HandleWldrNotification((Connection *)conn, message);

  message_Release(&message);
}

static Message *_readMessage(ListenerOps * listener, int fd,
                      AddressPair *pair, uint8_t * packet, bool * processed) {
  UdpListener * udp = (UdpListener *)listener->context;

  Message *message = NULL;

  unsigned connid;
  bool foundConnection;

  const Connection *conn = _lookupConnection(listener, pair);
  if (conn) {
    connid = connection_GetConnectionId(conn);
    foundConnection = true;
  } else {
    connid = 0;
    foundConnection = false;
  }

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
        connid = _createNewConnection(listener, fd, pair);
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
  } else {

    *processed = messageHandler_handleHooks(udp->forwarder, packet, listener, fd, pair);
  }

  return message;
}

static void _readCommand(ListenerOps * listener, int fd,
                        AddressPair *pair, uint8_t * command) {
  UdpListener * udp = (UdpListener *)listener->context;

  if (*command != REQUEST_LIGHT){
    printf("the message received is not a command, drop\n");
    parcMemory_Deallocate((void **) &command);
    return;
  }

  command_id id = *(command + 1);

  if (id >= LAST_COMMAND_VALUE){
    printf("the message received is not a valid command, drop\n");
    parcMemory_Deallocate((void **) &command);
    return;
  }

  unsigned connid;

  const Connection *conn = _lookupConnection(listener, pair);
  if (conn) {
    connid = connection_GetConnectionId(conn);
  } else {
    connid = _createNewConnection(listener, fd, pair);
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
  //parcMemory_Deallocate((void **) &request);
}


static bool _receivePacket(ListenerOps * listener, int fd,
                           AddressPair *pair,
                           uint8_t * packet) {
  UdpListener * udp = (UdpListener *)listener->context;
  bool processed = false;
  Message *message = _readMessage(listener, fd, pair,
                                   packet, &processed);
  if (message) {
    forwarder_Receive(udp->forwarder, message);
  }
  return processed;
}

static void _readcb(int fd, PARCEventType what, void * listener_void) {
  ListenerOps * listener = (ListenerOps *)listener_void;
  UdpListener * udp = (UdpListener *)listener->context;

  if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "%s socket %d what %s%s%s%s data %p", __func__, fd,
               (what & PARCEventType_Timeout) ? " timeout" : "",
               (what & PARCEventType_Read) ? " read" : "",
               (what & PARCEventType_Write) ? " write" : "",
               (what & PARCEventType_Signal) ? " signal" : "", udp);
  }

  if (what & PARCEventType_Read) {
    struct sockaddr_storage peerIpAddress;
    socklen_t peerIpAddressLength = sizeof(peerIpAddress);

    //packet it deallocated by _receivePacket or _readCommand
    uint8_t * packet = parcMemory_AllocateAndClear(1500); //max MTU
     ssize_t readLength = recvfrom(fd, packet, 1500, 0,
      (struct sockaddr *)&peerIpAddress, &peerIpAddressLength);

#ifdef __APPLE__
    peerIpAddress.ss_len = 0x00;
#endif

    if(readLength < 0) {
      printf("unable to read the message\n");
      parcMemory_Deallocate(packet);
      return;
    }

    AddressPair *pair = _constructAddressPair(
      udp, (struct sockaddr *)&peerIpAddress, peerIpAddressLength);

    bool done = _receivePacket(listener, fd, pair, packet);
    if(!done){
      _readCommand(listener, fd, pair, packet);
    }

    addressPair_Release(&pair);
  }
}
