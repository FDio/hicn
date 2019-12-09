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

#include <errno.h>
#include <fcntl.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <hicn/io/hicnConnection.h>
#include <hicn/io/hicnListener.h>

#include <hicn/core/connection.h>
#include <hicn/core/connectionTable.h>
#include <hicn/core/forwarder.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/mapme.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/io/listener.h>
#include <hicn/socket/api.h>

#define IPv6 6
#define IPv4 4
#define MTU_SIZE 1500  // bytes
#define MAX_HICN_RETRY 5

struct hicn_listener {

  char *listenerName;

  Forwarder *forwarder;
  Logger *logger;

  PARCEvent *hicn_event;
  int hicn_fd;  // this is the file descriptor got from hicn library

  Address
      *localAddress;  // this is the local address  or 0::0 in case of the
                      // main listener this is the address used inside
                      // forwarder to identify the listener. Notice that this
                      // address is the same as the fisical interfaces on
                      // which we create the TUN. it is NOT the TUN address
                      // which is given by libhicn after the bind operation
                      // However the user alway uses this address since is
                      // the only one available at configuration time

  unsigned inetFamily;

  int connection_id;  // this is used only if the listener is used to receive
                      // data packets we assume that 1 connection is associated
                      // to one listener in this case so we set the
                      // connection_id we the connection is create. if this id
                      // is not set and a data packet is received, the packet is
                      // dropped

  unsigned conn_id;
};

static void _destroy(ListenerOps **listenerOpsPtr);
static const char *_getListenerName(const ListenerOps *ops);
static const char *_getInterfaceName(const ListenerOps *ops);
static unsigned _getInterfaceIndex(const ListenerOps *ops);
static const Address *_getListenAddress(const ListenerOps *ops);
static EncapType _getEncapType(const ListenerOps *ops);
static int _getSocket(const ListenerOps *ops, address_pair_t * * pair);
static unsigned _createNewConnection(ListenerOps *listener, int fd, const address_pair_t * *pair);
static const Connection * _lookupConnection(ListenerOps * listener, const address_pair_t * *pair);
static Message *_readMessage(ListenerOps * listener, int fd, uint8_t *msgBuffer);
static void _hicnListener_readcb(int fd, PARCEventType what, void *listener_void);
static Address *_createAddressFromPacket(uint8_t *msgBuffer);
static void _handleWldrNotification(ListenerOps *listener, uint8_t *msgBuffer);
static void _readFrameToDiscard(HicnListener *hicn, int fd);

static ListenerOps _hicnTemplate = {
  .context = NULL,
  .destroy = &_destroy,
  .getInterfaceIndex = &_getInterfaceIndex,
  .getListenAddress = &_getListenAddress,
  .getEncapType = &_getEncapType,
  .getSocket = &_getSocket,
  .getInterfaceName = &_getInterfaceName,
  .getListenerName = &_getListenerName,
  .createConnection = &_createNewConnection,
};

static const
address_pair_t *
_createRecvAddressPairFromPacket(const uint8_t *msgBuffer) {
  Address *packetSrcAddr = NULL; /* This one is in the packet */
  Address *localAddr = NULL; /* This one is to be determined */

  if (messageHandler_GetIPPacketType(msgBuffer) == IPv6_TYPE) {
    struct sockaddr_in6 addr_in6;
    addr_in6.sin6_family = AF_INET6;
    addr_in6.sin6_port = htons(1234);
    addr_in6.sin6_flowinfo = 0;
    addr_in6.sin6_scope_id = 0;
    memcpy(&addr_in6.sin6_addr,
           (struct in6_addr *)messageHandler_GetSource(msgBuffer), 16);
    packetSrcAddr = addressCreateFromInet6(&addr_in6);

    /* We now determine the local address used to reach the packet src address */
    int sock = socket (AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0)
      goto ERR;

    struct sockaddr_in6 remote, local;
    memset(&remote, 0, sizeof(remote));
    remote.sin6_family = AF_INET6;
    remote.sin6_addr = addr_in6.sin6_addr;
    remote.sin6_port = htons(1234);

    socklen_t locallen = sizeof(local);
    if (connect(sock, (const struct sockaddr*)&remote, sizeof(remote)) == -1)
      goto ERR;
    if (getsockname(sock, (struct sockaddr*) &local, &locallen) == -1)
      goto ERR;

    local.sin6_port = htons(1234);
    localAddr = addressCreateFromInet6(&local);

    close(sock);

  } else if (messageHandler_GetIPPacketType(msgBuffer) == IPv4_TYPE) {
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(1234);
    memcpy(&addr_in.sin_addr,
           (struct in_addr *)messageHandler_GetSource(msgBuffer), 4);
    packetSrcAddr = addressCreateFromInet(&addr_in);

    /* We now determine the local address used to reach the packet src address */

    int sock = socket (AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
      perror("Socket error");
      goto ERR;
    }

    struct sockaddr_in remote, local;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr = addr_in.sin_addr;
    remote.sin_port = htons(1234);

    socklen_t locallen = sizeof(local);
    if (connect(sock, (const struct sockaddr*)&remote, sizeof(remote)) == -1)
      goto ERR;
    if (getsockname(sock, (struct sockaddr*) &local, &locallen) == -1)
      goto ERR;

    local.sin_port = htons(1234);
    localAddr = addressCreateFromInet(&local);

    close(sock);
  }
  /* As this is a receive pair, we swap src and dst */
  return addressPair_Create(localAddr, packetSrcAddr);

ERR:
  perror("Socket error");
  return NULL;
}


static bool _isEmptyAddressIPv6(Address *address) {
  struct sockaddr_in6 *addr6 =
      parcMemory_AllocateAndClear(sizeof(struct sockaddr_in6));
  parcAssertNotNull(addr6, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(addr6));

  addressGetInet6(address, addr6);

  bool res = true;
  for (int i = 0; i < 16; ++i) {
    if (addr6->sin6_addr.s6_addr[i] != 0) {
      res = false;
    }
  }

  parcMemory_Deallocate((void **)&addr6);

  return res;
}

static Message *_readMessage(ListenerOps * listener, int fd, uint8_t *msgBuffer) {
  HicnListener * hicn = (HicnListener*)listener->context;
  Message *message = NULL;

  ssize_t readLength = read(fd, msgBuffer, MTU_SIZE);

  if (readLength < 0) {
    printf("read failed %d: (%d) %s\n", fd, errno, strerror(errno));
    return message;
  }

  size_t packetLength = messageHandler_GetTotalPacketLength(msgBuffer);

  if (readLength != packetLength) {
    parcMemory_Deallocate((void **)&msgBuffer);
    return message;
  }

  if (messageHandler_IsTCP(msgBuffer)) {
    MessagePacketType pktType;
    unsigned connid = 0;
    if (messageHandler_IsData(msgBuffer)) {
      pktType = MessagePacketType_ContentObject;
      if (hicn->connection_id == -1) {
        parcMemory_Deallocate((void **)&msgBuffer);
        return message;
      } else {
        connid = hicn->connection_id;
      }
    } else if (messageHandler_IsInterest(msgBuffer)) {
      // notice that the connections for the interest (the one that we create at
      // run time) uses as a local address 0::0, so the main tun
      pktType = MessagePacketType_Interest;
      Address *packetAddr = _createAddressFromPacket(msgBuffer);

      address_pair_t * *pair_find = addressPair_Create(packetAddr, /* dummy */ hicn->localAddress);
      const Connection *conn = _lookupConnection(listener, pair_find);
      addressPair_Release(&pair_find);
      if (conn == NULL) {
        address_pair_t * *pair = addressPair_Create(hicn->localAddress, packetAddr);
        connid = _createNewConnection(listener, fd, pair);
        addressPair_Release(&pair);
      } else {
        connid = connection_GetConnectionId(conn);
      }
      addressDestroy(&packetAddr);
    } else {
      printf("Got a packet that is not a data nor an interest, drop it!\n");
      parcMemory_Deallocate((void **)&msgBuffer);
      return message;
    }

    message = message_CreateFromByteArray(connid, msgBuffer, pktType,
                                          forwarder_GetTicks(hicn->forwarder),
                                          forwarder_GetLogger(hicn->forwarder));
    if (message == NULL) {
      parcMemory_Deallocate((void **)&msgBuffer);
    }
  } else if (messageHandler_IsWldrNotification(msgBuffer)) {
    _handleWldrNotification(listener, msgBuffer);
  } else {

    // TODO XXX XXX XXX XXX
#if 0
    const address_pair_t * pair = _createRecvaddress_pair_t * FromPacket(packet);
    if (!pair)
      return false;
#endif
      
    messageHandler_handleHooks(hicn->forwarder, msgBuffer, listener, fd, connid, NULL);
    parcMemory_Deallocate((void **)&msgBuffer);
  }

  return message;
}

static void _receivePacket(ListenerOps * listener, int fd) {
  HicnListener * hicn = (HicnListener*)listener->context;
  Message *msg = NULL;
  uint8_t *msgBuffer = parcMemory_AllocateAndClear(MTU_SIZE);
  msg = _readMessage(listener, fd, msgBuffer);

  if (msg) {
    forwarder_Receive(hicn->forwarder, msg, 1);
  }
}

static void _hicnListener_readcb(int fd, PARCEventType what, void *listener_void) {
  ListenerOps * listener = (ListenerOps *)listener_void;
  HicnListener *hicn = (HicnListener *)listener->context;

  if (hicn->inetFamily == IPv4 || hicn->inetFamily == IPv6) {
    if (what & PARCEventType_Read) {
      _receivePacket(listener, fd);
    }
  } else {
    _readFrameToDiscard(hicn, fd);
  }
}

static bool _isEmptyAddressIPv4(Address *address) {
  bool res = false;

  if (strcmp("inet4://0.0.0.0:1234", addressToString(address)) == 0) res = true;
  return res;
}

ListenerOps *hicnListener_CreateInet(Forwarder *forwarder, char *symbolic,
                                     Address *address) {
  HicnListener *hicn = parcMemory_AllocateAndClear(sizeof(HicnListener));
  parcAssertNotNull(hicn, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(HicnListener));

  hicn->forwarder = forwarder;
  hicn->listenerName = parcMemory_StringDuplicate(symbolic, strlen(symbolic));

  hicn->conn_id = forwarder_GetNextConnectionId(forwarder);
  hicn->inetFamily = IPv4;

  hicn->connection_id = -1;

  hicn_socket_helper_t *hicnSocketHelper =
      forwarder_GetHicnSocketHelper(forwarder);

  if (_isEmptyAddressIPv4(address)) {
    hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, NULL);
  } else {
    struct sockaddr_in *tmpAddr =
        parcMemory_AllocateAndClear(sizeof(struct sockaddr_in));
    parcAssertNotNull(tmpAddr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(tmpAddr));
    addressGetInet(address, tmpAddr);
    char *local_addr = parcMemory_AllocateAndClear(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(tmpAddr->sin_addr), local_addr, INET_ADDRSTRLEN);
    parcMemory_Deallocate((void **)&tmpAddr);

    hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, local_addr);

    parcMemory_Deallocate((void **)&local_addr);
  }

  if (hicn->hicn_fd < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(
          hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
          "HicnListener %s: error while creating an hicn listener in lib_hicn",
          symbolic);
    }
    logger_Release(&hicn->logger);
    addressDestroy(&hicn->localAddress);
    parcMemory_Deallocate((void **)&hicn->listenerName);
    parcMemory_Deallocate((void **)&hicn);
    return NULL;
  }

  // Set non-blocking flag
  int flags = fcntl(hicn->hicn_fd, F_GETFL, NULL);
  parcAssertTrue(flags != -1,
                 "fcntl failed to obtain file descriptor flags (%d)", errno);
  int failure = fcntl(hicn->hicn_fd, F_SETFL, flags | O_NONBLOCK);
  parcAssertFalse(failure, "fcntl failed to set file descriptor flags (%d)",
                  errno);

  ListenerOps *ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListenerOps));

  memcpy(ops, &_hicnTemplate, sizeof(ListenerOps));
  ops->context = hicn;

  hicn->hicn_event = dispatcher_CreateNetworkEvent(
      forwarder_GetDispatcher(forwarder), true, _hicnListener_readcb,
      (void *)ops, hicn->hicn_fd);
  dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                               hicn->hicn_event);


  if (logger_IsLoggable(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "HicnListener %s created", symbolic);
  }

  return ops;
  return NULL;
}

ListenerOps *hicnListener_CreateInet6(Forwarder *forwarder, char *symbolic,
                                      Address *address) {
  HicnListener *hicn = parcMemory_AllocateAndClear(sizeof(HicnListener));
  parcAssertNotNull(hicn, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(HicnListener));

  hicn->forwarder = forwarder;
  hicn->listenerName = parcMemory_StringDuplicate(symbolic, strlen(symbolic));
  hicn->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  hicn->conn_id = forwarder_GetNextConnectionId(forwarder);
  hicn->localAddress = addressCopy(address);

  hicn->inetFamily = IPv6;

  hicn->connection_id = -1;

  // the call to libhicn is the same both for the main and the normal listeners
  // in both cases we need to set only the identifier. In the case of normal
  // listener (listener for data packet) we let the library select the right ip
  // address we just need to set the right type of packet

  hicn_socket_helper_t *hicnSocketHelper =
      forwarder_GetHicnSocketHelper(forwarder);

  if (_isEmptyAddressIPv6(address)) {
    // create main listener
    hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, NULL);
  } else {
    // create listener for the connetion
    struct sockaddr_in6 *tmpAddr =
        parcMemory_AllocateAndClear(sizeof(struct sockaddr_in6));

    parcAssertNotNull(tmpAddr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(tmpAddr));
    addressGetInet6(address, tmpAddr);

    char *local_addr = parcMemory_AllocateAndClear(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(tmpAddr->sin6_addr), local_addr, INET6_ADDRSTRLEN);

    parcMemory_Deallocate((void **)&tmpAddr);

    hicn->hicn_fd = hicn_socket(hicnSocketHelper, symbolic, local_addr);

    parcMemory_Deallocate((void **)&local_addr);
  }

  if (hicn->hicn_fd < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(
          hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
          "HicnListener %s: error while creating an hicn listener in lib_hicn",
          symbolic);
    }
    logger_Release(&hicn->logger);
    addressDestroy(&hicn->localAddress);
    parcMemory_Deallocate((void **)&hicn->listenerName);
    parcMemory_Deallocate((void **)&hicn);
    return NULL;
  }

  // Set non-blocking flag
  int flags = fcntl(hicn->hicn_fd, F_GETFL, NULL);
  parcAssertTrue(flags != -1,
                 "fcntl failed to obtain file descriptor flags (%d)", errno);
  int failure = fcntl(hicn->hicn_fd, F_SETFL, flags | O_NONBLOCK);
  parcAssertFalse(failure, "fcntl failed to set file descriptor flags (%d)",
                  errno);

  ListenerOps *ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListenerOps));

  memcpy(ops, &_hicnTemplate, sizeof(ListenerOps));
  ops->context = hicn;

  hicn->hicn_event = dispatcher_CreateNetworkEvent(
      forwarder_GetDispatcher(forwarder), true, _hicnListener_readcb,
      (void *)ops, hicn->hicn_fd);
  dispatcher_StartNetworkEvent(forwarder_GetDispatcher(forwarder),
                               hicn->hicn_event);

  if (logger_IsLoggable(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "HicnListener %s created", symbolic);
  }

  return ops;
}

bool _hicnListener_BindInet6(ListenerOps *ops, const Address *remoteAddress) {
  HicnListener *hicn = (HicnListener *)ops->context;
  hicn_socket_helper_t *hicnSocketHelper =
      forwarder_GetHicnSocketHelper(hicn->forwarder);

  struct sockaddr_in6 *tmpAddr =
      parcMemory_AllocateAndClear(sizeof(struct sockaddr_in6));
  parcAssertNotNull(tmpAddr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(tmpAddr));
  addressGetInet6(remoteAddress, tmpAddr);
  char *remote_addr = parcMemory_AllocateAndClear(INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &(tmpAddr->sin6_addr), remote_addr, INET6_ADDRSTRLEN);
  parcMemory_Deallocate((void **)&tmpAddr);

  int res = hicn_bind(hicnSocketHelper, hicn->hicn_fd, remote_addr);

  bool result = false;
  if (res < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "hicn_bind failed %d %s", res, hicn_socket_strerror(res));
    }
  } else {
    result = true;
  }

  parcMemory_Deallocate((void **)&remote_addr);

  return result;
}

bool _hicnListener_BindInet(ListenerOps *ops, const Address *remoteAddress) {
  HicnListener *hicn = (HicnListener *)ops->context;
  hicn_socket_helper_t *hicnSocketHelper =
      forwarder_GetHicnSocketHelper(hicn->forwarder);

  struct sockaddr_in *tmpAddr =
      parcMemory_AllocateAndClear(sizeof(struct sockaddr_in));
  parcAssertNotNull(tmpAddr, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(tmpAddr));
  addressGetInet(remoteAddress, tmpAddr);
  char *remote_addr = parcMemory_AllocateAndClear(INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(tmpAddr->sin_addr), remote_addr, INET_ADDRSTRLEN);
  parcMemory_Deallocate((void **)&tmpAddr);

  int res = hicn_bind(hicnSocketHelper, hicn->hicn_fd, remote_addr);
  bool result = false;

  if (res < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "hicn_bind failed %d %s", res, hicn_socket_strerror(res));
    }
  } else {
    result = true;
  }

  parcMemory_Deallocate((void **)&remote_addr);

  return result;
}

bool hicnListener_Bind(ListenerOps *ops, const Address *remoteAddress) {
  if (addressGetType(remoteAddress) == ADDR_INET) {
    return _hicnListener_BindInet(ops, remoteAddress);
  } else if (addressGetType(remoteAddress) == ADDR_INET6) {
    return _hicnListener_BindInet6(ops, remoteAddress);
  } else {
    printf("Bind failed: Invalid address\n");
    return false;
  }
}

bool hicnListener_Punting(ListenerOps *ops, const char *prefix) {
  HicnListener *hicn = (HicnListener *)ops->context;
  hicn_socket_helper_t *hicnSocketHelper =
      forwarder_GetHicnSocketHelper(hicn->forwarder);

  int res = hicn_listen(hicnSocketHelper, hicn->hicn_fd, prefix);
  int retry = 0;

  while (res < 0 && retry < MAX_HICN_RETRY) {
    sleep(1);
    res = hicn_listen(hicnSocketHelper, hicn->hicn_fd, prefix);
    retry++;
  }

  if (res < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "hicn_listen failed %d %s", res, hicn_socket_strerror(res));
    }
    return false;
  }

  return true;
}

bool hicnListener_SetConnectionId(ListenerOps *ops, unsigned connId) {
  HicnListener *hicn = (HicnListener *)ops->context;
  if (hicn) {
    hicn->connection_id = connId;
    return true;
  }
  return false;
}

static void _hicnListener_Destroy(HicnListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");

  HicnListener *hicn = *listenerPtr;

  dispatcher_DestroyNetworkEvent(forwarder_GetDispatcher(hicn->forwarder),
                                 &hicn->hicn_event);
  logger_Release(&hicn->logger);
  addressDestroy(&hicn->localAddress);
  parcMemory_Deallocate((void **)&hicn);
  *listenerPtr = NULL;
}

static void _destroy(ListenerOps **listenerOpsPtr) {
  ListenerOps *ops = *listenerOpsPtr;
  HicnListener *hicn = (HicnListener *)ops->context;
  _hicnListener_Destroy(&hicn);
  parcMemory_Deallocate((void **)&ops);
  *listenerOpsPtr = NULL;
}

static const char *_getListenerName(const ListenerOps *ops) {
  HicnListener *hicn = (HicnListener *)ops->context;
  return hicn->listenerName;
}

static const char *_getInterfaceName(const ListenerOps *ops) {
  const char *interfaceName = "";
  return interfaceName;
}

static unsigned _getInterfaceIndex(const ListenerOps *ops) {
  HicnListener *hicn = (HicnListener *)ops->context;
  return hicn->conn_id;
}

static const Address *_getListenAddress(const ListenerOps *ops) {
  HicnListener *hicn = (HicnListener *)ops->context;
  return hicn->localAddress;
}

static EncapType _getEncapType(const ListenerOps *ops) { return ENCAP_HICN; }

static int _getSocket(const ListenerOps *ops, address_pair_t * * pair) {
  HicnListener *hicn = (HicnListener *)ops->context;
  return hicn->hicn_fd;
}

// ===============================

static void _readFrameToDiscard(HicnListener *hicn, int fd) {
  // we need to discard the frame.  Read 1 byte.  This will clear it off the
  // stack.
  uint8_t buffer;
  int nread = read(fd, &buffer, 1);

  if (nread > 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
                 "Discarded frame from fd %d", fd);
    }
  } else if (nread < 0) {
    if (logger_IsLoggable(hicn->logger, LoggerFacility_IO,
                          PARCLogLevel_Error)) {
      logger_Log(hicn->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                 "Error trying to discard frame from fd %d: (%d) %s", fd, errno,
                 strerror(errno));
    }
  }
}

static unsigned _createNewConnection(ListenerOps * listener, int fd,
                                     const address_pair_t * *pair) {
  HicnListener * hicn = (HicnListener *)listener->context;
  bool isLocal = false;

  // udpConnection_Create takes ownership of the pair
  IoOperations *ops = hicnConnection_Create(hicn->forwarder, listener->getInterfaceName(listener), fd, pair, isLocal);
  Connection *conn = connection_Create(ops);

  connectionTable_Add(forwarder_GetConnectionTable(hicn->forwarder), conn);
  unsigned connid = ioOperations_GetConnectionId(ops);

  return connid;
}

static const Connection * _lookupConnection(ListenerOps * listener,
                                const address_pair_t * *pair) {
  HicnListener * hicn = (HicnListener*)listener->context;
  const Address * packetSourceAddress = addressPair_GetLocal(pair);

  const Connection *conn = NULL;
  if (hicn->connection_id != -1) {
    conn = connectionTable_FindById(
        forwarder_GetConnectionTable(hicn->forwarder), hicn->connection_id);
  } else {
    if (packetSourceAddress != NULL) {
      // in this first check we try to retrieve the standard connection
      // generated by the hicn-light
      address_pair_t * *pair =
          addressPair_Create(hicn->localAddress, packetSourceAddress);
      conn = connectionTable_FindByaddress_pair_t * (
          forwarder_GetConnectionTable(hicn->forwarder), pair);
      addressPair_Release(&pair);
    }
  }

  return conn;
}

static Address *_createAddressFromPacket(uint8_t *msgBuffer) {
  Address *packetAddr = NULL;
  if (messageHandler_GetIPPacketType(msgBuffer) == IPv6_TYPE) {
    struct sockaddr_in6 addr_in6;
    addr_in6.sin6_family = AF_INET6;
    addr_in6.sin6_port = htons(1234);
    addr_in6.sin6_flowinfo = 0;
    addr_in6.sin6_scope_id = 0;
    memcpy(&addr_in6.sin6_addr,
           (struct in6_addr *)messageHandler_GetSource(msgBuffer), 16);
    packetAddr = addressCreateFromInet6(&addr_in6);
  } else if (messageHandler_GetIPPacketType(msgBuffer) == IPv4_TYPE) {
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(1234);
    memcpy(&addr_in.sin_addr,
           (struct in_addr *)messageHandler_GetSource(msgBuffer), 4);
    packetAddr = addressCreateFromInet(&addr_in);
  }
  return packetAddr;
}

static void _handleWldrNotification(ListenerOps *listener, uint8_t *msgBuffer) {
  HicnListener * hicn = (HicnListener *)listener->context;

  Address *packetAddr = _createAddressFromPacket(msgBuffer);

  if (packetAddr == NULL) {
    parcMemory_Deallocate((void **)&msgBuffer);
    return;
  }

  address_pair_t * * pair = addressPair_Create(packetAddr, /* dummy */ hicn->localAddress);

  const Connection *conn = _lookupConnection(listener, pair);

  addressPair_Release(&pair);
  addressDestroy(&packetAddr);

  if (conn == NULL) {
    parcMemory_Deallocate((void **)&msgBuffer);
    return;
  }

  Message *message = message_CreateFromByteArray(
      connection_GetConnectionId(conn), msgBuffer,
      MessagePacketType_WldrNotification, forwarder_GetTicks(hicn->forwarder),
      forwarder_GetLogger(hicn->forwarder));

  connection_HandleWldrNotification((Connection *)conn, message);

  message_Release(&message);
}
