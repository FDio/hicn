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
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <hicn/core/connectionTable.h>
#include <hicn/core/forwarder.h>
#include <hicn/io/listener.h>
#include <hicn/io/streamConnection.h>
#include <hicn/io/tcpListener.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>

typedef struct tcp_listener {
  char *listenerName;
  Forwarder *forwarder;
  Logger *logger;

  PARCEventSocket *listener;

  Address *localAddress;

  unsigned id;
  char *interfaceName;

  // is the localAddress as 127.0.0.0 address?
  bool isLocalAddressLocal;
} _TcpListener;

static void _tcpListener_Destroy(_TcpListener **listenerPtr);

static void _tcpListener_OpsDestroy(ListenerOps **listenerOpsPtr);

static const char *_tcpListener_ListenerName(const ListenerOps *ops);

static unsigned _tcpListener_OpsGetInterfaceIndex(const ListenerOps *ops);

static const Address *_tcpListener_OpsGetListenAddress(const ListenerOps *ops);

static const char *_tcpListener_InterfaceName(const ListenerOps *ops);

static EncapType _tcpListener_OpsGetEncapType(const ListenerOps *ops);

static ListenerOps _tcpTemplate = {
    .context = NULL,
    .destroy = &_tcpListener_OpsDestroy,
    .getListenerName = &_tcpListener_ListenerName,
    .getInterfaceIndex = &_tcpListener_OpsGetInterfaceIndex,
    .getListenAddress = &_tcpListener_OpsGetListenAddress,
    .getEncapType = &_tcpListener_OpsGetEncapType,
    .getInterfaceName = &_tcpListener_InterfaceName,
    .getSocket = NULL};

// STREAM daemon listener callback
static void _tcpListener_Listen(int, struct sockaddr *, int socklen,
                                void *tcpVoid);

ListenerOps *tcpListener_CreateInet6(Forwarder *forwarder, char *listenerName,
                                     struct sockaddr_in6 sin6, char *interfaceName) {

  _TcpListener *tcp = parcMemory_AllocateAndClear(sizeof(_TcpListener));
  parcAssertNotNull(tcp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_TcpListener));

  tcp->forwarder = forwarder;
  tcp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  tcp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  tcp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));

  tcp->listener = dispatcher_CreateListener(
      forwarder_GetDispatcher(forwarder), _tcpListener_Listen, (void *)tcp, -1,
      (struct sockaddr *)&sin6, sizeof(sin6));

  if (tcp->listener == NULL) {
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
               "dispatcher_CreateListener failed to create listener (%d) %s",
               errno, strerror(errno));
    logger_Release(&tcp->logger);
    parcMemory_Deallocate((void **)&tcp);
    return NULL;
  }

  tcp->localAddress = addressCreateFromInet6(&sin6);
  tcp->id = forwarder_GetNextConnectionId(forwarder);
  tcp->isLocalAddressLocal =
      parcNetwork_IsSocketLocal((struct sockaddr *)&sin6);

  ListenerOps *ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListenerOps));

  memcpy(ops, &_tcpTemplate, sizeof(ListenerOps));
  ops->context = tcp;

  if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    char *str = addressToString(tcp->localAddress);
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "TcpListener %p created for address %s (isLocal %d)",
               (void *)tcp, str, tcp->isLocalAddressLocal);
    parcMemory_Deallocate((void **)&str);
  }

  return ops;
}

ListenerOps *tcpListener_CreateInet(Forwarder *forwarder, char *listenerName,
                                    struct sockaddr_in sin, char *interfaceName) {
  _TcpListener *tcp = parcMemory_AllocateAndClear(sizeof(_TcpListener));
  parcAssertNotNull(tcp, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_TcpListener));

  tcp->forwarder = forwarder;
  tcp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  tcp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  tcp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));

  tcp->listener = dispatcher_CreateListener(
      forwarder_GetDispatcher(forwarder), _tcpListener_Listen, (void *)tcp, -1,
      (struct sockaddr *)&sin, sizeof(sin));

  if (tcp->listener == NULL) {
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
               "dispatcher_CreateListener failed to create listener (%d) %s",
               errno, strerror(errno));

    logger_Release(&tcp->logger);
    parcMemory_Deallocate((void **)&tcp);
    return NULL;
  }

  tcp->localAddress = addressCreateFromInet(&sin);
  tcp->id = forwarder_GetNextConnectionId(forwarder);
  tcp->isLocalAddressLocal = parcNetwork_IsSocketLocal((struct sockaddr *)&sin);

  ListenerOps *ops = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  parcAssertNotNull(ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ListenerOps));

  memcpy(ops, &_tcpTemplate, sizeof(ListenerOps));
  ops->context = tcp;

  if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    char *str = addressToString(tcp->localAddress);
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "TcpListener %p created for address %s (isLocal %d)",
               (void *)tcp, str, tcp->isLocalAddressLocal);
    parcMemory_Deallocate((void **)&str);
  }

  return ops;
}

static void _tcpListener_Destroy(_TcpListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");
  _TcpListener *tcp = *listenerPtr;

  if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    char *str = addressToString(tcp->localAddress);
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "TcpListener %p destroyed", (void *)tcp);
    parcMemory_Deallocate((void **)&str);
  }

  parcMemory_Deallocate((void **)&tcp->listenerName);
  parcMemory_Deallocate((void **)&tcp->interfaceName);
  logger_Release(&tcp->logger);
  dispatcher_DestroyListener(forwarder_GetDispatcher(tcp->forwarder),
                             &tcp->listener);
  addressDestroy(&tcp->localAddress);
  parcMemory_Deallocate((void **)&tcp);
  *listenerPtr = NULL;
}

// ==================================================

static const char *_tcpListener_ListenerName(const ListenerOps *ops) {
  _TcpListener *tcp = (_TcpListener *)ops->context;
  return tcp->listenerName;
}

static const char *_tcpListener_InterfaceName(const ListenerOps *ops) {
  _TcpListener *tcp = (_TcpListener *)ops->context;
  return tcp->interfaceName;
}

static void _tcpListener_Listen(int fd, struct sockaddr *sa, int socklen,
                                void *tcpVoid) {
  _TcpListener *tcp = (_TcpListener *)tcpVoid;

  Address *remote;

  switch (sa->sa_family) {
    case AF_INET:
      remote = addressCreateFromInet((struct sockaddr_in *)sa);
      break;

    case AF_INET6:
      remote = addressCreateFromInet6((struct sockaddr_in6 *)sa);
      break;

    default:
      parcTrapIllegalValue(sa, "Expected INET or INET6, got %d", sa->sa_family);
      abort();
  }

  AddressPair *pair = addressPair_Create(tcp->localAddress, remote);

  IoOperations *ops = streamConnection_AcceptConnection(
      tcp->forwarder, fd, pair, tcp->isLocalAddressLocal);
  Connection *conn = connection_Create(ops);

  connectionTable_Add(forwarder_GetConnectionTable(tcp->forwarder), conn);

  if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "TcpListener %p listen started", (void *)tcp);
  }

  addressDestroy(&remote);
}

static void _tcpListener_OpsDestroy(ListenerOps **listenerOpsPtr) {
  ListenerOps *ops = *listenerOpsPtr;
  _TcpListener *tcp = (_TcpListener *)ops->context;
  _tcpListener_Destroy(&tcp);
  parcMemory_Deallocate((void **)&ops);
  *listenerOpsPtr = NULL;
}

static unsigned _tcpListener_OpsGetInterfaceIndex(const ListenerOps *ops) {
  _TcpListener *tcp = (_TcpListener *)ops->context;
  return tcp->id;
}

static const Address *_tcpListener_OpsGetListenAddress(const ListenerOps *ops) {
  _TcpListener *tcp = (_TcpListener *)ops->context;
  return tcp->localAddress;
}

static EncapType _tcpListener_OpsGetEncapType(const ListenerOps *ops) {
  return ENCAP_TCP;
}
