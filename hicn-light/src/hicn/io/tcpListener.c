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

#include <hicn/core/forwarder.h>
#include <hicn/io/listener.h>
#include <hicn/io/streamConnection.h>
#include <hicn/io/tcpListener.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>

#define DEBUG(FMT, ...) do {                                                    \
    if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug))  \
      logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

#define ERROR(FMT, ...) do {                                                    \
    if (logger_IsLoggable(tcp->logger, LoggerFacility_IO,  PARCLogLevel_Error)) \
      logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

typedef struct tcp_listener {
  char *listenerName;
  Forwarder *forwarder;
  Logger *logger;

  PARCEventSocket *listener;

  address_t local_address;

  unsigned id;
  char *interfaceName;

  // is the local_address as 127.0.0.0 address?
  bool isLocalAddressLocal;
} _TcpListener;

static void _tcpListener_Destroy(_TcpListener **listenerPtr);

static void _tcpListener_OpsDestroy(ListenerOps **listenerOpsPtr);

static const char *_tcpListener_ListenerName(const ListenerOps *ops);

static unsigned _tcpListener_OpsGetInterfaceIndex(const ListenerOps *ops);

static const address_t *_tcpListener_OpsGetListenAddress(const ListenerOps *ops);

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

/* STREAM daemon listener callback */
static void _tcpListener_Listen(int fd, struct sockaddr *, int socklen, void
        *tcpVoid);

ListenerOps *
tcpListener_Create(Forwarder *forwarder, char *listenerName,
        const address_t * address, char *interfaceName)
{
  _TcpListener *tcp = parcMemory_AllocateAndClear(sizeof(_TcpListener));
  if (!tcp) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(_TcpListener));
    goto ERR_TCP;
  }
  tcp->forwarder = forwarder;
  tcp->listenerName = parcMemory_StringDuplicate(listenerName, strlen(listenerName));
  tcp->interfaceName = parcMemory_StringDuplicate(interfaceName, strlen(interfaceName));
  tcp->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  tcp->listener = dispatcher_CreateListener(
      forwarder_GetDispatcher(forwarder), _tcpListener_Listen, (void *)tcp, -1,
      address, address_socklen(address));
  if (!tcp->listener) {
    ERROR("dispatcher_CreateListener failed to create listener (%d) %s", errno,
            strerror(errno));
    goto ERR_LISTENER;
  }

  tcp->local_address = *address;
  tcp->id = forwarder_GetNextConnectionId(forwarder);
  tcp->isLocalAddressLocal = address_is_local(address);

  ListenerOps *listener = parcMemory_AllocateAndClear(sizeof(ListenerOps));
  if (!listener) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(ListenerOps));
    goto ERR;
  }
  memcpy(listener, &_tcpTemplate, sizeof(ListenerOps));
  listener->context = tcp;

// XXX TODO
#if 0
  char *str = addressToString(tcp->local_address);
  DEBUG("TcpListener %p created for address %s (isLocal %d)", (void *)tcp,
          str, tcp->isLocalAddressLocal);
  parcMemory_Deallocate((void **)&str);
#endif

  return listener;

ERR:
  // XXX TODO
  // Dispatcher_RemoveListener() ?
ERR_LISTENER:
  logger_Release(&tcp->logger);
  parcMemory_Deallocate((void **)&tcp->interfaceName);
  parcMemory_Deallocate((void **)&tcp->listenerName);
  parcMemory_Deallocate((void **)&tcp);
ERR_TCP:
  return NULL;
}

static void _tcpListener_Destroy(_TcpListener **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must derefernce to non-null pointer");
  _TcpListener *tcp = *listenerPtr;

#if 0
  if (logger_IsLoggable(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug)) {
    char *str = addressToString(tcp->local_address);
    logger_Log(tcp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "TcpListener %p destroyed", (void *)tcp);
    parcMemory_Deallocate((void **)&str);
  }
#endif

  parcMemory_Deallocate((void **)&tcp->listenerName);
  parcMemory_Deallocate((void **)&tcp->interfaceName);
  logger_Release(&tcp->logger);
  dispatcher_DestroyListener(forwarder_GetDispatcher(tcp->forwarder),
                             &tcp->listener);
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

/**
 * @note The prototype should not change as it is a PARCEventSocket_Callback
 */
static
void
_tcpListener_Listen(int fd, struct sockaddr * sa, int socklen, void *tcpVoid)
{
  address_t * remote = (address_t *)sa;
  _TcpListener *tcp = (_TcpListener *)tcpVoid;

  address_pair_t pair = {
    .local = tcp->local_address,
    .remote = *remote,
  };

  IoOperations *ops = streamConnection_AcceptConnection( tcp->forwarder, fd,
          &pair, tcp->isLocalAddressLocal);

  connection_table_t * table = forwarder_GetConnectionTable(tcp->forwarder);
  Connection ** conn_ptr;
  connection_table_allocate(table, conn_ptr, &pair);
  *conn_ptr = connection_Create(ops);

  DEBUG("TcpListener %p listen started", (void *)tcp)
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

static const address_t *_tcpListener_OpsGetListenAddress(const ListenerOps *ops) {
  _TcpListener *tcp = (_TcpListener *)ops->context;
  return &tcp->local_address;
}

static EncapType _tcpListener_OpsGetEncapType(const ListenerOps *ops) {
  return ENCAP_TCP;
}
