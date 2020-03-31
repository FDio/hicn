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
 * Embodies the reader/writer for a Hicn connection
 *
 * NB The Send() function may overflow the output buffer
 *
 */

#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <hicn/core/message.h>
#include <hicn/io/hicnConnection.h>

#include <hicn/core/messageHandler.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>

typedef struct hicn_state {
  Forwarder *forwarder;
  char * interfaceName;
  Logger *logger;

  // the hicn listener socket we receive packets on
  int hicnListenerSocket;

  AddressPair *addressPair;

  // We need to access this all the time, so grab it out
  // of the addressPair;
  struct sockaddr *peerAddress;
  socklen_t peerAddressLength;

  struct sockaddr *localAddress;
  socklen_t localAddressLength;

  bool isLocal;
  bool isUp;
  unsigned id;

  unsigned delay;

  /* This information would better be stored in the connection data structure
   * but it is currently not reachable from within the implementation. */
  connection_state_t state;
  connection_state_t admin_state;
#ifdef WITH_POLICY
  uint32_t priority;
#endif /* WITH_POLICY */
} _HicnState;

// Prototypes
static bool _send(IoOperations *ops, const Address *nexthop, Message *message, bool queue);
static bool _sendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size);
static const Address *_getRemoteAddress(const IoOperations *ops);
static const AddressPair *_getAddressPair(const IoOperations *ops);
static unsigned _getConnectionId(const IoOperations *ops);
static bool _isUp(const IoOperations *ops);
static bool _isLocal(const IoOperations *ops);
static void _destroy(IoOperations **opsPtr);
static list_connections_type _getConnectionType(const IoOperations *ops);
static void _sendProbe(IoOperations *ops, uint8_t *message);
static connection_state_t _getState(const IoOperations *ops);
static void _setState(IoOperations *ops, connection_state_t state);
static connection_state_t _getAdminState(const IoOperations *ops);
static void _setAdminState(IoOperations *ops, connection_state_t admin_state);
#ifdef WITH_POLICY
static uint32_t _getPriority(const IoOperations *ops);
static void _setPriority(IoOperations *ops, uint32_t priority);
#endif /* WITH_POLICY */
static const char * _getInterfaceName(const IoOperations *ops);

/*
 * This assigns a unique pointer to the void * which we use
 * as a GUID for this class.
 */
static const void *_ioOperationsGuid = __FILE__;

/*
 * Return our GUID
 */
static const void *_streamConnection_Class(const IoOperations *ops) {
  return _ioOperationsGuid;
}

static IoOperations _template = {
  .closure = NULL,
  .send = &_send,
  .sendIOVBuffer = &_sendIOVBuffer,
  .getRemoteAddress = &_getRemoteAddress,
  .getAddressPair = &_getAddressPair,
  .getConnectionId = &_getConnectionId,
  .isUp = &_isUp,
  .isLocal = &_isLocal,
  .destroy = &_destroy,
  .class = &_streamConnection_Class,
  .getConnectionType = &_getConnectionType,
  .sendProbe = &_sendProbe,
  .getState = &_getState,
  .setState = &_setState,
  .getAdminState = &_getAdminState,
  .setAdminState = &_setAdminState,
#ifdef WITH_POLICY
  .getPriority = &_getPriority,
  .setPriority = &_setPriority,
#endif /* WITH_POLICY */
  .getInterfaceName = &_getInterfaceName,
};

// =================================================================

static void _setConnectionState(_HicnState *Hicn, bool isUp);
static bool _saveSockaddr(_HicnState *hicnConnState, const AddressPair *pair);

IoOperations *hicnConnection_Create(Forwarder *forwarder, const char * interfaceName, int fd,
                                    const AddressPair *pair, bool isLocal) {
  IoOperations *io_ops = NULL;

  _HicnState *hicnConnState = parcMemory_AllocateAndClear(sizeof(_HicnState));
  parcAssertNotNull(hicnConnState,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_HicnState));

  hicnConnState->forwarder = forwarder;
  hicnConnState->interfaceName = strdup(interfaceName);
  hicnConnState->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  bool saved = _saveSockaddr(hicnConnState, pair);
  if (saved) {
    hicnConnState->hicnListenerSocket = fd;
    hicnConnState->id = forwarder_GetNextConnectionId(forwarder);
    hicnConnState->addressPair = addressPair_Acquire(pair);
    hicnConnState->isLocal = isLocal;

    // allocate a connection
    io_ops = parcMemory_AllocateAndClear(sizeof(IoOperations));
    parcAssertNotNull(io_ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(IoOperations));
    memcpy(io_ops, &_template, sizeof(IoOperations));
    io_ops->closure = hicnConnState;

    _setConnectionState(hicnConnState, true);

#ifdef WITH_POLICY
    hicnConnState->priority = 0;
#endif /* WITH_POLICY */

    if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                          PARCLogLevel_Info)) {
      char *str = addressPair_ToString(hicnConnState->addressPair);
      logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
                 __func__,
                 "HicnConnection %p created for address %s (isLocal %d)",
                 (void *)hicnConnState, str, hicnConnState->isLocal);
      free(str);
    }

    messenger_Send(
        forwarder_GetMessenger(forwarder),
        missive_Create(MissiveType_ConnectionCreate, hicnConnState->id));
    messenger_Send(forwarder_GetMessenger(forwarder),
                   missive_Create(MissiveType_ConnectionUp, hicnConnState->id));
  } else {
    // _saveSockaddr will already log an error, no need for extra log message
    // here
    logger_Release(&hicnConnState->logger);
    free(hicnConnState->interfaceName);
    parcMemory_Deallocate((void **)&hicnConnState);
  }

  return io_ops;
}

// =================================================================
// I/O Operations implementation

static void _destroy(IoOperations **opsPtr) {
  parcAssertNotNull(opsPtr, "Parameter opsPtr must be non-null double pointer");
  parcAssertNotNull(*opsPtr,
                    "Parameter opsPtr must dereference to non-null pointer");

  IoOperations *ops = *opsPtr;
  parcAssertNotNull(ioOperations_GetClosure(ops),
                    "ops->context must not be null");

  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);
  addressPair_Release(&hicnConnState->addressPair);
  parcMemory_Deallocate((void **)&(hicnConnState->peerAddress));
  parcMemory_Deallocate((void **)&(hicnConnState->localAddress));

  messenger_Send(
      forwarder_GetMessenger(hicnConnState->forwarder),
      missive_Create(MissiveType_ConnectionDestroyed, hicnConnState->id));

  if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                        PARCLogLevel_Info)) {
    logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
               __func__, "HicnConnection %p destroyed", (void *)hicnConnState);
  }

  // do not close hicListenerSocket, the listener will close
  // that when its done
  // should I say something to libhicn?

  logger_Release(&hicnConnState->logger);
  free(hicnConnState->interfaceName);
  parcMemory_Deallocate((void **)&hicnConnState);
  parcMemory_Deallocate((void **)&ops);

  *opsPtr = NULL;
}

static bool _isUp(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->isUp;
}

static bool _isLocal(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->isLocal;
}

static const Address *_getRemoteAddress(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return addressPair_GetRemote(hicnConnState->addressPair);
}

static const AddressPair *_getAddressPair(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->addressPair;
}

static unsigned _getConnectionId(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->id;
}

/**
 * @function hicnConnection_Send
 * @abstract Non-destructive send of the message.
 * @discussion
 *   sends a message to the peer.
 *
 * @param dummy is ignored. .
 */
/* @param queue is ignored for now */
static bool _send(IoOperations *ops, const Address *nexthop, Message *message, bool queue) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");

  /* No need to flush */
  if (!message)
    return true;

  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);

  // NAT for HICN
  if (message_GetType(message) == MESSAGE_TYPE_DATA) {
    // this is a data packet. We need to put the remote address in the
    // destination field

    if (messageHandler_GetIPPacketType(message_FixedHeader(message)) ==
        IPv6_TYPE) {
      messageHandler_SetDestination_IPv6(
          (uint8_t *)message_FixedHeader(message),
          &((struct sockaddr_in6 *)hicnConnState->peerAddress)->sin6_addr);
    } else {
      messageHandler_SetDestination_IPv4(
          (uint8_t *)message_FixedHeader(message),
          &(((struct sockaddr_in *)hicnConnState->peerAddress)
                ->sin_addr.s_addr));
    }
  } else if (message_GetType(message) == MESSAGE_TYPE_INTEREST) {
    // this si an interest packet. We need to put the local address in the
    // source field
    if (messageHandler_GetIPPacketType(message_FixedHeader(message)) ==
        IPv6_TYPE) {
      messageHandler_SetSource_IPv6(
          (uint8_t *)message_FixedHeader(message),
          &((struct sockaddr_in6 *)hicnConnState->localAddress)->sin6_addr);
    } else {
      messageHandler_SetSource_IPv4(
          (uint8_t *)message_FixedHeader(message),
          &(((struct sockaddr_in *)hicnConnState->localAddress)
                ->sin_addr.s_addr));
    }
  } else if (message_GetType(message) == MESSAGE_TYPE_WLDR_NOTIFICATION) {
    // here we don't need to do anything for now
  } else {
    // unkown packet
    if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                          PARCLogLevel_Debug)) {
      logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Debug,
                 __func__, "connid %u can't parse the message",
                 hicnConnState->id);
    }
    return false;
  }

  ssize_t writeLength =
      write(hicnConnState->hicnListenerSocket, message_FixedHeader(message),
            message_Length(message));

  if (writeLength < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return false;
    } else {
      // this print is for debugging
      printf("Incorrect write length %zd, expected %zd: (%d) %s\n", writeLength,
             message_Length(message), errno, strerror(errno));
      return false;
    }
  }

  return true;
}

static bool _sendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);


  ssize_t n = writev(hicnConnState->hicnListenerSocket, message, size);
  if (n < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                  PARCLogLevel_Error)) {
        size_t length = 0;
        for (int i = 0; i < size; i++)
          length += message[i].iov_len;
        logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Error,
                __func__, "Incorrect write length %zd, expected %zd: (%d) %s\n",
                n, length, errno, strerror(errno));
      }
    }
    return false;
  }
  return true;
}

static list_connections_type _getConnectionType(const IoOperations *ops) {
  return CONN_HICN;
}

static void _sendProbe(IoOperations *ops, uint8_t *message) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");

  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);

  if(messageHandler_IsInterest(message)){//
    // this is an interest packet. We need to put the local address in the
    // source field
    if (messageHandler_GetIPPacketType(message) == IPv6_TYPE) {
      messageHandler_SetSource_IPv6(message,
          &((struct sockaddr_in6 *)hicnConnState->localAddress)->sin6_addr);
    } else {
      messageHandler_SetSource_IPv4(message,
          &(((struct sockaddr_in *)hicnConnState->localAddress)
                ->sin_addr.s_addr));
    }
  }//if is a data packet the packet is already set (see
   //messageHandler_CreateProbeReply)

  ssize_t writeLength = write(hicnConnState->hicnListenerSocket, message,
                                messageHandler_GetTotalPacketLength(message));

  if (writeLength < 0) {
    return;
  }
}

// =================================================================
// Internal API

static bool _saveSockaddr(_HicnState *hicnConnState, const AddressPair *pair) {
  bool success = false;
  const Address *remoteAddress = addressPair_GetRemote(pair);
  const Address *localAddress = addressPair_GetLocal(pair);
  switch (addressGetType(remoteAddress)) {  // local must be of the same type

    case ADDR_INET: {
      size_t bytes = sizeof(struct sockaddr_in);
      hicnConnState->peerAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(hicnConnState->peerAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet(remoteAddress,
                     (struct sockaddr_in *)hicnConnState->peerAddress);
      hicnConnState->peerAddressLength = (socklen_t)bytes;

      hicnConnState->localAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(hicnConnState->localAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet(localAddress,
                     (struct sockaddr_in *)hicnConnState->localAddress);
      hicnConnState->localAddressLength = (socklen_t)bytes;
      success = true;
      break;
    }

    case ADDR_INET6: {
      size_t bytes = sizeof(struct sockaddr_in6);
      hicnConnState->peerAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(hicnConnState->peerAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet6(remoteAddress,
                      (struct sockaddr_in6 *)hicnConnState->peerAddress);
      hicnConnState->peerAddressLength = (socklen_t)bytes;

      hicnConnState->localAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(hicnConnState->localAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet6(localAddress,
                      (struct sockaddr_in6 *)hicnConnState->localAddress);
      hicnConnState->localAddressLength = (socklen_t)bytes;
      success = true;
      break;
    }

    default:
      if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                            PARCLogLevel_Error)) {
        char *str = addressToString(remoteAddress);
        logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Error,
                   __func__, "Remote address is not INET or INET6: %s", str);
        parcMemory_Deallocate((void **)&str);
      }
      break;
  }
  return success;
}

static void _setConnectionState(_HicnState *hicnConnState, bool isUp) {
  parcAssertNotNull(hicnConnState, "Parameter HICN must be non-null");

  Messenger *messenger = forwarder_GetMessenger(hicnConnState->forwarder);

  bool oldStateIsUp = hicnConnState->isUp;
  hicnConnState->isUp = isUp;

  if (oldStateIsUp && !isUp) {
    // bring connection DOWN
    Missive *missive =
        missive_Create(MissiveType_ConnectionDown, hicnConnState->id);
    messenger_Send(messenger, missive);
    return;
  }

  if (!oldStateIsUp && isUp) {
    // bring connection UP
    Missive *missive =
        missive_Create(MissiveType_ConnectionUp, hicnConnState->id);
    messenger_Send(messenger, missive);
    return;
  }
}

static connection_state_t _getState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->state;
}

static void _setState(IoOperations *ops, connection_state_t state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _HicnState *hicnConnState =
      (_HicnState *)ioOperations_GetClosure(ops);
  hicnConnState->state = state;
}

static connection_state_t _getAdminState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->admin_state;
}

static void _setAdminState(IoOperations *ops, connection_state_t admin_state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _HicnState *hicnConnState =
      (_HicnState *)ioOperations_GetClosure(ops);
  hicnConnState->admin_state = admin_state;
}

#ifdef WITH_POLICY
static uint32_t _getPriority(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _HicnState *hicnConnState =
      (const _HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->priority;
}

static void _setPriority(IoOperations *ops, uint32_t priority) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _HicnState *hicnConnState =
      (_HicnState *)ioOperations_GetClosure(ops);
  hicnConnState->priority = priority;
}
#endif /* WITH_POLICY
*/
static const char * _getInterfaceName(const IoOperations *ops)
{
  parcAssertNotNull(ops, "Parameter must be non-null");
  _HicnState *hicnConnState =
      (_HicnState *)ioOperations_GetClosure(ops);
  return hicnConnState->interfaceName;
}
