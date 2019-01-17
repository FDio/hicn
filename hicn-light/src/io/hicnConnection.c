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
 * Embodies the reader/writer for a HIcn connection
 *
 * NB The Send() function may overflow the output buffer
 *
 */

#include <errno.h>
#include <src/config.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <src/core/message.h>
#include <src/io/hicnConnection.h>

#include <src/core/messageHandler.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <src/core/connection.h>
#include <src/core/forwarder.h>

typedef struct hicn_state {
  Forwarder *forwarder;
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

  // this address contains one of the content names reachable
  // throught the connection peer. We need this address beacuse it is
  // the only way we have to conntact the next hop, since the main tun
  // does not have address. Notice that a connection that sends probes
  // is a connection that sends interest. In a "data" connection this
  // value will remain NULL. We refresh the content address every time
  // we send a probe, in this way we don't need to waste to much time in
  // copy the address, but we can also react to the routing changes
  struct sockaddr *probeDestAddress;
  socklen_t probeDestAddressLength;
  bool refreshProbeDestAddress;

  bool isLocal;
  bool isUp;
  unsigned id;

  unsigned delay;
} _HicnState;

// Prototypes
static bool _send(IoOperations *ops, const Address *nexthop, Message *message);
static const Address *_getRemoteAddress(const IoOperations *ops);
static const AddressPair *_getAddressPair(const IoOperations *ops);
static unsigned _getConnectionId(const IoOperations *ops);
static bool _isUp(const IoOperations *ops);
static bool _isLocal(const IoOperations *ops);
static void _destroy(IoOperations **opsPtr);
static list_connections_type _getConnectionType(const IoOperations *ops);
static Ticks _sendProbe(IoOperations *ops, unsigned probeType,
                        uint8_t *message);

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

static IoOperations _template = {.closure = NULL,
                                 .send = &_send,
                                 .getRemoteAddress = &_getRemoteAddress,
                                 .getAddressPair = &_getAddressPair,
                                 .getConnectionId = &_getConnectionId,
                                 .isUp = &_isUp,
                                 .isLocal = &_isLocal,
                                 .destroy = &_destroy,
                                 .class = &_streamConnection_Class,
                                 .getConnectionType = &_getConnectionType,
                                 .sendProbe = &_sendProbe};

// =================================================================

static void _setConnectionState(_HicnState *HIcn, bool isUp);
static bool _saveSockaddr(_HicnState *hicnConnState, const AddressPair *pair);
static void _refreshProbeDestAddress(_HicnState *hicnConnState,
                                     const uint8_t *message);

IoOperations *hicnConnection_Create(Forwarder *forwarder, int fd,
                                    const AddressPair *pair, bool isLocal) {
  IoOperations *io_ops = NULL;

  _HicnState *hicnConnState = parcMemory_AllocateAndClear(sizeof(_HicnState));
  parcAssertNotNull(hicnConnState,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_HicnState));

  hicnConnState->forwarder = forwarder;
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

    if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                          PARCLogLevel_Info)) {
      char *str = addressPair_ToString(hicnConnState->addressPair);
      logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
                 __func__,
                 "HIcnConnection %p created for address %s (isLocal %d)",
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
  if (hicnConnState->probeDestAddress != NULL)
    parcMemory_Deallocate((void **)&(hicnConnState->probeDestAddress));

  messenger_Send(
      forwarder_GetMessenger(hicnConnState->forwarder),
      missive_Create(MissiveType_ConnectionDestroyed, hicnConnState->id));

  if (logger_IsLoggable(hicnConnState->logger, LoggerFacility_IO,
                        PARCLogLevel_Info)) {
    logger_Log(hicnConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
               __func__, "HIcnConnection %p destroyed", (void *)hicnConnState);
  }

  // XXX
  // do not close hicListenerSocket, the listener will close
  // that when its done
  // should I say something to libhicn?

  logger_Release(&hicnConnState->logger);
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
 * @return <#return#>
 */
static bool _send(IoOperations *ops, const Address *dummy, Message *message) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);

  // NAT for HICN
  // XXX
  if (message_GetType(message) == MessagePacketType_ContentObject) {
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
  } else if (message_GetType(message) == MessagePacketType_Interest) {
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

    // only in this case we may need to set the probeDestAddress
    if (hicnConnState->refreshProbeDestAddress) {
      _refreshProbeDestAddress(hicnConnState, message_FixedHeader(message));
    }

  } else if (message_GetType(message) == MessagePacketType_WldrNotification) {
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

static list_connections_type _getConnectionType(const IoOperations *ops) {
  return CONN_HICN;
}

static Ticks _sendProbe(IoOperations *ops, unsigned probeType,
                        uint8_t *message) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  _HicnState *hicnConnState = (_HicnState *)ioOperations_GetClosure(ops);

  if ((hicnConnState->peerAddressLength == sizeof(struct sockaddr_in)) ||
      (hicnConnState->localAddressLength == sizeof(struct sockaddr_in)))
    return false;

  if (hicnConnState->probeDestAddress == NULL &&
      probeType == PACKET_TYPE_PROBE_REPLY) {
    uint8_t *pkt = parcMemory_AllocateAndClear(
        messageHandler_GetICMPPacketSize(IPv6_TYPE));
    messageHandler_SetProbePacket(
        pkt, probeType,
        (struct in6_addr *)messageHandler_GetDestination(message),
        (struct in6_addr *)messageHandler_GetSource(message));

    ssize_t writeLength = write(hicnConnState->hicnListenerSocket, pkt,
                                messageHandler_GetICMPPacketSize(IPv6_TYPE));

    parcMemory_Deallocate((void **)&pkt);

    if (writeLength < 0) {
      return 0;
    }

  } else if (hicnConnState->probeDestAddress != NULL &&
             probeType == PACKET_TYPE_PROBE_REQUEST) {
    hicnConnState->refreshProbeDestAddress = true;

    uint8_t *pkt = parcMemory_AllocateAndClear(
        messageHandler_GetICMPPacketSize(IPv6_TYPE));
    messageHandler_SetProbePacket(
        pkt, probeType,
        &((struct sockaddr_in6 *)hicnConnState->localAddress)->sin6_addr,
        &((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_addr);

    ssize_t writeLength = write(hicnConnState->hicnListenerSocket, pkt,
                                messageHandler_GetICMPPacketSize(IPv6_TYPE));

    parcMemory_Deallocate((void **)&pkt);

    if (writeLength < 0) {
      return 0;
    }

  } else {
    if (hicnConnState->probeDestAddress == NULL &&
        probeType == PACKET_TYPE_PROBE_REQUEST) {
      // this happen for the first probe
      hicnConnState->refreshProbeDestAddress = true;
    }
    // do nothing
    return 0;
  }

  return forwarder_GetTicks(hicnConnState->forwarder);
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

      hicnConnState->probeDestAddress = NULL;
      hicnConnState->probeDestAddressLength = (socklen_t)bytes;
      hicnConnState->refreshProbeDestAddress = false;

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

      hicnConnState->probeDestAddress = NULL;
      hicnConnState->probeDestAddressLength = (socklen_t)bytes;
      hicnConnState->refreshProbeDestAddress = false;

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

static void _refreshProbeDestAddress(_HicnState *hicnConnState,
                                     const uint8_t *message) {
  if ((hicnConnState->peerAddressLength == sizeof(struct sockaddr_in)) ||
      (hicnConnState->localAddressLength == sizeof(struct sockaddr_in)))
    return;

  if (hicnConnState->probeDestAddress == NULL) {
    hicnConnState->probeDestAddress =
        parcMemory_AllocateAndClear(sizeof(struct sockaddr_in6));
    parcAssertNotNull(hicnConnState->probeDestAddress,
                      "parcMemory_Allocate(%zu) returned NULL",
                      sizeof(struct sockaddr_in6));
  }

  ((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_family =
      AF_INET6;
  ((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_port =
      htons(1234);
  ((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_scope_id = 0;
  ((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_flowinfo = 0;
  ((struct sockaddr_in6 *)hicnConnState->probeDestAddress)->sin6_addr =
      *((struct in6_addr *)messageHandler_GetDestination(message));
  hicnConnState->refreshProbeDestAddress = false;
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
