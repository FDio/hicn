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
 * Embodies the reader/writer for a UDP connection
 *
 * NB The Send() function may overflow the output buffer
 *
 */

#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <errno.h>
#include <src/config.h>
#include <stdio.h>
#include <string.h>

#include <src/core/messageHandler.h>
#include <src/io/udpConnection.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <src/core/connection.h>
#include <src/core/forwarder.h>
#include <src/core/message.h>

typedef struct udp_state {
  Forwarder *forwarder;
  Logger *logger;

  // the udp listener socket we receive packets on
  int udpListenerSocket;

  AddressPair *addressPair;

  // We need to access this all the time, so grab it out
  // of the addressPair;
  struct sockaddr *peerAddress;
  socklen_t peerAddressLength;

  bool isLocal;
  bool isUp;
  unsigned id;

  unsigned delay;
} _UdpState;

// Prototypes
static bool _send(IoOperations *ops, const Address *nexthop, Message *message);
static bool _sendCommandResponse(IoOperations *ops, struct iovec *message);
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
static const void *_IoOperationsGuid = __FILE__;

/*
 * Return our GUID
 */
static const void *_streamConnection_Class(const IoOperations *ops) {
  return _IoOperationsGuid;
}

static IoOperations _template = {.closure = NULL,
                                 .send = &_send,
                                 .sendCommandResponse = &_sendCommandResponse,
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

static void _setConnectionState(_UdpState *Udp, bool isUp);
static bool _saveSockaddr(_UdpState *udpConnState, const AddressPair *pair);

IoOperations *udpConnection_Create(Forwarder *forwarder, int fd,
                                   const AddressPair *pair, bool isLocal) {
  IoOperations *io_ops = NULL;

  _UdpState *udpConnState = parcMemory_AllocateAndClear(sizeof(_UdpState));
  parcAssertNotNull(udpConnState,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_UdpState));

  udpConnState->forwarder = forwarder;
  udpConnState->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  bool saved = _saveSockaddr(udpConnState, pair);
  if (saved) {
    udpConnState->udpListenerSocket = fd;
    udpConnState->id = forwarder_GetNextConnectionId(forwarder);
    udpConnState->addressPair = addressPair_Acquire(pair);
    udpConnState->isLocal = isLocal;

    // allocate a connection
    io_ops = parcMemory_AllocateAndClear(sizeof(IoOperations));
    parcAssertNotNull(io_ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                      sizeof(IoOperations));
    memcpy(io_ops, &_template, sizeof(IoOperations));
    io_ops->closure = udpConnState;

    _setConnectionState(udpConnState, true);

    if (logger_IsLoggable(udpConnState->logger, LoggerFacility_IO,
                          PARCLogLevel_Info)) {
      char *str = addressPair_ToString(udpConnState->addressPair);
      logger_Log(udpConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
                 __func__,
                 "UdpConnection %p created for address %s (isLocal %d)",
                 (void *)udpConnState, str, udpConnState->isLocal);
      free(str);
    }

    messenger_Send(
        forwarder_GetMessenger(forwarder),
        missive_Create(MissiveType_ConnectionCreate, udpConnState->id));
    messenger_Send(forwarder_GetMessenger(forwarder),
                   missive_Create(MissiveType_ConnectionUp, udpConnState->id));
  } else {
    // _saveSockaddr will already log an error, no need for extra log message
    // here
    logger_Release(&udpConnState->logger);
    parcMemory_Deallocate((void **)&udpConnState);
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

  _UdpState *udpConnState = (_UdpState *)ioOperations_GetClosure(ops);
  addressPair_Release(&udpConnState->addressPair);
  parcMemory_Deallocate((void **)&(udpConnState->peerAddress));

  messenger_Send(
      forwarder_GetMessenger(udpConnState->forwarder),
      missive_Create(MissiveType_ConnectionDestroyed, udpConnState->id));

  if (logger_IsLoggable(udpConnState->logger, LoggerFacility_IO,
                        PARCLogLevel_Info)) {
    logger_Log(udpConnState->logger, LoggerFacility_IO, PARCLogLevel_Info,
               __func__, "UdpConnection %p destroyed", (void *)udpConnState);
  }

  // do not close udp->udpListenerSocket, the listener will close
  // that when its done

  logger_Release(&udpConnState->logger);
  parcMemory_Deallocate((void **)&udpConnState);
  parcMemory_Deallocate((void **)&ops);

  *opsPtr = NULL;
}

static bool _isUp(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udpConnState =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udpConnState->isUp;
}

static bool _isLocal(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udpConnState =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udpConnState->isLocal;
}

static const Address *_getRemoteAddress(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udpConnState =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return addressPair_GetRemote(udpConnState->addressPair);
}

static const AddressPair *_getAddressPair(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udpConnState =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udpConnState->addressPair;
}

static unsigned _getConnectionId(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udpConnState =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udpConnState->id;
}

/**
 * @function metisUdpConnection_Send
 * @abstract Non-destructive send of the message.
 * @discussion
 *   sends a message to the peer.
 *
 * @param dummy is ignored.  A udp connection has only one peer.
 * @return <#return#>
 */
static bool _send(IoOperations *ops, const Address *dummy, Message *message) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  _UdpState *udpConnState = (_UdpState *)ioOperations_GetClosure(ops);

  // NAT for HICN
  // in this particular connection we don't need natting beacause we send the
  // packet to the next hop using upd connection

  ssize_t writeLength =
      sendto(udpConnState->udpListenerSocket, message_FixedHeader(message),
             (int)message_Length(message), 0, udpConnState->peerAddress,
             udpConnState->peerAddressLength);

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

static bool _sendCommandResponse(IoOperations *ops, struct iovec *message){
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  _UdpState *udpConnState = (_UdpState *)ioOperations_GetClosure(ops);

#ifndef _WIN32
  // Perform connect before to establish association between this peer and
  // the remote peer. This is required to use writev.
  // Connection association can be changed at any time.
  connect(udpConnState->udpListenerSocket,
          udpConnState->peerAddress,
          udpConnState->peerAddressLength);

  ssize_t writeLength = writev(udpConnState->udpListenerSocket, message, 2);

  struct sockaddr any_address = {0};
  any_address.sa_family = AF_UNSPEC;
  connect(udpConnState->udpListenerSocket,
          &any_address, (socklen_t)sizeof(any_address));

  if (writeLength < 0) {
      return false;
  }
#else
  ssize_t writeLength = write(udpConnState->udpListenerSocket, message[0].iov_base, (unsigned int)message[0].iov_len);
  if (writeLength < 0) {
	  return false;
  }
  writeLength = write(udpConnState->udpListenerSocket, message[0].iov_base, (unsigned int)message[0].iov_len);
  if (writeLength < 0) {
	  return false;
  }
#endif
  return true;
}

static list_connections_type _getConnectionType(const IoOperations *ops) {
  return CONN_UDP;
}

static Ticks _sendProbe(IoOperations *ops, unsigned probeType,
                        uint8_t *message) {
  //TODO
  return 0;
}

// =================================================================
// Internal API

static bool _saveSockaddr(_UdpState *udpConnState, const AddressPair *pair) {
  bool success = false;
  const Address *remoteAddress = addressPair_GetRemote(pair);

  switch (addressGetType(remoteAddress)) {
    case ADDR_INET: {
      size_t bytes = sizeof(struct sockaddr_in);
      udpConnState->peerAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(udpConnState->peerAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet(remoteAddress,
                     (struct sockaddr_in *)udpConnState->peerAddress);
      udpConnState->peerAddressLength = (socklen_t)bytes;

      success = true;
      break;
    }

    case ADDR_INET6: {
      size_t bytes = sizeof(struct sockaddr_in6);
      udpConnState->peerAddress = parcMemory_Allocate(bytes);
      parcAssertNotNull(udpConnState->peerAddress,
                        "parcMemory_Allocate(%zu) returned NULL", bytes);

      addressGetInet6(remoteAddress,
                      (struct sockaddr_in6 *)udpConnState->peerAddress);
      udpConnState->peerAddressLength = (socklen_t)bytes;

      success = true;
      break;
    }

    default:
      if (logger_IsLoggable(udpConnState->logger, LoggerFacility_IO,
                            PARCLogLevel_Error)) {
        char *str = addressToString(remoteAddress);
        logger_Log(udpConnState->logger, LoggerFacility_IO, PARCLogLevel_Error,
                   __func__, "Remote address is not INET or INET6: %s", str);
        parcMemory_Deallocate((void **)&str);
      }
      break;
  }
  return success;
}

static void _setConnectionState(_UdpState *udpConnState, bool isUp) {
  parcAssertNotNull(udpConnState, "Parameter Udp must be non-null");

  Messenger *messenger = forwarder_GetMessenger(udpConnState->forwarder);

  bool oldStateIsUp = udpConnState->isUp;
  udpConnState->isUp = isUp;

  if (oldStateIsUp && !isUp) {
    // bring connection DOWN
    Missive *missive =
        missive_Create(MissiveType_ConnectionDown, udpConnState->id);
    messenger_Send(messenger, missive);
    return;
  }

  if (!oldStateIsUp && isUp) {
    // bring connection UP
    Missive *missive =
        missive_Create(MissiveType_ConnectionUp, udpConnState->id);
    messenger_Send(messenger, missive);
    return;
  }
}
