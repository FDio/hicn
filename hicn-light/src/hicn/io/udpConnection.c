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

/* This has to be included early as other modules are including socket.h */
#define _GNU_SOURCE
#include <sys/socket.h>

#include <unistd.h>
#include <fcntl.h>

#include <hicn/processor/messageProcessor.h>

#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <string.h>

#include <hicn/base/address_pair.h>
#include <hicn/core/messageHandler.h>
#include <hicn/io/udpConnection.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/message.h>

#define DEBUG(FMT, ...) do {                                                    \
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug))  \
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

#define ERROR(FMT, ...) do {                                                    \
    if (logger_IsLoggable(udp->logger, LoggerFacility_IO,  PARCLogLevel_Error)) \
      logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,  \
                 FMT, ## __VA_ARGS__);                                          \
} while(0);

typedef struct udp_state {
  Forwarder *forwarder;
  char * interfaceName;
  Logger *logger;

  // the udp listener socket we receive packets on
  int fd;

  address_pair_t pair;

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

  /* Sending socket (connected) */
  int queue_len;

  /* sendmmsg data structures */ // TODO purge
  struct mmsghdr messages[MAX_MSG];
  struct iovec iovecs[MAX_MSG];
  //char buffers[MAX_MSG][MTU_SIZE];
  //struct sockaddr_storage addrs[MAX_MSG];

} _UdpState;

// Prototypes
static bool _send(IoOperations *ops, const address_t *nexthop, msgbuf_t *message, bool queue);
static bool _sendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size);
static const address_t *_getRemoteAddress(const IoOperations *ops);
static const address_pair_t *_getAddressPair(const IoOperations *ops);
static unsigned _getConnectionId(const IoOperations *ops);
static bool _isUp(const IoOperations *ops);
static bool _isLocal(const IoOperations *ops);
static void _destroy(IoOperations **opsPtr);
static connection_type_t _getConnectionType(const IoOperations *ops);
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
static const void *_IoOperationsGuid = __FILE__;

/*
 * Return our GUID
 */
static const void *_streamConnection_Class(const IoOperations *ops) {
  return _IoOperationsGuid;
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

static void _setConnectionState(_UdpState *Udp, bool isUp);

IoOperations *udpConnection_Create(Forwarder *forwarder, const char * interfaceName, int fd,
                                   const address_pair_t *pair, bool isLocal, unsigned connid) {
  _UdpState *udp = parcMemory_AllocateAndClear(sizeof(_UdpState));
  parcAssertNotNull(udp,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_UdpState));

  udp->forwarder = forwarder;
  udp->interfaceName = strdup(interfaceName);
  udp->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  udp->fd = fd;
  udp->id = connid;
  udp->pair = *pair;
  udp->isLocal = isLocal;

  // allocate a connection
  IoOperations * io_ops = parcMemory_AllocateAndClear(sizeof(IoOperations));
  parcAssertNotNull(io_ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(IoOperations));
  memcpy(io_ops, &_template, sizeof(IoOperations));
  io_ops->closure = udp;

  _setConnectionState(udp, true);

#ifdef WITH_POLICY
  udp->priority = 0;
#endif /* WITH_POLICY */

  /* Setup sendmmsg data structures. */
  for (unsigned i = 0; i < MAX_MSG; i++) {
    struct mmsghdr *msg = &udp->messages[i];
    struct iovec *iovec = &udp->iovecs[i];
    msg->msg_hdr.msg_iov = iovec;
    msg->msg_hdr.msg_iovlen = 1;
  }

  udp->queue_len = 0;

#if 0
  if (logger_IsLoggable(udp->logger, LoggerFacility_IO,
                        PARCLogLevel_Info)) {
    char *str = pair_ToString(udp->pair);
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Info,
               __func__,
               "UdpConnection %p created for address %s (isLocal %d)",
               (void *)udp, str, udp->isLocal);
    free(str);
  }
#endif

  messenger_Send(
      forwarder_GetMessenger(forwarder),
      missive_Create(MissiveType_ConnectionCreate, udp->id));
  messenger_Send(forwarder_GetMessenger(forwarder),
                   missive_Create(MissiveType_ConnectionUp, udp->id));
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

  _UdpState *udp = (_UdpState *)ioOperations_GetClosure(ops);

  messenger_Send(
      forwarder_GetMessenger(udp->forwarder),
      missive_Create(MissiveType_ConnectionDestroyed, udp->id));

  if (logger_IsLoggable(udp->logger, LoggerFacility_IO,
                        PARCLogLevel_Info)) {
    logger_Log(udp->logger, LoggerFacility_IO, PARCLogLevel_Info,
               __func__, "UdpConnection %p destroyed", (void *)udp);
  }

  // do not close udp->fd, the listener will close
  // that when its done

  logger_Release(&udp->logger);
  free(udp->interfaceName);
  parcMemory_Deallocate((void **)&udp);
  parcMemory_Deallocate((void **)&ops);

  *opsPtr = NULL;
}

static bool _isUp(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->isUp;
}

static bool _isLocal(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->isLocal;
}

static const address_t *_getRemoteAddress(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return address_pair_remote(&udp->pair);
}

static const address_pair_t *_getAddressPair(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return &udp->pair;
}

static unsigned _getConnectionId(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->id;
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
static bool _send(IoOperations *ops, const address_t *dummy, msgbuf_t *message, bool queue) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  _UdpState *udp = (_UdpState *)ioOperations_GetClosure(ops);

  /* Flush if required or if queue is full */
  if ((!message) || (queue && (udp->queue_len > MAX_MSG)))  {
    /* Flush operation */
    //DEBUG("udp->queue_len=%d", udp->queue_len);
    //printf("Send queuelen=%d on socket %d\n", udp->queue_len, udp->fd);
#ifdef WITH_ZEROCOPY
    int n = sendmmsg(udp->fd, udp->messages, udp->queue_len, MSG_ZEROCOPY);
#else
    int n = sendmmsg(udp->fd, udp->messages, udp->queue_len, 0);
#endif /* WITH_ZEROCOPY */
    if (n == -1) {
      perror("sendmmsg()");
      udp->queue_len = 0;
      return false;
    }

    if (n < udp->queue_len) {
        // XXX TODO
        printf("Unhandled Error after sending n=%d messages\n", n);
    }

    /* XXX check msglen */
    udp->queue_len = 0;
    return true;
  }

  if (queue) {
    struct iovec *iovec = &udp->iovecs[udp->queue_len++];
    iovec->iov_base = msgbuf_packet(message);
    iovec->iov_len = msgbuf_len(message);

  } else {
    ssize_t writeLength = write(udp->fd, msgbuf_packet(message), msgbuf_len(message));

    if (writeLength < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      } else {
        // this print is for debugging
        printf("Incorrect write length %zd, expected %u: (%d) %s\n", writeLength,
               msgbuf_len(message), errno, strerror(errno));
        return false;
      }
    }

  }

  return true;
}

static bool _sendIOVBuffer(IoOperations *ops, struct iovec *message,
    size_t size) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  _UdpState *udp = (_UdpState *)ioOperations_GetClosure(ops);

#ifndef _WIN32
  // Perform connect before to establish association between this peer and
  // the remote peer. This is required to use writev.
  // Connection association can be changed at any time.

  ssize_t writeLength = writev(udp->fd, message, (int)size);
  if (writeLength < 0) {
      return false;
  }
#else
  WSABUF dataBuf[ARRAY_SIZE(message)];
  DWORD BytesSent = 0;

  for (int i = 0; i < ARRAY_SIZE(message); i++) {
    dataBuf[i].buf = message[i].iov_base;
    dataBuf[i].len = (ULONG)message[i].iov_len;
  }

  int rc = WSASendTo(udp->fd, dataBuf, ARRAY_SIZE(message),
    &BytesSent, 0, (SOCKADDR *)address_sa(address_pair_remote(&udp->pair)),
    address_socklen(address_pair_remote(&udp->pair)), NULL, NULL);

  if (rc == SOCKET_ERROR) {
    return false;
  }
#endif
  return true;
}

static connection_type_t _getConnectionType(const IoOperations *ops) {
  return CONN_UDP;
}

static void _sendProbe(IoOperations *ops, uint8_t *message) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  _UdpState *udp = (_UdpState *)ioOperations_GetClosure(ops);

  if(udp->isLocal)
    return;

  ssize_t writeLength = sendto(udp->fd, message,
          messageHandler_GetTotalPacketLength(message), 0,
          address_sa(address_pair_remote(&udp->pair)),
          address_socklen(address_pair_remote(&udp->pair)));

  if (writeLength < 0) {
     return;
  }
}

// =================================================================
// Internal API

static void _setConnectionState(_UdpState *udp, bool isUp) {
  parcAssertNotNull(udp, "Parameter Udp must be non-null");

  Messenger *messenger = forwarder_GetMessenger(udp->forwarder);

  bool oldStateIsUp = udp->isUp;
  udp->isUp = isUp;

  if (oldStateIsUp && !isUp) {
    // bring connection DOWN
    Missive *missive =
        missive_Create(MissiveType_ConnectionDown, udp->id);
    messenger_Send(messenger, missive);
    return;
  }

  if (!oldStateIsUp && isUp) {
    // bring connection UP
    Missive *missive =
        missive_Create(MissiveType_ConnectionUp, udp->id);
    messenger_Send(messenger, missive);
    return;
  }
}

static connection_state_t _getState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->state;
}

static void _setState(IoOperations *ops, connection_state_t state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _UdpState *udp =
      (_UdpState *)ioOperations_GetClosure(ops);
  udp->state = state;
}

static connection_state_t _getAdminState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->admin_state;
}

static void _setAdminState(IoOperations *ops, connection_state_t admin_state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _UdpState *udp =
      (_UdpState *)ioOperations_GetClosure(ops);
  udp->admin_state = admin_state;
}

#ifdef WITH_POLICY
static uint32_t _getPriority(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _UdpState *udp =
      (const _UdpState *)ioOperations_GetClosure(ops);
  return udp->priority;
}

static void _setPriority(IoOperations *ops, uint32_t priority) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _UdpState *udp =
      (_UdpState *)ioOperations_GetClosure(ops);
  udp->priority = priority;
}
#endif /* WITH_POLICY */

static const char * _getInterfaceName(const IoOperations *ops)
{
  parcAssertNotNull(ops, "Parameter must be non-null");
  _UdpState *udp =
      (_UdpState *)ioOperations_GetClosure(ops);
  return udp->interfaceName;
}
