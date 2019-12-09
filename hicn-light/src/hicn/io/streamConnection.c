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
 * Common activity for STREAM based listeners.
 */

#include <errno.h>
#include <hicn/hicn-light/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <parc/algol/parc_Hash.h>
#include <hicn/core/connection.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/message.h>
#include <hicn/io/streamConnection.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/core/messageHandler.h>

#include <hicn/utils/commands.h>

#include <hicn/hicn.h>
// 128 KB output queue
#define OUTPUT_QUEUE_BYTES (128 * 1024)

#define DEBUG(FMT, ...) do {                                                       \
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO, PARCLogLevel_Debug))  \
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,  \
                 FMT, ## __VA_ARGS__);                                             \
} while(0);

#define INFO(FMT, ...) do {                                                        \
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,  PARCLogLevel_Info))  \
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Info, __func__,   \
                 FMT, ## __VA_ARGS__);                                             \
} while(0);

#define WARN(FMT, ...) do {                                                        \
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,  PARCLogLevel_Warning))\
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Warning, __func__,\
                 FMT, ## __VA_ARGS__);                                             \
} while(0);

#define ERROR(FMT, ...) do {                                                       \
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,  PARCLogLevel_Error)) \
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,  \
                 FMT, ## __VA_ARGS__);                                             \
} while(0);

static void _conn_readcb(PARCEventQueue *bufferEventVector, PARCEventType type,
        void *ioOpsVoid);

static void _conn_eventcb(PARCEventQueue *bufferEventVector,
        PARCEventQueueEventType events, void *ioOpsVoid);

typedef struct stream_state {
  Forwarder *forwarder;
  char * interfaceName;
  Logger *logger;

  int fd;

  address_pair_t address_pair;
  PARCEventQueue *bufferEventVector;

  bool isLocal;
  bool isUp;
  bool isClosed;
  unsigned id;

  size_t nextMessageLength;

  /* This information would better be stored in the connection data structure
   * but it is currently not reachable from within the implementation. */
  connection_state_t state;
  connection_state_t admin_state;
#ifdef WITH_POLICY
  uint32_t priority;
#endif /* WITH_POLICY */
} _StreamState;

// Prototypes
static bool _streamConnection_Send(IoOperations *ops, const address_t *nexthop,
    msgbuf_t *message, bool queue);
static bool _streamConnection_SendIOVBuffer(IoOperations *ops, struct
    iovec *msg, size_t size);
static const address_t *_streamConnection_GetRemoteAddress(
    const IoOperations *ops);
static const address_pair_t *_streamConnection_GetAddressPair(
    const IoOperations *ops);
static unsigned _streamConnection_GetConnectionId(const IoOperations *ops);
static bool _streamConnection_IsUp(const IoOperations *ops);
static bool _streamConnection_IsLocal(const IoOperations *ops);
static void _streamConnection_DestroyOperations(IoOperations **opsPtr);

static void _setConnectionState(_StreamState *stream, bool isUp);
static list_connections_type _streamConnection_GetConnectionType(
    const IoOperations *ops);
static void _sendProbe(IoOperations *ops, uint8_t *message);
static connection_state_t _streamConnection_getState(const IoOperations *ops);
static void _streamConnection_setState(IoOperations *ops, connection_state_t state);
static connection_state_t _streamConnection_getAdminState(const IoOperations *ops);
static void _streamConnection_setAdminState(IoOperations *ops, connection_state_t admin_state);
#ifdef WITH_POLICY
static uint32_t _streamConnection_getPriority(const IoOperations *ops);
static void _streamConnection_setPriority(IoOperations *ops, uint32_t priority);
#endif /* WITH_POLICY */
static const char * _streamConnection_getInterfaceName(const IoOperations *ops);

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
    .send = &_streamConnection_Send,
    .sendIOVBuffer = &_streamConnection_SendIOVBuffer,
    .getRemoteAddress = &_streamConnection_GetRemoteAddress,
    .getAddressPair = &_streamConnection_GetAddressPair,
    .getConnectionId = &_streamConnection_GetConnectionId,
    .isUp = &_streamConnection_IsUp,
    .isLocal = &_streamConnection_IsLocal,
    .destroy = &_streamConnection_DestroyOperations,
    .class = &_streamConnection_Class,
    .getConnectionType = &_streamConnection_GetConnectionType,
    .sendProbe = &_sendProbe,
    .getState = &_streamConnection_getState,
    .setState = &_streamConnection_setState,
    .getAdminState = &_streamConnection_getAdminState,
    .setAdminState = &_streamConnection_setAdminState,
#ifdef WITH_POLICY
    .getPriority = &_streamConnection_getPriority,
    .setPriority = &_streamConnection_setPriority,
#endif /* WITH_POLICY */
    .getInterfaceName = &_streamConnection_getInterfaceName,
};

IoOperations *
streamConnection_AcceptConnection(Forwarder *forwarder, int fd,
        address_pair_t *pair, bool isLocal)
{
  _StreamState *stream = parcMemory_AllocateAndClear(sizeof(_StreamState));
  parcAssertNotNull(stream, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(_StreamState));

  Dispatcher *dispatcher = forwarder_GetDispatcher(forwarder);
  PARCEventScheduler *eventBase = dispatcher_GetEventScheduler(dispatcher);
  stream->bufferEventVector = parcEventQueue_Create(
      eventBase, fd,
      PARCEventQueueOption_CloseOnFree | PARCEventQueueOption_DeferCallbacks);

  stream->forwarder = forwarder;
  stream->interfaceName = NULL;
  stream->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  stream->fd = fd;
  stream->id = forwarder_GetNextConnectionId(forwarder);
  stream->address_pair = *pair;
  stream->isClosed = false;

#ifdef WITH_POLICY
  stream->priority = 0;
#endif /* WITH_POLICY */

  // allocate a connection
  IoOperations *io_ops = parcMemory_AllocateAndClear(sizeof(IoOperations));
  parcAssertNotNull(io_ops, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(IoOperations));
  memcpy(io_ops, &_template, sizeof(IoOperations));
  io_ops->closure = stream;
  stream->isLocal = isLocal;

  parcEventQueue_SetCallbacks(stream->bufferEventVector, _conn_readcb, NULL,
                              _conn_eventcb, (void *)io_ops);
  parcEventQueue_Enable(stream->bufferEventVector, PARCEventType_Read);

  messenger_Send(forwarder_GetMessenger(stream->forwarder),
                 missive_Create(MissiveType_ConnectionCreate, stream->id));

  // As we are acceting a connection, we begin in the UP state
  _setConnectionState(stream, true);

// XXX TODO
#if 0
  if (logger_IsLoggable(stream->logger, LoggerFacility_IO,
                        PARCLogLevel_Debug)) {
    char *pair_str = address_pair_ToString(pair);
    logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
               "StreamConnection %p accept for address pair %s", (void *)stream,
               pair_str);
    free(pair_str);
  }
#endif

  return io_ops;
}

IoOperations *
streamConnection_OpenConnection(Forwarder *forwarder, address_pair_t *pair,
        bool isLocal, unsigned connid)
{
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(pair, "Parameter pair must be non-null");

  // if there's an error on the bind or connect, will return NULL
  PARCEventQueue *bufferEventVector =
      dispatcher_StreamBufferConnect(forwarder_GetDispatcher(forwarder), pair);
  if (!bufferEventVector)
    goto ERR_BUFFER;

  _StreamState *stream = parcMemory_AllocateAndClear(sizeof(_StreamState));
  if (!stream) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(_StreamState));
    goto ERR_STREAM;
  }

  stream->forwarder = forwarder;
  stream->interfaceName = NULL;
  stream->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  stream->fd = parcEventQueue_GetFileDescriptor(bufferEventVector);
  stream->bufferEventVector = bufferEventVector;
  stream->id = connid; //forwarder_GetNextConnectionId(forwarder);
  stream->address_pair = *pair;
  stream->isClosed = false;

  // allocate a connection
  IoOperations *io_ops = parcMemory_AllocateAndClear(sizeof(IoOperations));
  if (!io_ops) {
    ERROR("parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(IoOperations));
    goto ERR_IO_OPS;
  }

  memcpy(io_ops, &_template, sizeof(IoOperations));
  io_ops->closure = stream;
  stream->isLocal = isLocal;

  parcEventQueue_SetCallbacks(stream->bufferEventVector, _conn_readcb, NULL,
                              _conn_eventcb, (void *)io_ops);
  parcEventQueue_Enable(stream->bufferEventVector, PARCEventType_Read);

  // we start in DOWN state, until remote side answers
  messenger_Send(forwarder_GetMessenger(stream->forwarder),
                 missive_Create(MissiveType_ConnectionCreate, stream->id));
  _setConnectionState(stream, false);

// XXX TODO
#if 0
  if (logger_IsLoggable(stream->logger, LoggerFacility_IO, PARCLogLevel_Info)) {
    char *pair_str = address_pair_ToString(pair);
    logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Info, __func__,
               "StreamConnection %p connect for address pair %s",
               (void *)stream, pair_str);
    free(pair_str);
  }
#endif

  return io_ops;

ERR_IO_OPS:
ERR_STREAM:
  // XXX TODO
ERR_BUFFER:
  return NULL;
}

static
void
_streamConnection_DestroyOperations(IoOperations **opsPtr)
{
  parcAssertNotNull(opsPtr, "Parameter opsPtr must be non-null double pointer");
  parcAssertNotNull(*opsPtr,
                    "Parameter opsPtr must dereference to non-null pointer");

  IoOperations *ops = *opsPtr;
  parcAssertNotNull(ioOperations_GetClosure(ops),
                    "ops->context must not be null");

  _StreamState *stream = (_StreamState *)ioOperations_GetClosure(ops);

  parcEventQueue_Destroy(&stream->bufferEventVector);

  if (!stream->isClosed) {
    stream->isClosed = true;
    messenger_Send(forwarder_GetMessenger(stream->forwarder),
                   missive_Create(MissiveType_ConnectionClosed, stream->id));
  }

  messenger_Send(forwarder_GetMessenger(stream->forwarder),
                 missive_Create(MissiveType_ConnectionDestroyed, stream->id));

  INFO("StreamConnection %p destroyed", (void *)stream);

  logger_Release(&stream->logger);
  parcMemory_Deallocate((void **)&stream);
  parcMemory_Deallocate((void **)&ops);

  *opsPtr = NULL;
}

static bool _streamConnection_IsUp(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->isUp;
}

static bool _streamConnection_IsLocal(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->isLocal;
}

static const address_t *_streamConnection_GetRemoteAddress(
    const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return address_pair_remote(&stream->address_pair);
}

static const address_pair_t *_streamConnection_GetAddressPair(
    const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return &stream->address_pair;
}

static unsigned _streamConnection_GetConnectionId(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->id;
}

bool _streamConnection_SendIOVBuffer(IoOperations *ops,
    struct iovec * message, size_t size) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  _StreamState *conn = (_StreamState *)ioOperations_GetClosure(ops);

  if (!conn->isUp) {
    if (logger_IsLoggable(conn->logger, LoggerFacility_IO,
                          PARCLogLevel_Error)) {
      logger_Log(
          conn->logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
          "connid %u tried to send to down connection (isUp %d isClosed %d)",
          conn->id, conn->isUp, conn->isClosed);
    }
    return false;
  }

  PARCEventBuffer *buffer =
      parcEventBuffer_GetQueueBufferOutput(conn->bufferEventVector);
  size_t buffer_backlog = parcEventBuffer_GetLength(buffer);
  parcEventBuffer_Destroy(&buffer);

  if (buffer_backlog >= OUTPUT_QUEUE_BYTES) {
    if (logger_IsLoggable(conn->logger, LoggerFacility_IO,
                          PARCLogLevel_Warning)) {
      logger_Log(conn->logger, LoggerFacility_IO, PARCLogLevel_Warning,
                 __func__,
                 "connid %u Writing to buffer backlog %zu bytes DROP MESSAGE",
                 conn->id, buffer_backlog);
    }
    return false;
  }

  if (logger_IsLoggable(conn->logger, LoggerFacility_IO,
                        PARCLogLevel_Debug)) {
    size_t length = 0;
    for (int i = 0; i < size; i++)
      length += message[i].iov_len;

    logger_Log( conn->logger, LoggerFacility_IO, PARCLogLevel_Debug, __func__,
            "connid %u Writing %zu bytes to buffer with backlog %zu bytes",
            conn->id, length, buffer_backlog);
  }

  /* Write directly into the parcEventQueue without passing through message */
  for (int i = 0; i < size; i++) {
    if (parcEventQueue_Write(conn->bufferEventVector, message[i].iov_base,
                message[i].iov_len) != 0)
        return false;
  }

  return true;
}

/**
 * @function streamConnection_Send
 * @abstract Non-destructive send of the message.
 * @discussion
 *   Send uses message_CopyToStreamBuffer, which is a non-destructive write.
 *   The send may fail if there's no buffer space in the output queue.
 *
 * @param dummy is ignored.  A stream has only one peer.
 * @return <#return#>
 */
static bool _streamConnection_Send(IoOperations *ops, const address_t *nexthop,
    msgbuf_t *message, bool queue) {
  parcAssertNotNull(ops, "Parameter ops must be non-null");

  /* No need to flush */
  if (!message)
    return true;

  _StreamState *stream = (_StreamState *)ioOperations_GetClosure(ops);

  if (!stream->isUp) {
    ERROR("connid %u tried to send to down connection (isUp %d isClosed %d)",
        stream->id, stream->isUp, stream->isClosed);
    return false;
  }

  PARCEventBuffer *buffer =
      parcEventBuffer_GetQueueBufferOutput(stream->bufferEventVector);
  size_t buffer_backlog = parcEventBuffer_GetLength(buffer);
  parcEventBuffer_Destroy(&buffer);

  if (buffer_backlog >= OUTPUT_QUEUE_BYTES) {
    WARN("connid %u Writing to buffer backlog %zu bytes DROP MESSAGE",
                 stream->id, buffer_backlog);
    return false;
  }

  DEBUG("connid %u Writing %zu bytes to buffer with backlog %zu bytes",
        stream->id, msgbuf_len(message), buffer_backlog);

  return (parcEventQueue_Write(stream->bufferEventVector,
              msgbuf_packet(message), msgbuf_len(message)) == 0);
}

list_connections_type _streamConnection_GetConnectionType(
    const IoOperations *ops) {
  return CONN_TCP;
}

static void _sendProbe(IoOperations *ops, uint8_t *message) {
  // we don't need to implemet this here, it is a local connection
}

// =================================================================
// the actual I/O functions

int _isACommand(PARCEventBuffer *input) {
  size_t bytesAvailable = parcEventBuffer_GetLength(input);
  parcAssertTrue(bytesAvailable >= sizeof(header_control_message),
                 "Called with too short an input: %zu", bytesAvailable);

  uint8_t *msg = parcEventBuffer_Pullup(input, bytesAvailable);
  // read first byte of the header

  // first byte: must be a REQUEST_LIGHT
  if (msg[0] != REQUEST_LIGHT) {
    return LAST_COMMAND_VALUE;
  }

  // second byte: must be a command_id
  if (msg[1] < 0 || msg[1] >= LAST_COMMAND_VALUE) {
    return LAST_COMMAND_VALUE;
  }

  return msg[1];
}

PARCEventBuffer *_tryReadControlMessage(_StreamState *stream,
                                        PARCEventBuffer *input,
                                        command_id command,
                                        struct iovec **request) {
  size_t bytesAvailable = parcEventBuffer_GetLength(input);

  if (stream->nextMessageLength == 0) {
    stream->nextMessageLength =
        sizeof(header_control_message) +
        payloadLengthDaemon(command);  // consider the whole packet.
  }

  if (bytesAvailable >= stream->nextMessageLength) {
    PARCEventBuffer *message = parcEventBuffer_Create();
    int bytesRead = parcEventBuffer_ReadIntoBuffer(input, message,
                                                   stream->nextMessageLength);
    parcAssertTrue(bytesRead == stream->nextMessageLength,
                   "Partial read, expected %zu got %d",
                   stream->nextMessageLength, bytesRead);

    uint8_t *control =
        parcEventBuffer_Pullup(message, stream->nextMessageLength);
    if (!(*request = (struct iovec *)parcMemory_AllocateAndClear(
              sizeof(struct iovec) * 2))) {
      return NULL;
    }
    (*request)[0].iov_base = control;  // header
    (*request)[0].iov_len = sizeof(header_control_message);
    if (payloadLengthDaemon(command) > 0) {
      (*request)[1].iov_base =
          control + sizeof(header_control_message);  // payload
    } else {
      (*request)[1].iov_base = NULL;
    }
    (*request)[1].iov_len = payloadLengthDaemon(command);
    // now reset message length for next packet

    stream->nextMessageLength = 0;

    return message;
  }

  return NULL;
}

static bool _isAnHicnPacket(PARCEventBuffer *input) {
  size_t bytesAvailable = parcEventBuffer_GetLength(input);
  parcAssertTrue(bytesAvailable >= sizeof(header_control_message),
                 "Called with too short an input: %zu", bytesAvailable);

  uint8_t *fh = parcEventBuffer_Pullup(input, sizeof(header_control_message));
  return messageHandler_IsValidHicnPacket(fh);
}

static void _startNewMessage(_StreamState *stream, PARCEventBuffer *input,
                             size_t inputBytesAvailable) {
  parcAssertTrue(stream->nextMessageLength == 0,
                 "Invalid state, nextMessageLength not zero: %zu",
                 stream->nextMessageLength);
  parcAssertTrue(inputBytesAvailable >= sizeof(header_control_message),
                 "read_length not a whole fixed header!: %zd",
                 inputBytesAvailable);

  // this linearizes the first messageHandler_GetIPv6HeaderLength() bytes of the
  // input buffer's iovecs and returns a pointer to it.
  uint8_t *fh = parcEventBuffer_Pullup(input, sizeof(header_control_message));

  // Calculate the total message size based on the fixed header
  stream->nextMessageLength = messageHandler_GetTotalPacketLength(fh);
}

static
int
_tryReadMessage(PARCEventBuffer *input, _StreamState *stream, msgbuf_t * msgbuf)
{
  size_t bytesAvailable = parcEventBuffer_GetLength(input);
  parcAssertTrue(bytesAvailable >= sizeof(header_control_message),
                 "Called with too short an input: %zu", bytesAvailable);

  if (stream->nextMessageLength == 0)
    _startNewMessage(stream, input, bytesAvailable);

  // This is not an ELSE statement.  We can both start a new message then
  // check if there's enough bytes to read the whole thing.

  if (bytesAvailable < stream->nextMessageLength)
    return -1;

  uint8_t * packet = parcMemory_AllocateAndClear(stream->nextMessageLength);
  if (!packet)
    return -1;

  // copy the data because *data is destroyed in the connection.
  if (parcEventBuffer_Read(input, msgbuf_packet(msgbuf), stream->nextMessageLength) < 0)
    return -1;

  uint8_t packetType;
  if (messageHandler_IsInterest(msgbuf->messageHead)) {
    packetType = MessagePacketType_Interest;
  } else if (messageHandler_IsData(msgbuf->messageHead)) {
    packetType = MessagePacketType_ContentObject;
  } else {
    ERROR("Got a packet that is not a data nor an interest, drop it!");
    return -1;
  }

  Logger * logger = stream->logger;
  msgbuf_from_packet(msgbuf, packet, packetType, stream->id,
          forwarder_GetTicks(stream->forwarder), logger);

  // now reset message length for next packet
  stream->nextMessageLength = 0;
  return 0;
}

/**
 * @function conn_readcb
 * @abstract Event callback for reads
 * @discussion
 *   Will read messages off the input.  Continues reading as long as we
 *   can get a header to determine the next message length or as long as we
 *   can read a complete message.
 *
 *   This function manipulates the read low water mark.  (1) read a fixed header
 * plus complete message, then set the low water mark to FIXED_HEADER_LEN.  (2)
 * read a fixed header, but not a complete message, then set low water mark to
 * the total mesage length.  Using the low water mark like this means the buffer
 * event will only trigger on meaningful byte boundaries when we can get actual
 *   work done.
 *
 * @param <#param1#>
 * @return <#return#>
 */
static void _conn_readcb(PARCEventQueue *event, PARCEventType type,
                         void *ioOpsVoid) {
  command_id command;
  IoOperations *ops = (IoOperations *)ioOpsVoid;
  _StreamState *stream = (_StreamState *)ioOperations_GetClosure(ops);

  PARCEventBuffer *input = parcEventBuffer_GetQueueBufferInput(event);

  // drain the input buffer

  // notice that we always try to read at least 8 bytes
  // (sizeof(header_control_message)). This is enough to read the length of all
  // kind of packets
  while (parcEventBuffer_GetLength(input) >= sizeof(header_control_message) &&
         parcEventBuffer_GetLength(input) >= stream->nextMessageLength) {

    if ((command = _isACommand(input)) != LAST_COMMAND_VALUE) {
      struct iovec *rx;
      // Get message from the stream and set the stream->nextMessageLength
      PARCEventBuffer *message =
          _tryReadControlMessage(stream, input, command, &rx);
      // If received correctly the whole message, send to dispatcher
      if (message) {
        forwarder_ReceiveCommand(stream->forwarder, command, rx, stream->id);
        parcMemory_Deallocate((void **)&rx);
        parcEventBuffer_Destroy(&message);
      }

    } else if (_isAnHicnPacket(input)) {
      // this is an Hicn packet (here we should distinguish between IPv4 and
      // IPv6 tryReadMessage may set nextMessageLength
      msgbuf_t msgbuf;
      if (_tryReadMessage(input, stream, &msgbuf) < 0)
          continue;
      forwarder_Receive(stream->forwarder, &msgbuf, 1);

    } else {
      parcAssertTrue(false,
                     "(Local stream connection) malformed packet received");
    }
  }

  if (stream->nextMessageLength == 0) {
    // we don't have the next header, so set it to the header length
    streamBuffer_SetWatermark(event, true, false,
                              sizeof(header_control_message), 0);
  } else {
    // set it to the packet length
    streamBuffer_SetWatermark(event, true, false, stream->nextMessageLength, 0);
  }
  parcEventBuffer_Destroy(&input);
}

static void _setConnectionState(_StreamState *stream, bool isUp) {
  parcAssertNotNull(stream, "Parameter stream must be non-null");

  Messenger *messenger = forwarder_GetMessenger(stream->forwarder);

  bool oldStateIsUp = stream->isUp;
  stream->isUp = isUp;

  if (oldStateIsUp && !isUp) {
    // bring connection DOWN
    Missive *missive = missive_Create(MissiveType_ConnectionDown, stream->id);
    messenger_Send(messenger, missive);
    return;
  }

  if (!oldStateIsUp && isUp) {
    // bring connection UP
    Missive *missive = missive_Create(MissiveType_ConnectionUp, stream->id);
    messenger_Send(messenger, missive);
    return;
  }
}

static void _conn_eventcb(PARCEventQueue *event, PARCEventQueueEventType events,
                          void *ioOpsVoid) {
  IoOperations *ops = (IoOperations *)ioOpsVoid;
  _StreamState *stream = (_StreamState *)ioOperations_GetClosure(ops);

  if (events & PARCEventQueueEventType_Connected) {
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,
                          PARCLogLevel_Info)) {
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Info, __func__,
                 "Connection %u is connected", stream->id);
    }

    // if the stream was closed, do not transition to an UP state
    if (!stream->isClosed) {
      _setConnectionState(stream, true);
    }
  } else if (events & PARCEventQueueEventType_EOF) {
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,
                          PARCLogLevel_Info)) {
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Info, __func__,
                 "connid %u closed.", stream->id);
    }

    parcEventQueue_Disable(stream->bufferEventVector, PARCEventType_Read);

    _setConnectionState(stream, false);

    if (!stream->isClosed) {
      stream->isClosed = true;
      // this will cause the connection manager to destroy the connection later
      messenger_Send(forwarder_GetMessenger(stream->forwarder),
                     missive_Create(MissiveType_ConnectionClosed, stream->id));
    }
  } else if (events & PARCEventQueueEventType_Error) {
    if (logger_IsLoggable(stream->logger, LoggerFacility_IO,
                          PARCLogLevel_Error)) {
      logger_Log(stream->logger, LoggerFacility_IO, PARCLogLevel_Error,
                 __func__, "Got an error on the connection %u: %s", stream->id,
                 strerror(errno));
    }

    parcEventQueue_Disable(stream->bufferEventVector,
                           PARCEventType_Read | PARCEventType_Write);

    _setConnectionState(stream, false);

    if (!stream->isClosed) {
      stream->isClosed = true;
      // this will cause the connection manager to destroy the connection later
      messenger_Send(forwarder_GetMessenger(stream->forwarder),
                     missive_Create(MissiveType_ConnectionClosed, stream->id));
    }
  }
  /* None of the other events can happen here, since we haven't enabled
   * timeouts */
}

static connection_state_t _streamConnection_getState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->state;
}

static void _streamConnection_setState(IoOperations *ops, connection_state_t state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _StreamState *stream =
      (_StreamState *)ioOperations_GetClosure(ops);
  stream->state = state;
}

static connection_state_t _streamConnection_getAdminState(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->admin_state;
}

static void _streamConnection_setAdminState(IoOperations *ops, connection_state_t admin_state) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _StreamState *stream =
      (_StreamState *)ioOperations_GetClosure(ops);
  stream->admin_state = admin_state;
}

#ifdef WITH_POLICY
static uint32_t _streamConnection_getPriority(const IoOperations *ops) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  const _StreamState *stream =
      (const _StreamState *)ioOperations_GetClosure(ops);
  return stream->priority;
}

static void _streamConnection_setPriority(IoOperations *ops, uint32_t priority) {
  parcAssertNotNull(ops, "Parameter must be non-null");
  _StreamState *stream =
      (_StreamState *)ioOperations_GetClosure(ops);
  stream->priority = priority;
}
#endif /* WITH_POLICY */

static const char * _streamConnection_getInterfaceName(const IoOperations *ops)
{
  parcAssertNotNull(ops, "Parameter must be non-null");
  _StreamState *stream =
      (_StreamState *)ioOperations_GetClosure(ops);
  return stream->interfaceName;
}
