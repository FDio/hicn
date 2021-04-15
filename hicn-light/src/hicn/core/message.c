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
#include <stdio.h>
#include <string.h>

#include <hicn/core/forwarder.h>
#include <hicn/core/message.h>
#include <hicn/core/wldr.h>

#include <hicn/core/messageHandler.h>

#include <parc/algol/parc_Hash.h>
#include <parc/algol/parc_Memory.h>
#include <hicn/core/messagePacketType.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_EventBuffer.h>

struct message {
  Logger *logger;

  Ticks receiveTime;
  unsigned ingressConnectionId;

  Name *name;

  uint8_t *messageHead;

  unsigned length;

  uint8_t packetType;

  unsigned refcount;
};

Message *message_Acquire(const Message *message) {
  Message *copy = (Message *)message;
  copy->refcount++;
  return copy;
}

Message *message_CreateFromEventBuffer(PARCEventBuffer *data, size_t dataLength,
                                       unsigned ingressConnectionId,
                                       Ticks receiveTime, Logger *logger) {
  // used by applications, we can get only interest or data packets
  Message *message = parcMemory_AllocateAndClear(sizeof(Message));
  parcAssertNotNull(message, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Message));

  message->logger = logger_Acquire(logger);
  message->receiveTime = receiveTime;
  message->ingressConnectionId = ingressConnectionId;
  message->length = (unsigned int)dataLength;

  message->messageHead = parcMemory_AllocateAndClear(dataLength);
  parcAssertNotNull(message->messageHead,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    dataLength);

  // copy the data because *data is destroyed in the connection.
  int res = parcEventBuffer_Read(data, message->messageHead, dataLength);
  if (res == -1) {
    return NULL;
  }

  if (messageHandler_IsInterest(message->messageHead)) {
    message->packetType = MessagePacketType_Interest;
  } else if (messageHandler_IsData(message->messageHead)) {
    message->packetType = MessagePacketType_ContentObject;
  } else {
    printf("Got a packet that is not a data nor an interest, drop it!\n");
    return NULL;
  }
  message->name =
      name_CreateFromPacket(message->messageHead, message->packetType);

  message->refcount = 1;

  return message;
}

Message *message_CreateFromByteArray(unsigned connid, uint8_t *pckt,
                                     MessagePacketType type, Ticks receiveTime,
                                     Logger *logger) {
  Message *message = parcMemory_AllocateAndClear(sizeof(Message));
  parcAssertNotNull(message, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Message));

  message->logger = logger_Acquire(logger);
  message->receiveTime = receiveTime;
  message->ingressConnectionId = connid;
  message->messageHead = pckt;
  message->length = messageHandler_GetTotalPacketLength(pckt);
  message->packetType = type;

  if (messageHandler_IsWldrNotification(pckt)) {
    message->name = NULL;
  } else {
    message->name =
        name_CreateFromPacket(message->messageHead, message->packetType);
  }

  message->refcount = 1;

  return message;
}

void message_Release(Message **messagePtr) {
  parcAssertNotNull(messagePtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*messagePtr,
                    "Parameter must dereference to non-null pointer");

  Message *message = *messagePtr;
  parcAssertTrue(
      message->refcount > 0,
      "Invalid state: message_Release called on message with 0 references %p",
      (void *)message);

  message->refcount--;
  if (message->refcount == 0) {
    if (logger_IsLoggable(message->logger, LoggerFacility_Message,
                          PARCLogLevel_Debug)) {
      logger_Log(message->logger, LoggerFacility_Message, PARCLogLevel_Debug,
                 __func__, "Message %p destroyed", (void *)message);
    }

    logger_Release(&message->logger);
    if (message->name != NULL) name_Release(&message->name);
    parcMemory_Deallocate((void **)&message->messageHead);
    parcMemory_Deallocate((void **)&message);
  }
  *messagePtr = NULL;
}

bool message_Write(PARCEventQueue *parcEventQueue, const Message *message) {
  parcAssertNotNull(message, "Message parameter must be non-null");
  parcAssertNotNull(parcEventQueue, "Buffer parameter must be non-null");

  return parcEventQueue_Write(parcEventQueue, message->messageHead,
                              message_Length(message));
}

size_t message_Length(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return message->length;
}

bool message_HasWldr(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_HasWldr(message->messageHead);
}

bool message_IsWldrNotification(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_IsWldrNotification(message->messageHead);
}

void message_ResetWldrLabel(Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  messageHandler_ResetWldrLabel(message->messageHead);
}

unsigned message_GetWldrLabel(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_GetWldrLabel(message->messageHead);
}

unsigned message_GetWldrExpectedLabel(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_GetExpectedWldrLabel(message->messageHead);
}

unsigned message_GetWldrLastReceived(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_GetWldrLastReceived(message->messageHead);
}

void message_SetWldrLabel(Message *message, uint16_t label) {
  parcAssertNotNull(message, "Parameter must be non-null");
  messageHandler_SetWldrLabel(message->messageHead, label);
}

Message *message_CreateWldrNotification(Message *original, uint16_t expected,
                                        uint16_t lastReceived) {
  parcAssertNotNull(original, "Parameter original must be non-null");
  Message *message = parcMemory_AllocateAndClear(sizeof(Message));
  parcAssertNotNull(message, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Message));
  message->receiveTime = original->receiveTime;
  message->ingressConnectionId = original->ingressConnectionId;
  message->refcount = 1;
  message->logger = logger_Acquire(original->logger);

  message->length = (unsigned int)messageHandler_GetICMPPacketSize(
      messageHandler_GetIPPacketType(original->messageHead));
  message->messageHead = parcMemory_AllocateAndClear(message->length);
  parcAssertNotNull(message->messageHead,
                    "parcMemory_AllocateAndClear returned NULL");

  message->packetType = MessagePacketType_WldrNotification;
  message->name = NULL;  // nobody will use the name in a notification packet,
                         // so we can simply set it to NULL

  // set notification stuff.
  messageHandler_SetWldrNotification(
      message->messageHead, original->messageHead, expected, lastReceived);
  return message;
}

unsigned message_GetIngressConnectionId(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return message->ingressConnectionId;
}

void message_SetIngressConnectionId(Message *message, unsigned conn) {
  parcAssertNotNull(message, "Parameter must be non-null");
  message->ingressConnectionId = conn;
}

Ticks message_GetReceiveTime(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return message->receiveTime;
}

uint32_t message_GetPathLabel(const Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  return messageHandler_GetPathLabel(message->messageHead);
}

void message_SetPathLabel(Message *message, uint32_t label) {
  parcAssertNotNull(message, "Parameter must be non-null");
  messageHandler_SetPathLabel(message->messageHead,
        messageHandler_GetPathLabel(message->messageHead), label);
}

void message_UpdatePathLabel(Message *message, uint8_t outFace) {
  parcAssertNotNull(message, "Parameter must be non-null");
  messageHandler_UpdatePathLabel(message->messageHead, outFace);
}

void message_ResetPathLabel(Message *message) {
  parcAssertNotNull(message, "Parameter must be non-null");
  messageHandler_ResetPathLabel(message->messageHead);
}

MessagePacketType message_GetType(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  return message->packetType;
}

Name *message_GetName(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  return message->name;
}

bool message_HasInterestLifetime(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  return messageHandler_HasInterestLifetime(message->messageHead);
}

uint64_t message_GetInterestLifetimeTicks(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  uint64_t lifetime = messageHandler_GetInterestLifetime(message->messageHead);
  return forwarder_NanosToTicks(lifetime * 1000000ULL);
}

bool message_HasContentExpiryTime(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  return messageHandler_HasContentExpiryTime(message->messageHead);
}

uint64_t message_GetContentExpiryTimeTicks(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  uint64_t expire = messageHandler_GetContentExpiryTime(message->messageHead);
  if(expire == 0)
    return message->receiveTime;
  return message->receiveTime + forwarder_NanosToTicks(expire * 1000000ULL);
}

const uint8_t *message_FixedHeader(const Message *message) {
  parcAssertNotNull(message, "Parameter message must be non-null");
  return message->messageHead;
}
