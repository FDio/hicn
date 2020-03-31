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
  messageHandler_SetPathLabel(message->messageHead, label);
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
