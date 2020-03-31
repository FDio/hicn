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
 * @file message.h
 * @brief Message is the unit of forwarding, i.e. the packets being switched
 *
 */
#ifndef message_h
#define message_h

#include <hicn/hicn-light/config.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/core/streamBuffer.h>

#include <hicn/core/name.h>

#include <parc/algol/parc_EventBuffer.h>
#include <parc/algol/parc_EventQueue.h>

#include <hicn/core/ticks.h>

struct message;
typedef struct message Message;

/**
 * @function message_CreateFromBuffer
 * @abstract Takes ownership of the input buffer, which comprises one complete
 * message
 */

Message *message_CreateFromEventBuffer(PARCEventBuffer *data, size_t dataLength,
                                       unsigned ingressConnectionId,
                                       Ticks receiveTime);

/**
 * @function message_CreateFromByteArray
 * @abstract create a message from a byte array
 */

Message *message_CreateFromByteArray(unsigned connid, uint8_t *pckt,
                                     MessagePacketType type, Ticks receiveTime);

/**
 * @function message_Copy
 * @abstract Get a reference counted copy
 */

Message *message_Acquire(const Message *message);

/**
 * Releases the message and frees the memory
 */
void message_Release(Message **messagePtr);

/**
 * Writes the message to the queue
 */

bool message_Write(PARCEventQueue *parcEventQueue, const Message *message);

/**
 * Returns the total byte length of the message
 */
size_t message_Length(const Message *message);

bool message_HasWldr(const Message *message);

bool message_IsWldrNotification(const Message *message);

void message_ResetWldrLabel(Message *message);

unsigned message_GetWldrLabel(const Message *message);

unsigned message_GetWldrExpectedLabel(const Message *message);

unsigned message_GetWldrLastReceived(const Message *message);

void message_SetWldrLabel(Message *message, uint16_t label);

Message *message_CreateWldrNotification(Message *original, uint16_t expected,
                                        uint16_t lastReceived);
/**
 * Returns the connection id of the packet input
 */
unsigned message_GetIngressConnectionId(const Message *message);

void message_SetIngressConnectionId(Message *message, unsigned conn);

/**
 * Returns the receive time (in router ticks) of the message
 */
Ticks message_GetReceiveTime(const Message *message);

/**
 * Returns the PacketType
 */
MessagePacketType message_GetType(const Message *message);

uint32_t message_GetPathLabel(const Message *message);
void message_SetPathLabel(Message *message, uint32_t label);
void message_UpdatePathLabel(Message *message, uint8_t outFace);
void message_ResetPathLabel(Message *message);

// ===========================================================
// Accessors used to index and compare messages

/**
 * @function message_GetName
 * @abstract The name in the message
 * @discussion
 *   The name of the Interest or Content Object.  If the caller will store the
 *   name, he should make a reference counted copy.
 * @return The name as stored in the message object.
 */

Name *message_GetName(const Message *message);

/**
 * Determines if the message has an Interest Lifetime parameter
 *
 * @param [in] message An allocated and parsed Message
 *
 * @retval true If an Intrerest Lifetime field exists
 * @retval false If no Interest Lifetime exists
 */

bool message_HasInterestLifetime(const Message *message);

/**
 * Returns the Interest lifetime in hicn-light Ticks
 *
 * the interest expires after now + returned ticks
 *
 * @param [in] message An allocated and parsed Message
 *
 * @retval integer Lifetime in forwarder Ticks
 *
 */

uint64_t message_GetInterestLifetimeTicks(const Message *message);

/**
 * checks if the expiry time is set inside the content object
 */
bool message_HasContentExpiryTime(const Message *message);

/**
 * returns the moment (in hicn-light ticks) when the content object will expire
 */
uint64_t message_GetContentExpiryTimeTicks(const Message *message);

/**
 * Returns a pointer to the beginning of the FixedHeader
 *
 * @param [in] message An allocated and parsed Message
 *
 * @return non-null The fixed header memory
 * @return null No fixed header or an error
 */

const uint8_t *message_FixedHeader(const Message *message);

#endif  // message_h
