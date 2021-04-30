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
 * The EventMessenger is the system that messages events between
 * producers and consumers.
 *
 * Events are delivered in a deferred event cycle to avoid event callbacks
 * firing when the event generator is still running.
 */

#ifndef messenger_h
#define messenger_h

#include <hicn/core/dispatcher.h>
#include <hicn/messenger/messengerRecipient.h>
#include <hicn/messenger/missive.h>

struct messenger;
typedef struct messenger Messenger;

/**
 * @function eventmessenger_Create
 * @abstract Creates an event notification system
 * @discussion
 *   Typically there's only one of these managed by forwarder.
 *
 * @param dispatcher is the event dispatcher to use to schedule events.
 */
Messenger *messenger_Create(Dispatcher *dispatcher);

/**
 * @function eventMessenger_Destroy
 * @abstract Destroys the messenger system, no notification is sent
 */
void messenger_Destroy(Messenger **messengerPtr);

/**
 * @function eventMessenger_Send
 * @abstract Send an event message, takes ownership of the event memory
 */
void messenger_Send(Messenger *messenger, Missive *missive);

/**
 * @function eventMessenger_Register
 * @abstract Receive all event messages
 */
void messenger_Register(Messenger *messenger,
                        const MessengerRecipient *recipient);

/**
 * @function eventMessenger_Unregister
 * @abstract Stop receiving event messages
 */
void messenger_Unregister(Messenger *messenger,
                          const MessengerRecipient *recipient);
#endif  // messenger_h
