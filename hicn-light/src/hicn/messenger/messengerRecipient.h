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
 * @file messengerRecipient.h
 * @brief A recipient represents the entity that will recieve a Missive from the
 * Messenger.
 *
 * A recipient is identified by the pair (contenxt, callback).  The context is
 * the recipients context, such as it's object pointer.  The callback is the
 * function the recipient uses to receive a Missive.
 *
 * If the receiver is going to do a lot of work or potentially send other
 * missives, the receiver should queue the received notifications and process
 * them in its own slice.
 *
 * A recipient will receive a reference counted copy of the missive, so it must
 * call
 * {@link missive_Release} on it.
 *
 *
 */

#ifndef messengerRecipient_h
#define messengerRecipient_h

#include <hicn/messenger/missive.h>

struct messenger_recipient;
typedef struct messenger_recipient MessengerRecipient;

/**
 * @typedef MessengerRecipientCallback
 * @abstract A recipient implements a callback to receive Missives.
 * @constant recipient The recipient to recieve the missive
 * @constant missive The missive, recipient must call {@link missive_Release} on
 * it
 */
typedef void(MessengerRecipientCallback)(MessengerRecipient *recipient,
                                         Missive *missive);

/**
 * Creates a Recipient, which represents a reciever of missives.
 *
 * Creates a Recipient that can be registerd with the Messenger using {@link
 * messenger_Register}.
 *
 * @param [in] recipientContext This pointer will be passed back to the
 * recipient with each missive, may be NULL
 * @param [in] recipientCallback The function that receives the missive, must be
 * non-NULL.
 *
 * @return non-null A recipient object
 */
MessengerRecipient *messengerRecipient_Create(
    void *recipientContext, MessengerRecipientCallback *recipientCallback);

/**
 * Destroys a recipient.  You should unregister it first.
 *
 * Destroying a recipient does not unregister it, so be sure to call
 * {@link messenger_Unregister} first.
 *
 * @param [in,out] recipientPtr Double pointer to the recipient to destroy, will
 * be NULL'd.
 */
void messengerRecipient_Destroy(MessengerRecipient **recipientPtr);

/**
 * Returns the recipient context passed on Create
 *
 * @param [in] recipient The recipient object
 *
 * @return pointer The context pointer used to create the object, maybe NULL
 */
void *messengerRecipient_GetRecipientContext(MessengerRecipient *recipient);

/**
 * Delivers a Missive to the recipient
 *
 * Passes the missive to the recipients callback.
 *
 * A recipient will receive a reference counted copy of the missive, so it must
 * call
 * {@link missive_Release} on it.
 *
 * @param [in] recipient The receiver
 * @param [in] missive The message to send
 */
void messengerRecipient_Deliver(MessengerRecipient *recipient,
                                Missive *missive);
#endif  // messengerRecipient_h
