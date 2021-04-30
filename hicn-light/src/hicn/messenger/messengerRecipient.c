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

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/messenger/messenger.h>
#include <hicn/messenger/messengerRecipient.h>

struct messenger_recipient {
  void *context;
  MessengerRecipientCallback *notify;
};

MessengerRecipient *messengerRecipient_Create(
    void *recipientContext, MessengerRecipientCallback *recipientCallback) {
  parcAssertNotNull(recipientCallback,
                    "Parameter recipientCallback must be non-null");

  MessengerRecipient *recipient =
      parcMemory_AllocateAndClear(sizeof(MessengerRecipient));
  parcAssertNotNull(recipient, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(MessengerRecipient));
  recipient->context = recipientContext;
  recipient->notify = recipientCallback;
  return recipient;
}

void messengerRecipient_Destroy(MessengerRecipient **recipientPtr) {
  parcAssertNotNull(recipientPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*recipientPtr,
                    "Parameter must dereference to non-null pointer");

  parcMemory_Deallocate((void **)recipientPtr);
  *recipientPtr = NULL;
}

void *messengerRecipient_GetRecipientContext(MessengerRecipient *recipient) {
  parcAssertNotNull(recipient, "Parameter must be non-null");

  return recipient->context;
}

void messengerRecipient_Deliver(MessengerRecipient *recipient,
                                Missive *missive) {
  parcAssertNotNull(recipient, "Parameter must be non-null");
  recipient->notify(recipient, missive);
}
