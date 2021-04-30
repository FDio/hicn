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
 *
 * The messenger is contructued with a reference to the forwarder's dispatcher
 * so it can schedule future events.  When someone calls messenger_Send(...), it
 * will put the message on a queue.  If the queue was empty, it will scheudle
 * itself to be run. By running the queue in a future dispatcher slice, it
 * guarantees that there will be no re-entrant behavior between callers and
 * message listeners.
 *
 * A recipient will receive a reference counted copy of the missive, so it must
 * call
 * {@link missive_Release} on it.
 *
 */

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Event.h>
#include <parc/algol/parc_EventScheduler.h>
#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/messenger/messenger.h>
#include <hicn/messenger/missiveDeque.h>

struct messenger {
  PARCArrayList *callbacklist;
  Dispatcher *dispatcher;
  MissiveDeque *eventQueue;

  PARCEventTimer *timerEvent;
};

static void messenger_Dequeue(int fd, PARCEventType which_event,
                              void *messengerVoidPtr);

// =========================================
// Public API

Messenger *messenger_Create(Dispatcher *dispatcher) {
  Messenger *messenger = parcMemory_AllocateAndClear(sizeof(Messenger));
  parcAssertNotNull(messenger, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Messenger));

  // NULL destroyer because we're storing structures owned by the caller
  messenger->dispatcher = dispatcher;
  messenger->callbacklist = parcArrayList_Create(NULL);
  messenger->eventQueue = missiveDeque_Create();

  // creates the timer, but does not start it
  messenger->timerEvent =
      dispatcher_CreateTimer(dispatcher, false, messenger_Dequeue, messenger);

  return messenger;
}

void messenger_Destroy(Messenger **messengerPtr) {
  parcAssertNotNull(messengerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*messengerPtr,
                    "Parameter must dereference to non-null pointer");

  Messenger *messenger = *messengerPtr;
  parcArrayList_Destroy(&messenger->callbacklist);
  missiveDeque_Release(&messenger->eventQueue);
  dispatcher_DestroyTimerEvent(messenger->dispatcher, &messenger->timerEvent);
  parcMemory_Deallocate((void **)&messenger);
  *messengerPtr = NULL;
}

void messenger_Send(Messenger *messenger, Missive *missive) {
  parcAssertNotNull(messenger, "Parameter messenger must be non-null");
  parcAssertNotNull(missive, "Parameter event must be non-null");

  missiveDeque_Append(messenger->eventQueue, missive);
  if (missiveDeque_Size(messenger->eventQueue) == 1) {
    // We need to scheudle ourself when an event is added to an empty queue

    // precondition: timer should not be running.
    struct timeval immediateTimeout = {0, 0};
    dispatcher_StartTimer(messenger->dispatcher, messenger->timerEvent,
                          &immediateTimeout);
  }
}

static void removeRecipient(Messenger *messenger,
                            const MessengerRecipient *recipient) {
  // don't increment i in the loop
  for (size_t i = 0; i < parcArrayList_Size(messenger->callbacklist);) {
    const void *p = parcArrayList_Get(messenger->callbacklist, i);
    if (p == recipient) {
      // removing will compact the list, so next element will also be at i.
      parcArrayList_RemoveAndDestroyAtIndex(messenger->callbacklist, i);
    } else {
      i++;
    }
  }
}

/**
 * @function eventMessenger_Register
 * @abstract Receive all event messages
 */
void messenger_Register(Messenger *messenger,
                        const MessengerRecipient *recipient) {
  parcAssertNotNull(messenger, "Parameter messenger must be non-null");
  parcAssertNotNull(recipient, "Parameter recipient must be non-null");

  // do not allow duplicates
  removeRecipient(messenger, recipient);

  parcArrayList_Add(messenger->callbacklist, recipient);
}

/**
 * @function eventMessenger_Unregister
 * @abstract Stop receiving event messages
 */
void messenger_Unregister(Messenger *messenger,
                          const MessengerRecipient *recipient) {
  parcAssertNotNull(messenger, "Parameter messenger must be non-null");
  parcAssertNotNull(recipient, "Parameter recipient must be non-null");

  removeRecipient(messenger, recipient);
}

/**
 * Called by event scheduler to give us a slice in which to dequeue events
 *
 * Called inside an event callback, so we now have exclusive access to the
 * system. Dequeues all pending events and calls all the listeners for each one.
 *
 * @param [in] fd unused, required for compliance with function prototype
 * @param [in] which_event unused, required for compliance with function
 * prototype
 * @param [in] messengerVoidPtr A void* to Messenger
 */
static void messenger_Dequeue(int fd, PARCEventType which_event,
                              void *messengerVoidPtr) {
  Messenger *messenger = (Messenger *)messengerVoidPtr;
  parcAssertNotNull(messenger, "Called with null messenger pointer");

  Missive *missive;
  while ((missive = missiveDeque_RemoveFirst(messenger->eventQueue)) != NULL) {
    for (size_t i = 0; i < parcArrayList_Size(messenger->callbacklist); i++) {
      MessengerRecipient *recipient =
          parcArrayList_Get(messenger->callbacklist, i);
      parcAssertTrue(recipient, "Recipient is null at index %zu", i);

      messengerRecipient_Deliver(recipient, missive_Acquire(missive));
    }

    // now let go of our reference to the missive
    missive_Release(&missive);
  }
}
