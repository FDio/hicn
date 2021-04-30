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
 * The Connection Manager sets itself up as a listener to the Messenger so it
 * can take action based on system events.
 *
 * The Connection Manager queues and then processes in a later time slice the
 * messages.
 *
 */

#include <hicn/hicn-light/config.h>
#include <hicn/core/connectionManager.h>
#include <hicn/core/forwarder.h>
#include <hicn/messenger/messenger.h>
#include <hicn/messenger/messengerRecipient.h>
#include <hicn/messenger/missiveDeque.h>
#include <stdio.h>

#include <parc/algol/parc_Memory.h>

#include <parc/assert/parc_Assert.h>

struct connection_manager {
  Forwarder *forwarder;
  Logger *logger;

  MessengerRecipient *messengerRecipient;

  // we queue missives as they come in to process in our own
  // event timeslice
  MissiveDeque *missiveQueue;

  // for deferred queue processing
  PARCEventTimer *timerEvent;
};

/**
 * Receives missives from the messenger, queues them, and schedules our
 * execution
 *
 * We defer processing of missives to a later time slice
 */
static void connectionManager_MessengerCallback(MessengerRecipient *recipient,
                                                Missive *missive);

/**
 * Event callback
 *
 * This is our main run loop to process our queue of messages.  It is scheduled
 * in {@link connectionManager_MessengerCallback} when the queue becomes
 * non-empty.
 *
 * When we are called here, we have exclusive use of the system, so we will not
 * create any message loops
 *
 * @param [in] fd unused, required for compliance with function prototype
 * @param [in] which_event unused, required for compliance with function
 * prototype
 * @param [in] connManagerVoidPtr A void* to ConnectionManager
 *
 */
static void connectionManager_ProcessQueue(int fd, PARCEventType which_event,
                                           void *connManagerVoidPtr);

static void connectionManager_ProcessClosedMissive(
    ConnectionManager *connManager, const Missive *missive);

// ========================================================
// Public API

ConnectionManager *connectionManager_Create(Forwarder *forwarder) {
  ConnectionManager *connManager =
      parcMemory_AllocateAndClear(sizeof(ConnectionManager));
  parcAssertNotNull(connManager,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(ConnectionManager));
  connManager->forwarder = forwarder;
  connManager->missiveQueue = missiveDeque_Create();
  connManager->logger = logger_Acquire(forwarder_GetLogger(forwarder));

  Messenger *messenger = forwarder_GetMessenger(connManager->forwarder);

  // creates the timer, but does not start it
  PARCEventScheduler *base =
      dispatcher_GetEventScheduler(forwarder_GetDispatcher(forwarder));
  connManager->timerEvent = parcEventTimer_Create(
      base, 0, connectionManager_ProcessQueue, connManager);

  connManager->messengerRecipient = messengerRecipient_Create(
      connManager, connectionManager_MessengerCallback);
  messenger_Register(messenger, connManager->messengerRecipient);
  return connManager;
}

void connectionManager_Destroy(ConnectionManager **managerPtr) {
  parcAssertNotNull(managerPtr, "Double pointer must be non-null");
  parcAssertNotNull(*managerPtr, "Double pointer must dereference to non-null");

  ConnectionManager *connManager = *managerPtr;

  Messenger *messenger = forwarder_GetMessenger(connManager->forwarder);
  parcEventTimer_Destroy(&(connManager->timerEvent));
  messenger_Unregister(messenger, connManager->messengerRecipient);
  messengerRecipient_Destroy(&connManager->messengerRecipient);
  missiveDeque_Release(&connManager->missiveQueue);
  logger_Release(&connManager->logger);

  parcMemory_Deallocate((void **)&connManager);
  *managerPtr = NULL;
}

// ========================================================
// Internal Functions

static void connectionManager_MessengerCallback(MessengerRecipient *recipient,
                                                Missive *missive) {
  ConnectionManager *connManager =
      messengerRecipient_GetRecipientContext(recipient);

  // we do not release our reference count, we store it until later
  // We are called with our own reference, so we do not need to acquire the
  // missive here.
  missiveDeque_Append(connManager->missiveQueue, missive);

  if (missiveDeque_Size(connManager->missiveQueue) == 1) {
    // When it becomes non-empty, schedule {@link
    // connectionManager_ProcessQueue}
    struct timeval immediateTimeout = {0, 0};
    parcEventTimer_Start(connManager->timerEvent, &immediateTimeout);
  }
}

static void connectionManager_ProcessQueue(int fd, PARCEventType which_event,
                                           void *connManagerVoidPtr) {
  ConnectionManager *connManager = (ConnectionManager *)connManagerVoidPtr;

  Missive *missive;
  while ((missive = missiveDeque_RemoveFirst(connManager->missiveQueue)) !=
         NULL) {
    switch (missive_GetType(missive)) {
      case MissiveType_ConnectionCreate:
        // hook to signal that a new connection was created
        break;
      case MissiveType_ConnectionUp:
        // hook to signal that a new connection is up
        break;
      case MissiveType_ConnectionDown:
        // hook to signal that a connection is down
        break;
      case MissiveType_ConnectionClosed:
        connectionManager_ProcessClosedMissive(connManager, missive);
        break;
      case MissiveType_ConnectionDestroyed:
        // hook to signal that a connection was destroyed
        break;
      default:
        parcTrapUnexpectedState("Missive %p of unknown type: %d",
                                (void *)missive, missive_GetType(missive));
    }
    missive_Release(&missive);
  }
}

static void connectionManager_ProcessClosedMissive(
    ConnectionManager *connManager, const Missive *missive) {
  logger_Log(connManager->logger, LoggerFacility_Core, PARCLogLevel_Debug,
             __func__, "Processing CLOSED message for connid %u",
             missive_GetConnectionId(missive));

  ConnectionTable *table = forwarder_GetConnectionTable(connManager->forwarder);
  const Connection *conn =
      connectionTable_FindById(table, missive_GetConnectionId(missive));

  if (conn) {
    // this will destroy the connection if its the last reference count
    connectionTable_Remove(table, conn);

    // remove from FIB
    forwarder_RemoveConnectionIdFromRoutes(connManager->forwarder,
                                           missive_GetConnectionId(missive));
  }
}
