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
 * @header dispatcher.c
 * @abstract Event dispatcher for hicn-light.  Uses parcEvent
 * @discussion
 *     Wraps the functions we use in parcEvent, along with StreamBuffer and
 * Message. The dispatcher is the event loop, so it manages things like signals,
 * timers, and network events.
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <hicn/hicn-light/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <parc/algol/parc_EventQueue.h>
#include <parc/algol/parc_EventTimer.h>

#include <parc/assert/parc_Assert.h>

#include <hicn/core/dispatcher.h>

#include <pthread.h>

#include <hicn/base/address_pair.h>

#ifndef INPORT_ANY
#define INPORT_ANY 0
#endif

struct dispatcher {
  PARCEventScheduler *Base;
  Logger *logger;
};

// ==========================================
// Public API

PARCEventScheduler *dispatcher_GetEventScheduler(Dispatcher *dispatcher) {
  return dispatcher->Base;
}

Dispatcher *dispatcher_Create(Logger *logger) {
  Dispatcher *dispatcher = parcMemory_AllocateAndClear(sizeof(Dispatcher));
  parcAssertNotNull(dispatcher,
                    "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Dispatcher));

  dispatcher->Base = parcEventScheduler_Create();
  dispatcher->logger = logger_Acquire(logger);

  parcAssertNotNull(dispatcher->Base,
                    "Got NULL from parcEventScheduler_Create()");

  return dispatcher;
}

void dispatcher_Destroy(Dispatcher **dispatcherPtr) {
  parcAssertNotNull(dispatcherPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*dispatcherPtr,
                    "Parameter must dereference to non-null pointer");
  Dispatcher *dispatcher = *dispatcherPtr;

  logger_Release(&dispatcher->logger);
  parcEventScheduler_Destroy(&(dispatcher->Base));
  parcMemory_Deallocate((void **)&dispatcher);
  *dispatcherPtr = NULL;
}

void dispatcher_Stop(Dispatcher *dispatcher) {
  struct timeval delay = {0, 1000};

  parcEventScheduler_Stop(dispatcher->Base, &delay);
}

void dispatcher_Run(Dispatcher *dispatcher) {
  parcAssertNotNull(dispatcher, "Parameter must be non-null");

  parcEventScheduler_Start(dispatcher->Base, 0);
}

void dispatcher_RunDuration(Dispatcher *dispatcher, struct timeval *duration) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(duration, "Parameter duration must be non-null");

  parcEventScheduler_Stop(dispatcher->Base, duration);
  parcEventScheduler_Start(dispatcher->Base, 0);
}

void dispatcher_RunCount(Dispatcher *dispatcher, unsigned count) {
  parcAssertNotNull(dispatcher, "Parameter must be non-null");

  for (unsigned i = 0; i < count; i++) {
    parcEventScheduler_Start(dispatcher->Base,
                             PARCEventSchedulerDispatchType_LoopOnce);
  }
}

PARCEventSocket *
dispatcher_CreateListener(Dispatcher *dispatcher,
        PARCEventSocket_Callback *callback, void *user_data, int backlog,
        const address_t * address, int socklen)
{
  PARCEventSocket *listener = parcEventSocket_Create(
      dispatcher->Base, callback, NULL, user_data, (struct sockaddr *)address, socklen);
  if (listener == NULL) {
    perror("Problem creating listener");
  }
  return listener;
}

void dispatcher_DestroyListener(Dispatcher *dispatcher,
                                PARCEventSocket **listenerPtr) {
  parcAssertNotNull(listenerPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*listenerPtr,
                    "Parameter must dereference to non-null pointer");
  parcEventSocket_Destroy(listenerPtr);
}

PARCEventQueue *dispatcher_CreateStreamBufferFromSocket(Dispatcher *dispatcher,
                                                        SocketType fd) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  PARCEventQueue *buffer = parcEventQueue_Create(
      dispatcher->Base, fd,
      PARCEventQueueOption_CloseOnFree | PARCEventQueueOption_DeferCallbacks);
  parcAssertNotNull(buffer,
                    "Got null from parcEventBufver_Create for socket %d", fd);
  return buffer;
}

PARCEventTimer *dispatcher_CreateTimer(Dispatcher *dispatcher, bool isPeriodic,
                                       PARCEvent_Callback *callback,
                                       void *userData) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(callback, "Parameter callback must be non-null");

  PARCEventType flags = 0;
  if (isPeriodic) {
    flags |= PARCEventType_Persist;
  }
  PARCEventTimer *event =
      parcEventTimer_Create(dispatcher->Base, flags, callback, userData);
  return event;
}

void dispatcher_StartTimer(Dispatcher *dispatcher, PARCEventTimer *timerEvent,
                           struct timeval *delay) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(timerEvent, "Parameter timerEvent must be non-null");
  int failure = parcEventTimer_Start(timerEvent, delay);
  parcAssertFalse(failure < 0, "Error starting timer event %p: (%d) %s",
                  (void *)timerEvent, errno, strerror(errno));
}

void dispatcher_StopTimer(Dispatcher *dispatcher, PARCEventTimer *event) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(event, "Parameter event must be non-null");

  int failure = parcEventTimer_Stop(event);
  parcAssertFalse(failure < 0, "Error stopping signal event %p: (%d) %s",
                  (void *)event, errno, strerror(errno));
}

void dispatcher_DestroyTimerEvent(Dispatcher *dispatcher,
                                  PARCEventTimer **eventPtr) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(eventPtr,
                    "Parameter eventPtr must be non-null double pointer");
  parcAssertNotNull(*eventPtr,
                    "Paramter eventPtr must dereference to non-null pointer");

  parcEventTimer_Destroy(eventPtr);
  eventPtr = NULL;
}

PARCEvent *dispatcher_CreateNetworkEvent(Dispatcher *dispatcher,
                                         bool isPersistent,
                                         PARCEvent_Callback *callback,
                                         void *userData, int fd) {
  short flags = PARCEventType_Timeout | PARCEventType_Read;
  if (isPersistent) {
    flags |= PARCEventType_Persist;
  }

  PARCEvent *event =
      parcEvent_Create(dispatcher->Base, fd, flags, callback, userData);
  parcAssertNotNull(event, "Got null from parcEvent_Create for socket %d", fd);
  return event;
}

void dispatcher_DestroyNetworkEvent(Dispatcher *dispatcher,
                                    PARCEvent **eventPtr) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(eventPtr,
                    "Parameter eventPtr must be non-null double pointer");
  parcAssertNotNull(*eventPtr,
                    "Paramter eventPtr must dereference to non-null pointer");

  parcEvent_Destroy(eventPtr);
  eventPtr = NULL;
}

void dispatcher_StartNetworkEvent(Dispatcher *dispatcher, PARCEvent *event) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(event, "Parameter event must be non-null");

  int failure = parcEvent_Start(event);
  parcAssertFalse(failure < 0, "Error starting signal event %p: (%d) %s",
                  (void *)event, errno, strerror(errno));
}

void dispatcher_StopNetworkEvent(Dispatcher *dispatcher, PARCEvent *event) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(event, "Parameter event must be non-null");

  int failure = parcEvent_Stop(event);
  parcAssertFalse(failure < 0, "Error stopping signal event %p: (%d) %s",
                  (void *)event, errno, strerror(errno));
}

PARCEventSignal *dispatcher_CreateSignalEvent(
    Dispatcher *dispatcher, PARCEventSignal_Callback *callback, void *userData,
    int signal) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(callback, "Parameter callback must be non-null");

  PARCEventSignal *event = parcEventSignal_Create(
      dispatcher->Base, signal, PARCEventType_Signal | PARCEventType_Persist,
      callback, userData);
  parcAssertNotNull(event,
                    "Got null event when creating signal catcher for signal %d",
                    signal);

  return event;
}

void dispatcher_DestroySignalEvent(Dispatcher *dispatcher,
                                   PARCEventSignal **eventPtr) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(eventPtr,
                    "Parameter eventPtr must be non-null double pointer");
  parcAssertNotNull(*eventPtr,
                    "Paramter eventPtr must dereference to non-null pointer");

  parcEventSignal_Destroy(eventPtr);
  eventPtr = NULL;
}

void dispatcher_StartSignalEvent(Dispatcher *dispatcher,
                                 PARCEventSignal *event) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(event, "Parameter event must be non-null");

  int failure = parcEventSignal_Start(event);
  parcAssertFalse(failure < 0, "Error starting signal event %p: (%d) %s",
                  (void *)event, errno, strerror(errno));
}

void dispatcher_StopSignalEvent(Dispatcher *dispatcher,
                                PARCEventSignal *event) {
  parcAssertNotNull(dispatcher, "Parameter dispatcher must be non-null");
  parcAssertNotNull(event, "Parameter event must be non-null");

  int failure = parcEventSignal_Stop(event);
  parcAssertFalse(failure < 0, "Error stopping signal event %p: (%d) %s",
                  (void *)event, errno, strerror(errno));
}


/**
 * Connect to an INET peer
 * @return NULL on error, otherwise a streambuffer
 */
PARCEventQueue *
dispatcher_StreamBufferConnect( Dispatcher *dispatcher, const address_pair_t * pair)
{
  if (!address_pair_valid(pair)) {
#if 0
    char message[2048];
    char *localAddressString = addressToString(localAddress);
    char *remoteAddressString = addressToString(remoteAddress);
    snprintf(message, 2048,
             "Remote address not same type as local address, expected %d got "
             "%d\nlocal %s remote %s",
             addressGetType(localAddress), addressGetType(remoteAddress),
             localAddressString, remoteAddressString);
#endif
    return NULL;
  }

  PARCEventQueue *buffer = parcEventQueue_Create( dispatcher->Base, -1,
          PARCEventQueueOption_CloseOnFree);
  parcAssertNotNull(buffer, "got null buffer from parcEventQueue_Create()");

  // we need to bind, then connect.  Special operation, so we make our
  // own fd then pass it off to the buffer event

#ifndef _WIN32
  int fd = socket(address_family(&pair->local), SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    goto ERR_SOCKET;
  }
#else
  SOCKET fd = socket(address_family(&pair->local), SOCK_STREAM, 0);
  if (fd == INVALID_SOCKET) {
    perror("socket");
    goto ERR_SOCKET;
  }
#endif /* _WIN32 */

  /* Set non-blocking flag */
#ifndef _WIN32
  int flags = fcntl(fd, F_GETFL, NULL);
  if (flags == -1) {
    perror("F_GETFL");
    goto ERR_IOCTL;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("F_SETFL");
    goto ERR_IOCTL;
  }
#else
  if (ioctlsocket(fd, FIONBIO, &(u_long){1}) != NO_ERROR) {
    perror("ioctlsocket");
    goto ERR_IOCTL;
  }
#endif /* _WIN32 */

  if (bind(fd, address_sa(&pair->local), address_socklen(&pair->local)) == -1) {
    perror("bind");
    goto ERR_BIND;
  }

#ifndef _WIN32
  parcEventQueue_SetFileDescriptor(buffer, fd);
#else
  parcEventQueue_SetFileDescriptor(buffer, (int)fd);
#endif /* _WIN32 */

  int failure = parcEventQueue_ConnectSocket(buffer, address_sa(&pair->remote), address_socklen(&pair->remote));
  if (failure && (errno != EINPROGRESS)) {
    perror("connect");
    goto ERR_CONNECT;
  }

  return buffer;

ERR_CONNECT:
ERR_BIND:
ERR_IOCTL:
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
  WSACleanup();
#endif /* _WIN32 */
ERR_SOCKET:
    parcEventQueue_Destroy(&buffer);
  return NULL;
}
