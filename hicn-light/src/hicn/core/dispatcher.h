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
 * @header hicn-light Dispatcher
 * @abstract The dispatcher is the event loop run by Forwarder.
 * @discussion
 *     These functions manage listeners, timers, and network events inside
 *     the event loop.
 *
 *     Curently, it is a thin wrapper around an event so we don't have to
 *     expose that implementation detail to other modules.
 *
 */

#ifndef dispatcher_h
#define dispatcher_h

#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <stdbool.h>

struct dispatcher;
typedef struct dispatcher Dispatcher;

#include <parc/algol/parc_Event.h>
#include <parc/algol/parc_EventQueue.h>
#include <parc/algol/parc_EventScheduler.h>
#include <parc/algol/parc_EventSignal.h>
#include <parc/algol/parc_EventSocket.h>
#include <parc/algol/parc_EventTimer.h>
#include <parc/algol/parc_Memory.h>

#include <hicn/base/address.h>

#include <hicn/core/logger.h>

PARCEventScheduler *dispatcher_GetEventScheduler(Dispatcher *dispatcher);
/**
 * Creates an event dispatcher
 *
 * Event dispatcher based on PARCEvent
 *
 * @return non-null Allocated event dispatcher
 * @return null An error
 */
Dispatcher *dispatcher_Create(Logger *logger);

/**
 * Destroys event dispatcher
 *
 * Caller is responsible for destroying call events before destroying
 * the event dispatcher.
 */
void dispatcher_Destroy(Dispatcher **dispatcherPtr);

/**
 * @function dispatcher_Stop
 * @abstract Called from a different thread, tells the dispatcher to stop
 * @discussion
 *   Called from a user thread or from an interrupt handler.
 *   Does not block.  Use <code>dispatcher_WaitForStopped()</code> to
 *   block until stopped after calling this.
 */
void dispatcher_Stop(Dispatcher *dispatcher);

/**
 * @function dispatcher_WaitForStopped
 * @abstract Blocks until dispatcher in stopped state
 * @discussion
 *   Used after <code>dispatcher_Stop()</code> to wait for stop.
 */
void dispatcher_WaitForStopped(Dispatcher *dispatcher);

/**
 * @function dispatcher_Run
 * @abstract Runs the forwarder, blocks.
 */
void dispatcher_Run(Dispatcher *dispatcher);

/**
 * @function dispatcher_RunDuration
 * @abstract Runs forwarder for at most duration, blocks.
 * @discussion
 *   Blocks running the forwarder for a duration.  May be called
 *   iteratively to keep running.  Duration is a minimum, actual
 *   runtime may be slightly longer.
 */
void dispatcher_RunDuration(Dispatcher *dispatcher, struct timeval *duration);

/**
 * @header dispatcher_RunCount
 * @abstract Run the event loop for the given count cycles
 * @discussion
 *     Runs the event loop for the given number of cycles, blocking
 *     until done.  May be called sequentially over and over.
 *
 */
void dispatcher_RunCount(Dispatcher *dispatcher, unsigned count);

typedef int SocketType;

typedef struct evconnlistener Listener;

/**
 * @typedef ListenerCallback
 * @abstract Callback function typedef for a stream listener
 *
 * @constant listener is the object created by <code>forwarder_NewBind()</code>
 * that received the client connection
 * @constant client_socket is the client socket
 * @constant user_data is the user_data passed to
 * <code>forwarder_NewBind()</code>
 * @constant client_addr is the client address
 * @constant socklen is the length of client_addr
 * @discussion <#Discussion#>
 */
typedef void(ListenerCallback)(Listener *listener, SocketType client_socket,
                               struct sockaddr *client_addr, int socklen,
                               void *user_data);

/**
 * @header forwarder_NewBind
 * @abstract Allocate a new stream listener
 * @discussion
 *     The server socket will be freed when closed and will be reusable.
 *
 * @param forwarder that owns the event loop
 * @param cb is the callback for a new connection
 * @param user_data is opaque user data passed to the callback
 * @param backlog is the listen() depth, may use -1 for a default value
 * @param sa is the socket address to bind to (INET, INET6, LOCAL)
 * @param socklen is the sizeof the actual sockaddr (e.g. sizeof(sockaddr_un))
 */
PARCEventSocket *dispatcher_CreateListener(Dispatcher *dispatcher,
        PARCEventSocket_Callback *callback, void *user_data, int backlog, const
        address_t * address, int socklen);

void dispatcher_DestroyListener(Dispatcher *dispatcher, PARCEventSocket
        **listenerPtr);

typedef struct event TimerEvent;
typedef struct event NetworkEvent;
typedef struct event SignalEvent;

/**
 * @typedef EventCallback
 * @abstract A network event or a timer callback
 * @constant fd The file descriptor associated with the event, may be -1 for
 * timers
 * @constant which_event is a bitmap of the EventType
 * @constant user_data is the user_data passed to
 * <code>Forwarder_CreateEvent()</code>
 */
typedef void(EventCallback)(SocketType fd, short which_event, void *user_data);

/**
 * @function dispatcher_CreateTimer
 * @abstract Creates a Event for use as a timer.
 * @discussion
 *
 *   When created, the timer is idle and you need to call
 * <code>forwarder_StartTimer()</code>
 *
 * @param isPeriodic means the timer will fire repeatidly, otherwise it is a
 * one-shot and needs to be set again with <code>dispatcher_StartTimer()</code>
 */
PARCEventTimer *dispatcher_CreateTimer(Dispatcher *dispatcher, bool isPeriodic,
                                       PARCEvent_Callback *callback,
                                       void *userData);

/**
 * @function dispatcher_StartTimer
 * @abstract Starts the timer with the given delay.
 * @discussion
 *   If the timer is periodic, it will keep firing with the given delay
 */
void dispatcher_StartTimer(Dispatcher *dispatcher, PARCEventTimer *timerEvent,
                           struct timeval *delay);

void dispatcher_StopTimer(Dispatcher *dispatcher, PARCEventTimer *timerEvent);

/**
 * @function dispatcher_DestroyTimerEvent
 * @abstract Cancels the timer and frees the event
 */
void dispatcher_DestroyTimerEvent(Dispatcher *dispatcher,
                                  PARCEventTimer **eventPtr);

/**
 * @function dispatcher_CreateNetworkEvent
 * @abstract Creates a network event callback on the socket
 * @discussion
 *   May be used on any sort of file descriptor or socket.  The event is edge
 * triggered and non-reentrent. This means you need to drain the events off the
 * socket, as the callback will not be called again until a new event arrives.
 *
 *   When created, the event is idle and you need to call
 * <code>forwarder_StartNetworkEvent()</code>
 *
 * @param isPersistent means the callback will keep firing with new events,
 * otherwise its a one-shot
 * @param fd is the socket to monitor
 */
PARCEvent *dispatcher_CreateNetworkEvent(Dispatcher *dispatcher,
                                         bool isPersistent,
                                         PARCEvent_Callback *callback,
                                         void *userData, int fd);

void dispatcher_StartNetworkEvent(Dispatcher *dispatcher, PARCEvent *event);
void dispatcher_StopNetworkEvent(Dispatcher *dispatcher, PARCEvent *event);

void dispatcher_DestroyNetworkEvent(Dispatcher *dispatcher,
                                    PARCEvent **eventPtr);

/**
 * @function dispatcher_CreateSignalEvent
 * @abstract Creates a signal trap
 * @discussion
 *   May be used on catchable signals.  The event is edge triggered and
 * non-reentrent.  Signal events are persistent.
 *
 *   When created, the signal trap is idle and you need to call
 * <code>forwarder_StartSignalEvent()</code>
 *
 * @param signal is the system signal to monitor (e.g. SIGINT).
 * @return <#return#>
 */
PARCEventSignal *dispatcher_CreateSignalEvent(
    Dispatcher *dispatcher, PARCEventSignal_Callback *callback, void *userData,
    int signal);

void dispatcher_DestroySignalEvent(Dispatcher *dispatcher,
                                   PARCEventSignal **eventPtr);

void dispatcher_StartSignalEvent(Dispatcher *dispatcher,
                                 PARCEventSignal *event);
void dispatcher_StopSignalEvent(Dispatcher *dispatcher, PARCEventSignal *event);

// =============
// stream buffers

#include <hicn/core/streamBuffer.h>
#include <hicn/base/address_pair.h>

/**
 * @function dispatcher_CreateStreamBuffer
 * @abstract Creates a high-function buffer around a stream socket
 */
PARCEventQueue *dispatcher_CreateStreamBufferFromSocket(Dispatcher *dispatcher,
                                                        SocketType fd);

/**
 * @function dispatcher_StreamBufferConnect
 * @abstract Create a TCP tunnel to a remote peer
 * @discussion
 *   For TCP, both address pairs need to be the same address family: both INET
 * or both INET6.  The remote address must have the complete socket information
 * (address, port).  The local socket could be wildcarded or may specify down to
 * the (address, port) pair.
 *
 *   If the local address is IPADDR_ANY and the port is 0, then it is a normal
 * call to "connect" that will use whatever local IP address and whatever local
 * port for the connection.  If either the address or port is set, the local
 * socket will first be bound (via bind(2)), and then call connect().
 *
 *   It is unlikely that the buffer will be connected by the time the function
 * returns.  The eventCallback will fire once the remote system accepts the
 * conneciton.
 *
 * @return NULL on error, otherwise a streambuffer.
 */
PARCEventQueue *dispatcher_StreamBufferConnect(Dispatcher *dispatcher,
                                               const address_pair_t *pair);
#endif  // dispatcher_h
