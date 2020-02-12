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
 * Event based router
 *
 * This module is the glue around the event scheduler.
 * Its the packet i/o module.
 *
 * Packet processing is done in dispatcher.c, which is the actual wrapper around
 * the event scheduler
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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/logging/parc_LogReporterTextStdout.h>

#include <hicn/core/connectionManager.h>
#include <hicn/core/connectionTable.h>
#include <hicn/core/dispatcher.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/messagePacketType.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */
#include <hicn/config/configuration.h>
#include <hicn/config/configurationFile.h>
#include <hicn/config/configurationListeners.h>
#include <hicn/processor/messageProcessor.h>

#include <hicn/core/wldr.h>

#include <parc/assert/parc_Assert.h>

// the router's clock frequency (we now use the monotonic clock)
#define HZ 1000

// these will all be a little off because its all integer division
#define MSEC_PER_TICK (1000 / HZ)
#define USEC_PER_TICK (1000000 / HZ)
#define NSEC_PER_TICK ((1000000000ULL) / HZ)
#define MSEC_TO_TICKS(msec) \
  ((msec < FC_MSEC_PER_TICK) ? 1 : msec / FC_MSEC_PER_TICK)
#define NSEC_TO_TICKS(nsec) ((nsec < NSEC_PER_TICK) ? 1 : nsec / NSEC_PER_TICK)

struct forwarder {
  Dispatcher *dispatcher;

  uint16_t server_port;

  PARCEventSignal *signal_int;
  PARCEventSignal *signal_term;
#ifndef _WIN32
  PARCEventSignal *signal_usr1;
#endif
  PARCEventTimer *keepalive_event;

  // will skew the virtual clock forward.  In normal operaiton, it is 0.
  Ticks clockOffset;

  unsigned nextConnectionid;
  Messenger *messenger;
  ConnectionManager *connectionManager;
  ConnectionTable *connectionTable;
  ListenerSet *listenerSet;
  Configuration *config;

  // we'll eventually want to setup a threadpool of these
  MessageProcessor *processor;

  Logger *logger;

  PARCClock *clock;

  hicn_socket_helper_t
      *hicnSocketHelper;  // state required to manage hicn connections

  // used by seed48 and nrand48
  unsigned short seed[3];

#ifdef WITH_MAPME
  MapMe *mapme;
#endif /* WITH_MAPME */
};

// signal traps through the event scheduler
static void _signal_cb(int, PARCEventType, void *);

// A no-op keepalive to prevent Libevent from exiting the dispatch loop
static void _keepalive_cb(int, PARCEventType, void *);

/**
 * Reseed our pseudo-random number generator.
 */
static void forwarder_Seed(Forwarder *forwarder) {
#ifndef _WIN32
  int fd;
  ssize_t res;

  res = -1;
  fd = open("/dev/urandom", O_RDONLY);
  if (fd != -1) {
    res = read(fd, forwarder->seed, sizeof(forwarder->seed));
    close(fd);
  }
  if (res != sizeof(forwarder->seed)) {
    forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
    forwarder->seed[2] = (unsigned short)time(NULL);
  }
  /*
   * The call to seed48 is needed by cygwin, and should be harmless
   * on other platforms.
   */
  seed48(forwarder->seed);
#else
  forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
  forwarder->seed[2] = (unsigned short)time(NULL);
#endif
}

Logger *forwarder_GetLogger(const Forwarder *forwarder) {
  return forwarder->logger;
}

// ============================================================================
// Setup and destroy section

Forwarder *forwarder_Create(Logger *logger) {
  Forwarder *forwarder = parcMemory_AllocateAndClear(sizeof(Forwarder));
  parcAssertNotNull(forwarder, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Forwarder));
  memset(forwarder, 0, sizeof(Forwarder));
  forwarder_Seed(forwarder);

  forwarder->clock = parcClock_Monotonic();
  forwarder->clockOffset = 0;

  if (logger) {
    forwarder->logger = logger_Acquire(logger);
    logger_SetClock(forwarder->logger, forwarder->clock);
  } else {
    PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
    forwarder->logger = logger_Create(reporter, forwarder->clock);
    parcLogReporter_Release(&reporter);
  }

  forwarder->nextConnectionid = 1;
  forwarder->dispatcher = dispatcher_Create(forwarder->logger);
  forwarder->messenger = messenger_Create(forwarder->dispatcher);
  forwarder->connectionManager = connectionManager_Create(forwarder);
  forwarder->connectionTable = connectionTable_Create();
  forwarder->listenerSet = listenerSet_Create();
  forwarder->config = configuration_Create(forwarder);
  forwarder->processor = messageProcessor_Create(forwarder);

  forwarder->signal_term = dispatcher_CreateSignalEvent(
      forwarder->dispatcher, _signal_cb, forwarder, SIGTERM);
  dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_term);

  forwarder->signal_int = dispatcher_CreateSignalEvent(
      forwarder->dispatcher, _signal_cb, forwarder, SIGINT);
  dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_int);
#ifndef _WIN32
  forwarder->signal_usr1 = dispatcher_CreateSignalEvent(
      forwarder->dispatcher, _signal_cb, forwarder, SIGPIPE);
  dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_usr1);
#endif

#if !defined(__APPLE__) && !defined(__ANDROID__) && !defined(_WIN32) && \
    defined(PUNTING)
  forwarder->hicnSocketHelper = hicn_create();
  if (!forwarder->hicnSocketHelper)
      goto ERR_SOCKET;
#endif /* __APPLE__ */

#ifdef WITH_MAPME
  if (!(mapme_create(&forwarder->mapme, forwarder)))
      goto ERR_MAPME;
#endif /* WITH_MAPME */


       /* ignore child */
#ifndef _WIN32
  signal(SIGCHLD, SIG_IGN);

  /* ignore tty signals */
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
#endif

  // We no longer use this for ticks, but we need to have at least one event
  // schedule to keep Libevent happy.

  struct timeval wtnow_timeout;
  timerclear(&wtnow_timeout);

  wtnow_timeout.tv_sec = 0;
  wtnow_timeout.tv_usec = 50000;  // 20 Hz keepalive

  PARCEventScheduler *base =
      dispatcher_GetEventScheduler(forwarder->dispatcher);
  forwarder->keepalive_event = parcEventTimer_Create(
      base, PARCEventType_Persist, _keepalive_cb, (void *)forwarder);
  parcEventTimer_Start(forwarder->keepalive_event, &wtnow_timeout);

  return forwarder;

#ifdef WITH_MAPME
ERR_MAPME:
#endif /* WITH_MAPME */
#if !defined(__APPLE__) && !defined(__ANDROID__) && !defined(_WIN32) && \
    defined(PUNTING)
  hicn_free(forwarder->hicnSocketHelper);
ERR_SOCKET:
#endif
  listenerSet_Destroy(&(forwarder->listenerSet));
  connectionManager_Destroy(&(forwarder->connectionManager));
  connectionTable_Destroy(&(forwarder->connectionTable));
  messageProcessor_Destroy(&(forwarder->processor));
  configuration_Destroy(&(forwarder->config));
  messenger_Destroy(&(forwarder->messenger));

  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_int));
  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_term));
#ifndef _WIN32
  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_usr1));
#endif

  parcClock_Release(&forwarder->clock);
  logger_Release(&forwarder->logger);

  // do the dispatcher last
  dispatcher_Destroy(&(forwarder->dispatcher));

  parcMemory_Deallocate((void **)&forwarder);
  return NULL;
}

void forwarder_Destroy(Forwarder **ptr) {
  parcAssertNotNull(ptr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*ptr, "Parameter must dereference to non-null pointer");
  Forwarder *forwarder = *ptr;
#if !defined(__APPLE__) && !defined(__ANDROID__) && !defined(_WIN32) && \
    defined(PUNTING)
  hicn_free(forwarder->hicnSocketHelper);
#endif
  parcEventTimer_Destroy(&(forwarder->keepalive_event));

  listenerSet_Destroy(&(forwarder->listenerSet));
  connectionManager_Destroy(&(forwarder->connectionManager));
  connectionTable_Destroy(&(forwarder->connectionTable));
  messageProcessor_Destroy(&(forwarder->processor));
  configuration_Destroy(&(forwarder->config));

  // the messenger is used by many of the other pieces, so destroy it last
  messenger_Destroy(&(forwarder->messenger));

#ifdef WITH_MAPME
  mapme_free(forwarder->mapme);
#endif /* WITH_MAPME */

  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_int));
  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_term));
#ifndef _WIN32
  dispatcher_DestroySignalEvent(forwarder->dispatcher,
                                &(forwarder->signal_usr1));
#endif

  parcClock_Release(&forwarder->clock);
  logger_Release(&forwarder->logger);

  // do the dispatcher last
  dispatcher_Destroy(&(forwarder->dispatcher));

  parcMemory_Deallocate((void **)&forwarder);
  *ptr = NULL;
}

void forwarder_SetupAllListeners(Forwarder *forwarder, uint16_t port,
                                 const char *localPath) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");

  configurationListeners_SetupAll(forwarder->config, port, localPath);
}

void forwarder_SetupLocalListeners(Forwarder *forwarder, uint16_t port) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  configurationListeners_SetutpLocalIPv4(forwarder->config, port);
}

void forwarder_SetupFromConfigFile(Forwarder *forwarder, const char *filename) {
  ConfigurationFile *configFile = configurationFile_Create(forwarder, filename);
  if (configFile) {
    configurationFile_Process(configFile);
    configurationFile_Release(&configFile);
  }
}

Configuration *forwarder_GetConfiguration(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->config;
}

// ============================================================================

unsigned forwarder_GetNextConnectionId(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->nextConnectionid++;
}

Messenger *forwarder_GetMessenger(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->messenger;
}

Dispatcher *forwarder_GetDispatcher(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->dispatcher;
}

#ifdef WITH_POLICY
ConnectionTable *forwarder_GetConnectionTable(const Forwarder *forwarder) {
#else
ConnectionTable *forwarder_GetConnectionTable(Forwarder *forwarder) {
#endif /* WITH_POLICY */
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->connectionTable;
}

ListenerSet *forwarder_GetListenerSet(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return forwarder->listenerSet;
}

void forwarder_SetChacheStoreFlag(Forwarder *forwarder, bool val) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  messageProcessor_SetCacheStoreFlag(forwarder->processor, val);
}

bool forwarder_GetChacheStoreFlag(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return messageProcessor_GetCacheStoreFlag(forwarder->processor);
}

void forwarder_SetChacheServeFlag(Forwarder *forwarder, bool val) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  messageProcessor_SetCacheServeFlag(forwarder->processor, val);
}

bool forwarder_GetChacheServeFlag(Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return messageProcessor_GetCacheServeFlag(forwarder->processor);
}

void forwarder_ReceiveCommand(Forwarder *forwarder, command_id command,
                              struct iovec *message, unsigned ingressId) {
  configuration_ReceiveCommand(forwarder->config, command, message, ingressId);
}

void forwarder_Receive(Forwarder *forwarder, Message *message) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  // this takes ownership of the message, so we're done here

  // this are the checks needed to implement WLDR. We set wldr only on the STAs
  // and we let the AP to react according to choise of the client.
  // if the STA enables wldr using the set command, the AP enable wldr as well
  // otherwise, if the STA disable it the AP remove wldr
  // WLDR should be enabled only on the STAs using the command line
  // TODO
  // disable WLDR command line on the AP
  const Connection *conn = connectionTable_FindById(
      forwarder->connectionTable, message_GetIngressConnectionId(message));

  if (!conn) {
    return;
  }

  if (message_HasWldr(message)) {
    if (connection_HasWldr(conn)) {
      // case 1: WLDR is enabled
      connection_DetectLosses((Connection *)conn, message);
    } else if (!connection_HasWldr(conn) &&
               connection_WldrAutoStartAllowed(conn)) {
      // case 2: We are on an AP. We enable WLDR
      connection_EnableWldr((Connection *)conn);
      connection_DetectLosses((Connection *)conn, message);
    }
    // case 3: Ignore WLDR
  } else {
    if (connection_HasWldr(conn) && connection_WldrAutoStartAllowed(conn)) {
      // case 1: STA do not use WLDR, we disable it
      connection_DisableWldr((Connection *)conn);
    }
  }

  messageProcessor_Receive(forwarder->processor, message);
}

Ticks forwarder_GetTicks(const Forwarder *forwarder) {
  parcAssertNotNull(forwarder, "Parameter must be non-null");
  return parcClock_GetTime(forwarder->clock) + forwarder->clockOffset;
}

Ticks forwarder_NanosToTicks(uint64_t nanos) { return NSEC_TO_TICKS(nanos); }

uint64_t forwarder_TicksToNanos(Ticks ticks) {
  return (1000000000ULL) * ticks / HZ;
}

bool forwarder_AddOrUpdateRoute(Forwarder *forwarder,
                                add_route_command *control, unsigned ifidx) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(control, "Parameter route must be non-null");

  // we only have one message processor
  bool res =
      messageProcessor_AddOrUpdateRoute(forwarder->processor, control, ifidx);

  return res;
}


bool forwarder_RemoveRoute(Forwarder *forwarder, remove_route_command *control,
                           unsigned ifidx) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(control, "Parameter route must be non-null");

  // we only have one message processor
  return messageProcessor_RemoveRoute(forwarder->processor, control, ifidx);
}

#ifdef WITH_POLICY

bool forwarder_AddOrUpdatePolicy(Forwarder *forwarder,
                                add_policy_command *control) {
  parcAssertNotNull(forwarder, "Parameter forwarder must be non-null");
  parcAssertNotNull(control, "Parameter control must be non-null");

  return messageProcessor_AddOrUpdatePolicy(forwarder->processor, control);
}

bool forwarder_RemovePolicy(Forwarder *forwarder, remove_policy_command *control) {
  parcAssertNotNull(forwarder, "Parameter forwarder must be non-null");
  parcAssertNotNull(control, "Parameter control must be non-null");

  return messageProcessor_RemovePolicy(forwarder->processor, control);
}

#endif /* WITH_POLICY */

void forwarder_RemoveConnectionIdFromRoutes(Forwarder *forwarder,
                                            unsigned connectionId) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  messageProcessor_RemoveConnectionIdFromRoutes(forwarder->processor,
                                                connectionId);
}

void forwarder_SetStrategy(Forwarder *forwarder, Name *prefix,
                           strategy_type strategy,
                           unsigned related_prefixes_len,
                           Name **related_prefixes) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(prefix, "Parameter prefix must be non-null");

  processor_SetStrategy(forwarder->processor, prefix, strategy,
                        related_prefixes_len, related_prefixes);
}

FibEntryList *forwarder_GetFibEntries(Forwarder *forwarder) {
  return messageProcessor_GetFibEntries(forwarder->processor);
}

void forwarder_SetContentObjectStoreSize(Forwarder *forwarder,
                                         size_t maximumContentStoreSize) {
  messageProcessor_SetContentObjectStoreSize(forwarder->processor,
                                             maximumContentStoreSize);
}

void forwarder_ClearCache(Forwarder *forwarder) {
  messageProcessor_ClearCache(forwarder->processor);
}

PARCClock *forwarder_GetClock(const Forwarder *forwarder) {
  return forwarder->clock;
}

hicn_socket_helper_t *forwarder_GetHicnSocketHelper(Forwarder *forwarder) {
  return forwarder->hicnSocketHelper;
}

// =======================================================

static void _signal_cb(int sig, PARCEventType events, void *user_data) {
  Forwarder *forwarder = (Forwarder *)user_data;

  logger_Log(forwarder->logger, LoggerFacility_Core, PARCLogLevel_Warning,
             __func__, "signal %d events %d", sig, events);

  switch ((int)sig) {
    case SIGTERM:
      logger_Log(forwarder->logger, LoggerFacility_Core, PARCLogLevel_Warning,
                 __func__, "Caught an terminate signal; exiting cleanly.");
      dispatcher_Stop(forwarder->dispatcher);
      break;

    case SIGINT:
      logger_Log(forwarder->logger, LoggerFacility_Core, PARCLogLevel_Warning,
                 __func__, "Caught an interrupt signal; exiting cleanly.");
      dispatcher_Stop(forwarder->dispatcher);
      break;
#ifndef _WIN32
    case SIGUSR1:
      // dump stats
      break;
#endif

    default:
      break;
  }
}

static void _keepalive_cb(int fd, PARCEventType what, void *user_data) {
  parcAssertTrue(what & PARCEventType_Timeout, "Got unexpected tick_cb: %d",
                 what);
  // function is just a keepalive for hicn-light, does not do anything
}

#ifdef WITH_MAPME
FIB *forwarder_getFib(Forwarder *forwarder) {
  return messageProcessor_getFib(forwarder->processor);
}

void forwarder_onFaceEvent(Forwarder *forwarder, unsigned conn_id, face_event_t event) {
  mapme_onFaceEvent(forwarder->mapme, conn_id, event);
}

void forwarder_onRouteEvent(Forwarder *forwarder, Name * name, unsigned conn_id, route_event_t event) {
  mapme_onRouteEvent(forwarder->mapme, name, conn_id, event);
}

void forwarder_ProcessMapMe(Forwarder *forwarder, const uint8_t *msgBuffer,
                            unsigned conn_id) {
  mapme_Process(forwarder->mapme, msgBuffer, conn_id);
}

MapMe *
forwarder_getMapmeInstance(const Forwarder *forwarder) {
    return forwarder->mapme;
}

#endif /* WITH_MAPME */
