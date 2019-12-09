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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <parc/algol/parc_Network.h>
#include <parc/assert/parc_Assert.h>
#include <hicn/io/udpConnection.h>
#include <hicn/io/udpListener.h>
#include <hicn/io/udpTunnel.h>

#if 0
#define ERROR(FMT, ...) do {                                                    \
  Logger *logger = forwarder_GetLogger(forwarder);                              \
  if (logger_IsLoggable(logger, LoggerFacility_IO, PARCLogLevel_Error))         \
    logger_Log(logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,         \
               FMT, ## __VA_ARGS__);                                            \
} while(0);
#endif

IoOperations *
udpTunnel_Create(Forwarder *forwarder, const address_pair_t * pair, unsigned connid)
{
  parcAssertNotNull(forwarder, "Parameter forwarder must be non-null");
  parcAssertNotNull(pair, "Parameter address pair must be non-null");

  listener_table_t * table = forwarder_GetListenerTable(forwarder);
  ListenerOps *listener = listener_table_lookup(table, ENCAP_UDP, &pair->local);
  if (!listener)
      goto ERR_NO_LISTENER;

  const char * interface_name = listener->getInterfaceName(listener);
  int fd = listener->getSocket(listener, pair);
  bool is_local = address_is_local(&pair->local);

  return udpConnection_Create(forwarder, interface_name, fd, pair, is_local, connid);

ERR_NO_LISTENER:
#if 0
  char *str = addressToString(localAddress);
  ERROR("Could not find listener to match address %s", str);
  parcMemory_Deallocate((void **)&str);
#endif
  return NULL;
}
