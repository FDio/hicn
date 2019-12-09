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

#include <parc/assert/parc_Assert.h>
#include <hicn/io/hicnConnection.h>
#include <hicn/io/hicnListener.h>
#include <hicn/io/hicnTunnel.h>

IoOperations *hicnTunnel_CreateOnListener(Forwarder *forwarder,
                                          ListenerOps *localListener,
                                          const Address *remoteAddress) {
  parcAssertNotNull(forwarder, "Parameter hicn-light must be non-null");
  parcAssertNotNull(localListener, "Parameter localListener must be non-null");
  parcAssertNotNull(remoteAddress, "Parameter remoteAddress must be non-null");

  Logger *logger = forwarder_GetLogger(forwarder);

  IoOperations *ops = NULL;
  if (localListener->getEncapType(localListener) == ENCAP_HICN) {
    const Address *localAddress =
        localListener->getListenAddress(localListener);
    address_type localType = addressGetType(localAddress);
    address_type remoteType = addressGetType(remoteAddress);

    if (localType == remoteType) {
      bool res = hicnListener_Bind(localListener, remoteAddress);
      if (res == false) {
        if (logger_IsLoggable(logger, LoggerFacility_IO, PARCLogLevel_Error)) {
          logger_Log(logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                     "Unable to bind local listener to remote node");
        }
        return ops;
      }

      // localAddress = hicnListener_GetTunAddress(localListener); //This is the
      // true local address

      AddressPair *pair = addressPair_Create(localAddress, remoteAddress);
      bool isLocal = false;
      int fd = localListener->getSocket(localListener, pair);
      ops = hicnConnection_Create(forwarder, localListener->getInterfaceName(localListener), fd, pair, isLocal);

      addressPair_Release(&pair);
    } else {
      if (logger_IsLoggable(logger, LoggerFacility_IO, PARCLogLevel_Error)) {
        logger_Log(logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                   "Local listener of type %s and remote type %s, cannot "
                   "establish tunnel",
                   addressTypeToString(localType),
                   addressTypeToString(remoteType));
      }
    }
  } else {
    if (logger_IsLoggable(logger, LoggerFacility_IO, PARCLogLevel_Error)) {
      logger_Log(logger, LoggerFacility_IO, PARCLogLevel_Error, __func__,
                 "Local listener %p is not type UDP, cannot establish tunnel",
                 (void *)localListener);
    }
  }

  return ops;
}

IoOperations *hicnTunnel_Create(Forwarder *forwarder,
                                const Address *localAddress,
                                const Address *remoteAddress) {
  ListenerSet *set = forwarder_GetListenerSet(forwarder);
  ListenerOps *listener = listenerSet_Find(set, ENCAP_HICN, localAddress);
  IoOperations *ops = NULL;
  if (listener) {
    ops = hicnTunnel_CreateOnListener(forwarder, listener, remoteAddress);
  } else {
    if (logger_IsLoggable(forwarder_GetLogger(forwarder), LoggerFacility_IO,
                          PARCLogLevel_Error)) {
      char *str = addressToString(localAddress);
      logger_Log(forwarder_GetLogger(forwarder), LoggerFacility_IO,
                 PARCLogLevel_Error, __func__,
                 "Could not find listener to match address %s", str);
      parcMemory_Deallocate((void **)&str);
    }
  }

  if (ops) {
    hicnListener_SetConnectionId(listener, ops->getConnectionId(ops));
  }

  return ops;
}
