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

IoOperations *udpTunnel_CreateOnListener(Forwarder *forwarder,
                                         ListenerOps *localListener,
                                         const Address *remoteAddress) {
  parcAssertNotNull(forwarder, "Parameter metis must be non-null");
  parcAssertNotNull(localListener, "Parameter localListener must be non-null");
  parcAssertNotNull(remoteAddress, "Parameter remoteAddress must be non-null");

  Logger *logger = forwarder_GetLogger(forwarder);

  IoOperations *ops = NULL;
  if (localListener->getEncapType(localListener) == ENCAP_UDP) {
    const Address *localAddress =
        localListener->getListenAddress(localListener);
    address_type localType = addressGetType(localAddress);
    address_type remoteType = addressGetType(remoteAddress);

    if (localType == remoteType) {
      AddressPair *pair = addressPair_Create(localAddress, remoteAddress);

      //check it the connection is local
      bool isLocal = false;
      if(localType == ADDR_INET){
        struct sockaddr_in tmpAddr;
        addressGetInet(localAddress, &tmpAddr);
        if(parcNetwork_IsSocketLocal((struct sockaddr *)&tmpAddr))
          isLocal = true;
      }else{
        struct sockaddr_in6 tmpAddr6;
        addressGetInet6(localAddress, &tmpAddr6);
        if(parcNetwork_IsSocketLocal((struct sockaddr *)&tmpAddr6))
          isLocal = true;
      }
      int fd = localListener->getSocket(localListener);
      // udpListener_SetPacketType(localListener,
      //                MessagePacketType_ContentObject);
      ops = udpConnection_Create(forwarder, localListener->getInterfaceName(localListener), fd, pair, isLocal);

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

IoOperations *udpTunnel_Create(Forwarder *forwarder,
                               const Address *localAddress,
                               const Address *remoteAddress) {
  ListenerSet *set = forwarder_GetListenerSet(forwarder);
  ListenerOps *listener = listenerSet_Find(set, ENCAP_UDP, localAddress);
  IoOperations *ops = NULL;
  if (listener) {
    ops = udpTunnel_CreateOnListener(forwarder, listener, remoteAddress);
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
  return ops;
}
