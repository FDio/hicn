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


#include <src/config.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <src/io/tcpTunnel.h>
#include <src/io/tcpListener.h>
#include <src/io/streamConnection.h>
#include <parc/assert/parc_Assert.h>


IoOperations *
tcpTunnel_Create(Forwarder *forwarder, const Address *localAddress, const Address *remoteAddress)
{
    IoOperations *ops = NULL;

    address_type localType = addressGetType(localAddress);
    address_type remoteType = addressGetType(remoteAddress);

    if (localType == remoteType) {
        AddressPair *pair = addressPair_Create(localAddress, remoteAddress);
        bool isLocal = false;

        ops = streamConnection_OpenConnection(forwarder, pair, isLocal);
    }

    return ops;
}

