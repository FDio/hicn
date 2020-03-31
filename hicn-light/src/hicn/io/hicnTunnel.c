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

#include <hicn/io/hicnConnection.h>
#include <hicn/io/hicnListener.h>
#include <hicn/io/hicnTunnel.h>
#include <hicn/util/log.h>

IoOperations *
hicnTunnel_CreateOnListener(Forwarder *forwarder, ListenerOps *localListener,
        const address_t * remoteAddress)
{
    assert(forwarder);
    assert(localListener);
    assert(remoteAddress);

    if (localListener->getEncapType(localListener) != ENCAP_HICN) {
        ERROR("Local listener %p is not type hICN, cannot establish tunnel", localListener);
        return NULL;
    }

    const address_t * localAddress = localListener->getListenAddress(localListener);
    const address_pair_t pair = {
        .local = *localAddress,
        .remote = *remoteAddress,
    };

    if (!address_pair_valid(&pair)) {
        ERROR("Local listener address families differ (%s != %s, cannot establish tunnel",
                address_family_str(localAddress), address_family_str(remoteAddress));
        return NULL;
    }

    if (!hicnListener_Bind(localListener, remoteAddress)) {
        ERROR("Unable to bind local listener to remote node");
        return NULL;
    }

    // XXX ?
    // localAddress = hicnListener_GetTunAddress(localListener); //This is the
    // true local address

    int fd = localListener->getSocket(localListener, &pair);

    return hicnConnection_Create(forwarder, localListener->getInterfaceName(localListener), fd, &pair, false);
}

IoOperations *
hicnTunnel_Create(Forwarder *forwarder, const address_pair_t * pair)
{
    listener_table_t * table = forwarder_GetListenerTable(forwarder);
    ListenerOps * listener = listener_table_lookup(table, ENCAP_HICN, address_pair_local(pair));
    if (!listener) {
        // XXX TOOD
        //char *str = addressToString(localAddress);
        ERROR("Could not find listener to match address %p", address_pair_local(pair));
        //parcMemory_Deallocate((void **)&str);
    }

    IoOperations *ops = hicnTunnel_CreateOnListener(forwarder, listener,
            address_pair_remote(pair));
    if (!ops)
        return NULL;

    hicnListener_SetConnectionId(listener, ops->getConnectionId(ops));

    return ops;
}
