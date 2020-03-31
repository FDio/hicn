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

#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <parc/assert/parc_Assert.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

//#include <hicn/core/system.h>
//#include <hicn/utils/interfaceSet.h>
#include <hicn/utils/punting.h>
#include <hicn/base/listener_table.c>

#include <hicn/config/configurationListeners.h>
#include <hicn/io/hicnListener.h>
#include <hicn/io/tcpListener.h>
#include <hicn/io/udpListener.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#include <hicn/util/log.h>

#define DEFAULT_PORT 1234


bool
_AddPuntingInet(const Configuration *config, punting_t * punting,
        unsigned ingressId)
{
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
    address_t fakeaddr = ADDRESS4_ANY(DEFAULT_PORT);

    Forwarder * forwarder = configuration_GetForwarder(config);
    listener_table_t * table = forwarder_GetListenerTable(forwarder);
    ListenerOps *listener = listener_table_lookup(table, ENCAP_HICN, &fakeaddr);
    if (!listener) {
        ERROR("the main listener (IPV4) does not exist");
        return false;
    }

    address_t * address = punting_address(punting);
    if (!address)
        return false;

    char prefix[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address4_ip(&fakeaddr).s_addr, prefix, INET_ADDRSTRLEN);

    char len[5];
    snprintf(len, 5, "%d", punting_len(punting));

    char *prefixStr =
        malloc(strlen(prefix) + strlen(len) + 2);  //+1 for the zero-terminator
    if (!prefixStr) {
        ERROR("error while create the prefix string\n");
        return false;
    }
    strcpy(prefixStr, prefix);
    strcat(prefixStr, "/");
    strcat(prefixStr, len);

    if (!hicnListener_Punting(listener, prefixStr)) {
        ERROR("error while adding the punting rule\n");
        return false;
    }

    return true;
#else
    return false;
#endif
}

bool _AddPuntingInet6(const Configuration *config, punting_t * punting,
        unsigned ingressId) {
#if !defined(__APPLE__) && !defined(_WIN32) && defined(PUNTING)
    address_t fakeaddr = ADDRESS6_ANY(DEFAULT_PORT);

    // comments:
    // EncapType: I use the Hicn encap since the punting is available only for
    // Hicn listeners LocalAddress: The only listern for which we need punting
    // rules is the main one, which has no address
    //              so I create a fake empty address. This need to be consistent
    //              with the address set at creation time

    Forwarder * forwarder = configuration_GetForwarder(config);
    listener_table_t * table = forwarder_GetListenerTable(forwarder);
    ListenerOps *listener = listener_table_lookup(table, ENCAP_HICN, &fakeaddr);
    if (!listener) {
        ERROR("the main listener (IPV6) does not exist");
        return false;
    }

    char prefix[INET6_ADDRSTRLEN];

    char len[5];
    snprintf(len, 5, "%d", punting_len(punting));

    char *prefixStr = malloc(strlen(prefix) + strlen(len) + 2);  // +1 for the zero-terminator
    if (!prefixStr) {
        ERROR("error while create the prefix string\n");
        return false;
    }
    strcpy(prefixStr, prefix);
    strcat(prefixStr, "/");
    strcat(prefixStr, len);

    if (!hicnListener_Punting(listener, prefixStr)) {
        ERROR("error while adding the punting rule\n");
        return false;
    }

    return true;
#else
    return false;
#endif
}

//=============     LIGHT COMMAND    ===============


struct iovec *
configurationListeners_AddPunting(Configuration *config, struct iovec *request,
        unsigned ingressId)
{
    header_control_message *header = request[0].iov_base;
    add_punting_command *control = request[1].iov_base;

    punting_t punting = {
        .symbolic = control->symbolicOrConnid,
        .len = control->len,
    };

    if (address_from_ip_port(punting_address(&punting), control->family, &control->address,
                DEFAULT_PORT) < 0) {
        ERROR("Invalid IP type.");
        goto NACK;
    }

    // TODO XXX this could be optimized
    switch(control->family) {
        case AF_INET:
            if (!_AddPuntingInet(config, &punting, ingressId))
                goto NACK;
            break;
        case AF_INET6:
            if (!_AddPuntingInet6(config, &punting, ingressId))
                goto NACK;
            break;
        default:
            break;
    }

    return utils_CreateAck(header, control, sizeof(add_punting_command));

NACK:
    return utils_CreateNack(header, control, sizeof(add_punting_command));
}

//===========================       INITIAL LISTENERS ====================

// XXX TODO
    void
configurationListeners_SetupAll(const Configuration *config, uint16_t port,
        const char *localPath)
{
#if 0
    // XXX TODO
    Forwarder *forwarder = configuration_GetForwarder(config);
    InterfaceSet *set = system_Interfaces(forwarder);

    size_t interfaceSetLen = interfaceSetLength(set);
    for (size_t i = 0; i < interfaceSetLen; i++) {
        Interface *iface = interfaceSetGetByOrdinalIndex(set, i);

        const AddressList *addresses = interfaceGetAddresses(iface);
        size_t addressListLen = addressListLength(addresses);

        for (size_t j = 0; j < addressListLen; j++) {
            const address_t *address = addressListGetItem(addresses, j);

            // Do not start on link address
            char listenerName[SYMBOLIC_NAME_LEN];
#ifdef __ANDROID__
            snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%zu", i);
#else
            snprintf(listenerName, SYMBOLIC_NAME_LEN, "local_%ld", i);
#endif
            // XXX TODO      if (addressGetType(address) != ADDR_LINK) {
            _setupTcpListener(forwarder, listenerName, address,
                    (char *)interfaceGetName(iface));
            //      }
        }
    }

    interfaceSetDestroy(&set);
#endif
}

// XXX TODO
    void
configurationListeners_SetupLocalIPv4(const Configuration *config,
        uint16_t port)
{
    Forwarder * forwarder = configuration_GetForwarder(config);
    address_t address = ADDRESS4_LOCALHOST(port);

    _setupUdpListener(forwarder, "lo_udp", &address, "lo");
    _setupTcpListener(forwarder, "lo_tcp", &address, "lo");
}
