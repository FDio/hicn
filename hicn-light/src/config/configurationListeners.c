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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Network.h>

#include <src/utils/interfaceSet.h>
#include <src/utils/punting.h>
#include <src/core/system.h>

#include <src/config/configurationListeners.h>
#include <src/io/tcpListener.h>
#include <src/io/hicnListener.h>
#include <src/io/udpListener.h>

#include <src/utils/addressList.h>
#include <src/utils/commands.h>
#include <src/utils/utils.h>


static bool
_setupHIcnListenerOnInet4(Forwarder *forwarder, const char *symbolic, Address *address)
{
    bool success = false;
#ifndef __APPLE__
    ListenerOps *ops = hicnListener_CreateInet(forwarder, (char *) symbolic, address);
    if (ops != NULL) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add HIcn listener %s to ListenerSet", symbolic);
    }
#endif /* __APPLE__ */
    return success;
}

static bool
_setupHIcnListenerOnInet6(Forwarder *forwarder, const char *symbolic, Address *address)
{
    bool success = false;
#ifndef __APPLE__
    ListenerOps *ops = hicnListener_CreateInet6(forwarder, (char *) symbolic, address);
    if (ops != NULL) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add HIcn listener %s to ListenerSet", symbolic);
    }
#endif /* __APPLE__ */
    return success;
}


bool
configurationListeners_Remove(const Configuration *config)
{
    Logger *logger = configuration_GetLogger(config);
    if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
        logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
                          "Removing a listener not supported: ingress %u control %s");
    }

    return false;
}

bool
_AddPuntingInet(const Configuration *config,
                    Punting * punting,
                    unsigned ingressId)
{
#ifndef __APPLE__
    struct sockaddr *addr = parcNetwork_SockAddress("0.0.0.0", 1234);
     if (addr == NULL) {
        printf("Error creating address\n");
        return false;
    }

    Address *fakeAddr =  addressCreateFromInet((struct sockaddr_in *) addr);

    ListenerOps * listenerOps = listenerSet_Find(forwarder_GetListenerSet(
            configuration_GetForwarder(config)), ENCAP_HICN, fakeAddr);
    addressDestroy(&fakeAddr);

    if(listenerOps == NULL){
        printf("the main listener (IPV4) does not exists\n");
        return false;
    }

    struct sockaddr_in puntingAddr;

    Address * address = puntingGetAddress(punting);
    if(address == NULL)
        return false;

    bool res = addressGetInet(address, &puntingAddr);
    if(!res) {
        printf("unable to read the punting address\n");
        return false;
    }


    char prefix[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(puntingAddr.sin_addr), prefix, INET_ADDRSTRLEN);

    char len[5];
    sprintf(len, "%d", puntingPrefixLen(punting));

    char *prefixStr = malloc(strlen(prefix)+strlen(len)+2);//+1 for the zero-terminator
    if(prefixStr == NULL){
        printf("error while create the prefix string\n");
        return false;
    }
    strcpy(prefixStr, prefix);
    strcat(prefixStr, "/");
    strcat(prefixStr, len);

    res = hicnListener_Punting(listenerOps, prefixStr);
    if(!res){
        printf("error while adding the punting rule\n");
        return false;
    }

    return true;
#else
    return false;
#endif

}


bool
_AddPuntingInet6(const Configuration *config,
                    Punting * punting,
                    unsigned ingressId)
{
   #ifndef __APPLE__
    struct sockaddr *addr = parcNetwork_SockAddress("0::0", 1234);
     if (addr == NULL) {
        printf("Error creating address\n");
        return false;
    }

    Address *fakeAddr =  addressCreateFromInet6((struct sockaddr_in6 *) addr);

    //comments:
    //EncapType: I use the HIcn encap since the puting is available only for HIcn listeners
    //LocalAddress: The only listern for which we need punting rules is the main one, which has no address
    //              so I create a fake empty address. This need to be consistent with the address set at
    //              creation time

    ListenerOps * listenerOps = listenerSet_Find(forwarder_GetListenerSet(
        configuration_GetForwarder(config)), ENCAP_HICN, fakeAddr);
    addressDestroy(&fakeAddr);

    if(listenerOps == NULL){
        printf("the main listener does not exists\n");
        return false;
    }

    struct sockaddr_in6 puntingAddr;
    bool res = addressGetInet6(puntingGetAddress(punting), &puntingAddr);
    if(!res) {
        printf("unable to read the punting address\n");
        return false;
    }

    char prefix[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(puntingAddr.sin6_addr), prefix, INET6_ADDRSTRLEN);

    char len[5];
    sprintf(len, "%d", puntingPrefixLen(punting));

    char *prefixStr = malloc(strlen(prefix)+strlen(len)+2);//+1 for the zero-terminator
    if(prefixStr == NULL){
        printf("error while create the prefix string\n");
        return false;
    }
    strcpy(prefixStr, prefix);
    strcat(prefixStr, "/");
    strcat(prefixStr, len);

    res = hicnListener_Punting(listenerOps, prefixStr);
    if(!res){
        printf("error while adding the punting rule\n");
        return false;
    }

    return true;
#else
    return false;
#endif

}


//=============     LIGHT COMMAN    ===============



static bool
_addEther(Configuration *config, add_listener_command *control, unsigned ingressId)
{
    //Not implemented
    return false;
}

static bool
_setupTcpListenerOnInet(Forwarder *forwarder, ipv4_addr_t *addr4, uint16_t *port){

    bool success = false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=*port;
    addr.sin_addr.s_addr=*addr4;

    ListenerOps *ops = tcpListener_CreateInet(forwarder, addr);
    if (ops) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add TCP listener on %s to ListenerSet", addressToString(ops->getListenAddress(ops)));
    }
    return success;
}

static bool
_setupUdpListenerOnInet(Forwarder *forwarder, ipv4_addr_t *addr4, uint16_t *port){

    bool success = false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_port=*port;
    addr.sin_addr.s_addr=*addr4;

    ListenerOps *ops = udpListener_CreateInet(forwarder, addr);
    if (ops) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add UDP listener on %s to ListenerSet", addressToString(ops->getListenAddress(ops)));
    }
    return success;

}

static bool
_setupTcpListenerOnInet6Light(Forwarder *forwarder, ipv6_addr_t *addr6, uint16_t *port, uint32_t scopeId)
{
    bool success = false;

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    addr.sin6_port=*port;
    addr.sin6_addr=*addr6;
    addr.sin6_scope_id=scopeId;

    ListenerOps *ops = tcpListener_CreateInet6(forwarder, addr);
    if (ops) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add TCP6 listener on %s to ListenerSet", addressToString(ops->getListenAddress(ops)));
    }
    return success;
}

static bool
_setupUdpListenerOnInet6Light(Forwarder *forwarder, ipv6_addr_t *addr6, uint16_t *port)
{
    bool success = false;

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    addr.sin6_port=*port;
    addr.sin6_addr=*addr6;
    addr.sin6_scope_id=0;

    ListenerOps *ops = udpListener_CreateInet6(forwarder, addr);
    if (ops) {
        success = listenerSet_Add(forwarder_GetListenerSet(forwarder), ops);
        parcAssertTrue(success, "Failed to add UDP6 listener on %s to ListenerSet", addressToString(ops->getListenAddress(ops)));
    }
    return success;
}



bool
_addHicn(Configuration *config, add_listener_command *control, unsigned ingressId){

    bool success = false;
    const char *symbolic = control->symbolic;
    Address *localAddress = NULL;

    switch (control->addressType){
        case ADDR_INET: {
            localAddress = utils_AddressFromInet(&control->address.ipv4, &control->port);
            success = _setupHIcnListenerOnInet4(configuration_GetForwarder(config), symbolic, localAddress);
            break;
        }

        case ADDR_INET6: {
            localAddress = utils_AddressFromInet6(&control->address.ipv6, &control->port);
            success = _setupHIcnListenerOnInet6(configuration_GetForwarder(config), symbolic, localAddress);
            break;
        }

        default:
            if (logger_IsLoggable(configuration_GetLogger(config),
                                         LoggerFacility_Config,
                                         PARCLogLevel_Warning)) {
                logger_Log(configuration_GetLogger(config),
                                  LoggerFacility_Config,
                                  PARCLogLevel_Warning,
                                  __func__,
                                  "Unsupported address type for HICN (ingress id %u): "
                                  "must be either IPV4 or IPV6",
                                  ingressId);
            }
            break;
    }

    if (success == true && localAddress != NULL) {
        if (logger_IsLoggable(configuration_GetLogger(config),
                                     LoggerFacility_Config,
                                     PARCLogLevel_Info)) {
            logger_Log(configuration_GetLogger(config),
                              LoggerFacility_Config,
                              PARCLogLevel_Info,
                              __func__,
                              "Setup hicn listener on address %s",
                              addressToString(localAddress));
        }
    }

    addressDestroy(&localAddress);

    return success;

}



bool
_addIP(Configuration *config, add_listener_command *control, unsigned ingressId){

    bool success = false;

    switch (control->addressType){
        case ADDR_INET: {
            if(control->connectionType == UDP_CONN){
                success = _setupUdpListenerOnInet(configuration_GetForwarder(config),
                                                        &control->address.ipv4,
                                                        &control->port);
            } else if (control->connectionType == TCP_CONN) {
                success = _setupTcpListenerOnInet(configuration_GetForwarder(config),
                                                        &control->address.ipv4,
                                                        &control->port);
            }
            break;
        }

        case ADDR_INET6: {
            if(control->connectionType == UDP_CONN){
                success = _setupUdpListenerOnInet6Light(configuration_GetForwarder(config),
                                                        &control->address.ipv6,
                                                        &control->port);
            } else if (control->connectionType == TCP_CONN) {
                success = _setupTcpListenerOnInet6Light(configuration_GetForwarder(config),
                                                        &control->address.ipv6,
                                                        &control->port,
                                                        0);
            }
            break;
        }

        default:
            if (logger_IsLoggable(configuration_GetLogger(config),
                                         LoggerFacility_Config,
                                         PARCLogLevel_Warning)) {
                char *addrStr = utils_CommandAddressToString(control->addressType,
                                                                        &control->address,
                                                                        &control->port);
                logger_Log(configuration_GetLogger(config),
                                LoggerFacility_Config,
                                PARCLogLevel_Warning,
                                __func__,
                                "Unsupported address type for IP encapsulation ingress id %u: %s",
                                ingressId,
                                addrStr);
            parcMemory_Deallocate((void **) &addrStr);
            }
            break;
    }

    if (success) {
        if (logger_IsLoggable(configuration_GetLogger(config),
                                     LoggerFacility_Config,
                                     PARCLogLevel_Info)) {
            char *addrStr = utils_CommandAddressToString(control->addressType,
                                                                    &control->address,
                                                                    &control->port);
            logger_Log(configuration_GetLogger(config),
                              LoggerFacility_Config,
                              PARCLogLevel_Info,
                              __func__,
                              "Setup listener on address %s",
                              addrStr);
        parcMemory_Deallocate((void **) &addrStr);
        }
    }

    return success;

}

struct iovec *
configurationListeners_Add(Configuration *config, struct iovec *request, unsigned ingressId){

    header_control_message *header  = request[0].iov_base;
    add_listener_command *control = request[1].iov_base;

    bool success = false;

    if (control->listenerMode == ETHER_MODE){
        parcTrapNotImplemented("Add Ethernet Listener is not supported");
        success = _addEther(config, control, ingressId);
        //it is a failure
    } else if (control->listenerMode == IP_MODE){
        success = _addIP(config, control, ingressId);
    } else if (control->listenerMode == HICN_MODE){
        success = _addHicn(config, control, ingressId);
    } else {
        Logger *logger = configuration_GetLogger(config);
        if (logger_IsLoggable(logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
            logger_Log(logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
                                "Unsupported encapsulation mode (ingress id %u)", ingressId);
        }
    }

    //generate ACK/NACK
    struct iovec* response;

    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(add_listener_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(add_listener_command));
    }

    return response;

}


struct iovec *
configurationListeners_AddPunting(Configuration *config, struct iovec *request, unsigned ingressId)
{

    header_control_message *header  = request[0].iov_base;
    add_punting_command *control = request[1].iov_base;

    const char *symbolicOrConnid = control->symbolicOrConnid;
    uint32_t len = control->len;
    in_port_t port = htons(1234);
    bool success = false;

    if(control->addressType == ADDR_INET){
        Address *address = utils_AddressFromInet(&control->address.ipv4, &port);
        Punting *punting = puntingCreate(symbolicOrConnid, address, len);
        success = _AddPuntingInet(config,punting,ingressId);
        addressDestroy(&address);
    }else if(control->addressType == ADDR_INET6){
        Address *address = utils_AddressFromInet6(&control->address.ipv6, &port);
        Punting *punting = puntingCreate(symbolicOrConnid, address, len);
        success = _AddPuntingInet6(config,punting,ingressId);
        addressDestroy(&address);
    }else {
        printf("Invalid IP type.\n"); //will generate a Nack
        return utils_CreateNack(header, control, sizeof(add_punting_command));
    }

    //generate ACK/NACK
    struct iovec* response;
    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(add_punting_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(add_punting_command));
    }

    return response;

}


//===========================       INITIAL LISTENERS        ====================


static void
_setupListenersOnAddress(Forwarder *forwarder, const Address *address, uint16_t port, const char *interfaceName)
{
    address_type type = addressGetType(address);
    switch (type) {
        case ADDR_INET:{
            struct sockaddr_in tmp;
            addressGetInet(address, &tmp);
            _setupTcpListenerOnInet(forwarder, &tmp.sin_addr.s_addr, &port);
            break;
        }


        case ADDR_INET6:{
            struct sockaddr_in6 tmp;
            addressGetInet6(address, &tmp);
            _setupTcpListenerOnInet6Light(forwarder, &tmp.sin6_addr, &port, tmp.sin6_scope_id);
            break;
        }


        case ADDR_LINK:
            // not used
            break;

        default:
            // dont' know how to handle this, so no listeners
            break;
    }
}


void
configurationListeners_SetupAll(const Configuration *config, uint16_t port, const char *localPath)
{
    Forwarder *forwarder = configuration_GetForwarder(config);
    InterfaceSet *set = system_Interfaces(forwarder);

    size_t interfaceSetLen = interfaceSetLength(set);
    for (size_t i = 0; i < interfaceSetLen; i++) {
        Interface *iface = interfaceSetGetByOrdinalIndex(set, i);

        const AddressList *addresses = interfaceGetAddresses(iface);
        size_t addressListLen = addressListLength(addresses);

        for (size_t j = 0; j < addressListLen; j++) {
            const Address *address = addressListGetItem(addresses, j);

            // Do not start on link address
            if (addressGetType(address) != ADDR_LINK) {
                _setupListenersOnAddress(forwarder, address, htons(port), interfaceGetName(iface));
            }
        }
    }

    //if (localPath != NULL) {
    //    _setupLocalListener(forwarder, localPath);
    //}

    interfaceSetDestroy(&set);
}

