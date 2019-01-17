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
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
#include <src/config.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_String.h>

#include <src/config/symbolicNameTable.h>
#include <src/config/configurationListeners.h>

#include <src/core/forwarder.h>
#include <src/core/system.h>
#include <src/core/connectionTable.h>
#include <src/core/connection.h>
#ifdef WITH_MAPME
#include <src/core/mapMe.h>
#endif /* WITH_MAPME */

#include <src/io/streamConnection.h>

#include <src/io/hicnTunnel.h>
#include <src/io/udpTunnel.h>
#include <src/io/tcpTunnel.h>

#include <src/utils/commands.h>
#include <src/utils/utils.h>
#include <src/io/listenerSet.h>      //   needed to print
#include <src/io/listener.h>         //the listener list
#include <parc/algol/parc_Unsigned.h>

#include <src/utils/address.h>

#define ETHERTYPE 0x0801

struct configuration {
    Forwarder *forwarder;
    Logger *logger;

    size_t maximumContentObjectStoreSize;

    // map from prefix (parcString) to strategy (parcString)
    PARCHashMap *strategy_map;

    // translates between a symblic name and a connection id
    SymbolicNameTable *symbolicNameTable;
};


// ========================================================================================

Configuration *
configuration_Create(Forwarder *forwarder)
{
    parcAssertNotNull(forwarder, "Parameter hicn-fwd must be non-null");
    Configuration *config = parcMemory_AllocateAndClear(sizeof(Configuration));
    parcAssertNotNull(config, "parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(Configuration));
    config->forwarder = forwarder;
    config->logger = logger_Acquire(forwarder_GetLogger(forwarder));
    config->maximumContentObjectStoreSize = 100000;
    config->strategy_map = parcHashMap_Create();
    config->symbolicNameTable = symbolicNameTable_Create();

    return config;
}

void
configuration_Destroy(Configuration **configPtr)
{
    parcAssertNotNull(configPtr, "Parameter must be non-null double poitner");
    parcAssertNotNull(*configPtr, "Parameter must dereference to non-null pointer");

    Configuration *config = *configPtr;
    logger_Release(&config->logger);
    parcHashMap_Release(&(config->strategy_map));
    symbolicNameTable_Destroy(&config->symbolicNameTable);
    parcMemory_Deallocate((void **) &config);
    *configPtr = NULL;
}

struct iovec *
configuration_ProcessRegisterHIcnPrefix(Configuration *config, struct iovec *request, unsigned ingressId){

    header_control_message *header  = request[0].iov_base;
    add_route_command *control = request[1].iov_base;

    bool success = false;

    const char *symbolicOrConnid = control->symbolicOrConnid;

    if ( strcmp(symbolicOrConnid, "SELF_ROUTE") == 0 ){
        success = forwarder_AddOrUpdateRoute(config->forwarder, control, ingressId);
    }else if(utils_IsNumber(symbolicOrConnid)){
        //case for connid as input
        unsigned connid = (unsigned) strtold(symbolicOrConnid, NULL);
        ConnectionTable *table = forwarder_GetConnectionTable(config->forwarder);

        //check if iconnID present in the fwd table
        if(connectionTable_FindById(table, connid)){
            success = forwarder_AddOrUpdateRoute(config->forwarder, control, connid);
        }else{
            logger_Log(forwarder_GetLogger(config->forwarder), LoggerFacility_IO, PARCLogLevel_Error, __func__,
                            "ConnID not found, check list connections");
            //failure
        }

    }else{
        //case for symbolic as input: check if symbolic name can be resolved
        unsigned connid = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        //connid = UINT_MAX when symbolicName is not found
        if (connid != UINT32_MAX) {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Debug)) {
            logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Debug, __func__,
                              "Add route resolve name '%s' to connid %u",
                              symbolicOrConnid, connid);
            }

            success = forwarder_AddOrUpdateRoute(config->forwarder, control, connid);

        }else {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
                 logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
                              "Add route symbolic name '%s' could not be resolved", symbolicOrConnid);
             }
            //failure
        }
    }

    //generate ACK/NACK
    struct iovec* response;

    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(add_route_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(add_route_command));
    }

    return response;

}

struct iovec *
configuration_ProcessUnregisterHIcnPrefix(Configuration *config, struct iovec *request){

    header_control_message *header  = request[0].iov_base;
    remove_route_command *control = request[1].iov_base;

    bool success = false;

    const char *symbolicOrConnid = control->symbolicOrConnid;

    if(utils_IsNumber(symbolicOrConnid)){
        //case for connid as input
        unsigned connid = (unsigned) strtold(symbolicOrConnid, NULL);
        ConnectionTable *table = forwarder_GetConnectionTable(config->forwarder);

        //check if interface index present in the fwd table
        if(connectionTable_FindById(table, connid)){
            success = forwarder_RemoveRoute(config->forwarder, control, connid);
        }else{
            logger_Log(forwarder_GetLogger(config->forwarder), LoggerFacility_IO, PARCLogLevel_Error, __func__,
                            "ConnID not found, check list connections");
            //failure
        }

    }else{
        //case for symbolic as input: chech if symbolic name can be resolved
        unsigned connid = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        //connid = UINT_MAX when symbolicName is not found
        if (connid != UINT32_MAX) {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Debug)) {
            logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Debug, __func__,
                              "Remove route resolve name '%s' to connid %u",
                              symbolicOrConnid, connid);
            }
            success = forwarder_RemoveRoute(config->forwarder, control, connid);
        }else {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
                 logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Warning, __func__,
                              "Remove route symbolic name '%s' could not be resolved", symbolicOrConnid);
             }
            //failure
        }

    }

    //generate ACK/NACK
    struct iovec* response;

    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(remove_route_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(remove_route_command));
    }

    return response;

}

struct iovec *
configuration_ProcessRegistrationList(Configuration *config, struct iovec *request)
{
    FibEntryList *fibList = forwarder_GetFibEntries(config->forwarder);

    size_t payloadSize = fibEntryList_Length(fibList);
    size_t pointerLocation = 0;
    struct sockaddr_in tmpAddr;
    struct sockaddr_in6 tmpAddr6;

    //allocate payload, cast from void* to uint8_t* = bytes granularity
    uint8_t *payloadResponse = parcMemory_AllocateAndClear(
        sizeof(list_routes_command) * payloadSize);

    for (size_t i = 0; i < fibEntryList_Length(fibList); i++) {
        FibEntry *entry = (FibEntry *) fibEntryList_Get(fibList, i);
        NameBitvector *prefix = name_GetContentName(fibEntry_GetPrefix(entry));
        const NumberSet *nexthops = fibEntry_GetNexthops(entry);

        if(numberSet_Length(nexthops)>1){
            //payload extended, need reallocate, further entries via nexthops
            payloadSize = payloadSize + numberSet_Length(nexthops)-1;
            payloadResponse = (uint8_t *) parcMemory_Reallocate(payloadResponse,
                sizeof(list_routes_command) * payloadSize);
        }

        for (size_t j = 0; j < numberSet_Length(nexthops); j++) {
            list_routes_command *listRouteCommand = (list_routes_command *)
                (payloadResponse + (pointerLocation * sizeof(list_routes_command)));

            Address *addressEntry = nameBitvector_ToAddress(prefix);
            if (addressGetType(addressEntry) == ADDR_INET){
                addressGetInet(addressEntry, &tmpAddr);
                listRouteCommand->addressType = ADDR_INET;
                listRouteCommand->address.ipv4 = tmpAddr.sin_addr.s_addr;
            }else if(addressGetType(addressEntry) == ADDR_INET6){
                addressGetInet6(addressEntry,&tmpAddr6);
                listRouteCommand->addressType = ADDR_INET6;
                listRouteCommand->address.ipv6 = tmpAddr6.sin6_addr;
            }
            listRouteCommand->connid = numberSet_GetItem(nexthops, j);
            listRouteCommand->len = nameBitvector_GetLength(prefix);
            listRouteCommand->cost = 1; // cost

            pointerLocation ++;
            addressDestroy(&addressEntry);
        }
    }

    //send response
    header_control_message *header  = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = payloadSize;

    struct iovec* response = parcMemory_AllocateAndClear( sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = sizeof(list_routes_command) * payloadSize;

    return response;
}


static void
configuration_SendResponse(Configuration *config, struct iovec *msg, unsigned egressId)
{

    ConnectionTable *connectionTable = forwarder_GetConnectionTable(config->forwarder);
    const Connection *conn = connectionTable_FindById(connectionTable, egressId);
    parcAssertNotNull(conn, "Got null connection for control message we just received");

    IoOperations * ops = connection_GetIoOperations(conn);
    streamState_SendCommandResponse(ops, msg);

}


struct iovec *
configuration_ProcessCreateTunnel(Configuration *config, struct iovec *request){

    header_control_message *header  = request[0].iov_base;
    add_connection_command *control = request[1].iov_base;

    bool success = false;
    bool exists = true;

    const char *symbolicName = control->symbolic;

    Address *source = NULL;
    Address *destination = NULL;


    if (!symbolicNameTable_Exists(config->symbolicNameTable, symbolicName)){

        if(control->ipType == ADDR_INET){
            source = utils_AddressFromInet(&control->localIp.ipv4, &control->localPort);
            destination = utils_AddressFromInet(&control->remoteIp.ipv4, &control->remotePort);
        }else if(control->ipType == ADDR_INET6){
            source = utils_AddressFromInet6(&control->localIp.ipv6, &control->localPort);
            destination = utils_AddressFromInet6(&control->remoteIp.ipv6, &control->remotePort);
        }else {
            printf("Invalid IP type.\n"); //will generate a Nack
        }

        AddressPair *pair = addressPair_Create(source, destination);
        const Connection *conn =
            connectionTable_FindByAddressPair(forwarder_GetConnectionTable(config->forwarder), pair);

        addressPair_Release(&pair);

        if(conn == NULL){
            //the connection does not exists (even without a name)
            exists = false;
        }

    }

    if(!exists) {
        IoOperations *ops = NULL;
        switch (control->connectionType){
            case TCP_CONN:
                //logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,
                //                  "Unsupported tunnel protocol: TCP");
                ops = tcpTunnel_Create(config->forwarder, source, destination);
                break;
            case UDP_CONN:
                ops = udpTunnel_Create(config->forwarder, source, destination);
                break;
            case GRE_CONN:
                logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,
                                  "Unsupported tunnel protocol: GRE");
                break;
#ifndef __APPLE__
            case HICN_CONN:
                ops = hicnTunnel_Create(config->forwarder, source, destination);
                break;
#endif /* __APPLE__ */
            default:
                logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,
                                  "Unsupported tunnel protocol: %d",
                                  control->connectionType);
                break;
        }

        if (ops != NULL) {
            Connection *conn = connection_Create(ops);

            connectionTable_Add(forwarder_GetConnectionTable(config->forwarder), conn);
            symbolicNameTable_Add(config->symbolicNameTable, symbolicName,
                                         connection_GetConnectionId(conn));

            success = true;

        } else {
            printf("failed, could not create IoOperations");
        }

    } else {
        printf("failed, symbolic name or connextion already exist\n");
    }

    addressDestroy(&source);
    addressDestroy(&destination);


    //generate ACK/NACK
    struct iovec* response;

    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(add_connection_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(add_connection_command));
    }

    return response;

}

/**
 * Add an IP-based tunnel.
 *
 * The call cal fail if the symbolic name is a duplicate.  It could also fail if there's an problem creating
 * the local side of the tunnel (i.e. the local socket address is not usable).
 *
 * @return true Tunnel added
 * @return false Tunnel not added (an error)
 */

struct iovec *
configuration_ProcessRemoveTunnel(Configuration *config, struct iovec *request){

    header_control_message *header  = request[0].iov_base;
    remove_connection_command *control = request[1].iov_base;

    bool success = false;

    const char *symbolicOrConnid = control->symbolicOrConnid;
    ConnectionTable *table = forwarder_GetConnectionTable(config->forwarder);

    if(utils_IsNumber(symbolicOrConnid)){
        //case for connid as input
        unsigned connid = (unsigned) strtold(symbolicOrConnid, NULL);

        //check if interface index present in the fwd table
        //(it was missing and therefore caused a program crash)
        if(connectionTable_FindById(table, connid)){

            //remove connection from the FIB
            forwarder_RemoveConnectionIdFromRoutes(config->forwarder, connid);
            //remove connection
            connectionTable_RemoveById(table, connid);

            success = true;
        }else{
            logger_Log(forwarder_GetLogger(config->forwarder), LoggerFacility_IO, PARCLogLevel_Error, __func__,
                            "ConnID not found, check list connections");
            //failure
        }

    }else{
        //case for symbolic as input
        //chech if symbolic name can be resolved
        unsigned connid = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        //connid = UINT_MAX when symbolicName is not found
        if (connid != UINT32_MAX) {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Debug)) {
            logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Debug, __func__,
                              "Remove connection resolve name '%s' to connid %u",
                              symbolicOrConnid, connid);
            }

            //remove connection from the FIB
            forwarder_RemoveConnectionIdFromRoutes(config->forwarder, connid);
            //remove connection
            connectionTable_RemoveById(table, connid);
            //remove connection from symbolicNameTable since we have symbolic input
            symbolicNameTable_Remove(config->symbolicNameTable, symbolicOrConnid);
            success = true; //to write
        }else {

            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
                 logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,
                              "Remove connection symbolic name '%s' could not be resolved", symbolicOrConnid);
             }
            //failure
        }

    }

    //generate ACK/NACK
    struct iovec* response;

    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(remove_connection_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(remove_connection_command));
    }

    return response;

}


struct iovec *
configuration_ProcessConnectionList(Configuration *config, struct iovec *request)
{

    ConnectionTable *table = forwarder_GetConnectionTable(config->forwarder);
    ConnectionList *connList = connectionTable_GetEntries(table);
    struct sockaddr_in tmpAddr;
    struct sockaddr_in6 tmpAddr6;

    //allocate payload, cast from void* to uint8_t* fot bytes granularity
    uint8_t *payloadResponse = parcMemory_AllocateAndClear(
        sizeof(list_connections_command) * connectionList_Length(connList));

    for (size_t i = 0; i < connectionList_Length(connList); i++) {
        // Don't release original, it is not stored
        Connection *original = connectionList_Get(connList, i);

        const AddressPair *addressPair = connection_GetAddressPair(original);
        Address *localAddress = addressCopy(addressPair_GetLocal(addressPair));
        Address *remoteAddress = addressCopy(addressPair_GetRemote(addressPair));

        //Fill payload by shifting and casting at each 'i' step.
        list_connections_command *listConnectionsCommand = (list_connections_command *)
            (payloadResponse + (i * sizeof(list_connections_command)));

        //set structure fields
        listConnectionsCommand->connid = connection_GetConnectionId(original);
        listConnectionsCommand->state = connection_IsUp(original) ? IFACE_UP : IFACE_DOWN;
        listConnectionsCommand->connectionData.connectionType = ioOperations_GetConnectionType(
                                                                connection_GetIoOperations(original));

        if (addressGetType(localAddress) == ADDR_INET && addressGetType(remoteAddress) == ADDR_INET){
            listConnectionsCommand->connectionData.ipType = ADDR_INET;

            //get local port/address
            addressGetInet(localAddress, &tmpAddr);
            listConnectionsCommand->connectionData.localPort = tmpAddr.sin_port;
            listConnectionsCommand->connectionData.localIp.ipv4 = tmpAddr.sin_addr.s_addr;
            memset(&tmpAddr, 0, sizeof(tmpAddr));
            //get remote port/address
            addressGetInet(remoteAddress, &tmpAddr);
            listConnectionsCommand->connectionData.remotePort = tmpAddr.sin_port;
            listConnectionsCommand->connectionData.remoteIp.ipv4 = tmpAddr.sin_addr.s_addr;

        }else if(addressGetType(localAddress) == ADDR_INET6 && addressGetType(remoteAddress) == ADDR_INET6){
            listConnectionsCommand->connectionData.ipType = ADDR_INET6;

            //get local port/address
            addressGetInet6(localAddress, &tmpAddr6);
            listConnectionsCommand->connectionData.localPort = tmpAddr6.sin6_port;
            listConnectionsCommand->connectionData.localIp.ipv6 = tmpAddr6.sin6_addr;
            memset(&tmpAddr6, 0, sizeof(tmpAddr6));
            //get remote port/address
            addressGetInet6(remoteAddress, &tmpAddr6);
            listConnectionsCommand->connectionData.remotePort = tmpAddr6.sin6_port;
            listConnectionsCommand->connectionData.remoteIp.ipv6 = tmpAddr6.sin6_addr;

        }   //no need further else, control on the addressed already done at the time of insertion in the connection table
        addressDestroy(&localAddress);
        addressDestroy(&remoteAddress);
    }


    //send response
    header_control_message *header  = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (uint16_t) connectionList_Length(connList);

    struct iovec* response = parcMemory_AllocateAndClear( sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = sizeof(list_connections_command) * connectionList_Length(connList);

    return response;
}

struct iovec *
configuration_ProcessListenersList(Configuration *config, struct iovec *request)
{

    ListenerSet *listenerList = forwarder_GetListenerSet(config->forwarder);
    struct sockaddr_in tmpAddr;
    struct sockaddr_in6 tmpAddr6;

    //allocate payload, cast from void* to uint8_t* fot bytes granularity
    uint8_t *payloadResponse = parcMemory_AllocateAndClear(
        sizeof(list_listeners_command) * listenerSet_Length(listenerList));

    for (size_t i = 0; i < listenerSet_Length(listenerList); i++) {

        ListenerOps *listenerEntry = listenerSet_Get(listenerList, i);

        //Fill payload by shifting and casting at each 'i' step.
        list_listeners_command *listListenersCommand = (list_listeners_command *)
            (payloadResponse + (i * sizeof(list_listeners_command)));

        listListenersCommand->connid = (uint32_t) listenerEntry->getInterfaceIndex(listenerEntry);
        listListenersCommand->encapType = (uint8_t) listenerEntry->getEncapType(listenerEntry);
        if (addressGetType((const Address *) listenerEntry->getListenAddress(listenerEntry)) == ADDR_INET){
            addressGetInet((const Address *) listenerEntry->getListenAddress(listenerEntry), &tmpAddr);
            listListenersCommand->addressType = ADDR_INET;
            listListenersCommand->address.ipv4 = tmpAddr.sin_addr.s_addr;
            listListenersCommand->port = tmpAddr.sin_port;
        }else if(addressGetType((const Address *) listenerEntry->getListenAddress(listenerEntry)) == ADDR_INET6){
            addressGetInet6((const Address *) listenerEntry->getListenAddress(listenerEntry), &tmpAddr6);
            listListenersCommand->addressType = ADDR_INET6;
            listListenersCommand->address.ipv6 = tmpAddr6.sin6_addr;
            listListenersCommand->port = tmpAddr6.sin6_port;
        }
    }

    //send response
    header_control_message *header  = request[0].iov_base;
    header->messageType = RESPONSE_LIGHT;
    header->length = (uint16_t) listenerSet_Length(listenerList);

    struct iovec* response = parcMemory_AllocateAndClear( sizeof(struct iovec) * 2);

    response[0].iov_base = header;
    response[0].iov_len = sizeof(header_control_message);
    response[1].iov_base = payloadResponse;
    response[1].iov_len = sizeof(list_listeners_command) * listenerSet_Length(listenerList);

    return response;

}

struct iovec *
configuration_ProcessCacheStore(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;;
    cache_store_command *control = request[1].iov_base;;

    bool success = false;

    switch (control->activate)
    {
        case ACTIVATE_ON:
            forwarder_SetChacheStoreFlag(config->forwarder, true);
            if (forwarder_GetChacheStoreFlag(config->forwarder)) {
                success = true;
            }
            break;

        case ACTIVATE_OFF:
            forwarder_SetChacheStoreFlag(config->forwarder, false);
            if (!forwarder_GetChacheStoreFlag(config->forwarder)) {
                success = true;
            }
            break;

        default:
            break;
    }

    struct iovec* response;
    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(cache_store_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(cache_store_command));
    }

    return response;

}


struct iovec *
configuration_ProcessCacheServe(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    cache_serve_command *control = request[1].iov_base;

    bool success = false;

    switch (control->activate)
    {
        case ACTIVATE_ON:
            forwarder_SetChacheServeFlag(config->forwarder, true);
            if (forwarder_GetChacheServeFlag(config->forwarder)) {
                success = true;
            }
            break;

        case ACTIVATE_OFF:
            forwarder_SetChacheServeFlag(config->forwarder, false);
            if (!forwarder_GetChacheServeFlag(config->forwarder)) {
                success = true;
            }
            break;

        default:
            break;
    }

    struct iovec* response;
    if (success) {  //ACK
        response = utils_CreateAck(header, control, sizeof(cache_store_command));
    } else {        //NACK
        response = utils_CreateNack(header, control, sizeof(cache_store_command));
    }

    return response;

}

struct iovec *
configuration_ProcessCacheClear(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;

    forwarder_ClearCache(config->forwarder);

    struct iovec *response = utils_CreateAck(header, NULL, 0);
    return response;
}


size_t
configuration_GetObjectStoreSize(Configuration *config)
{
    return config->maximumContentObjectStoreSize;
}

void
_configuration_StoreFwdStrategy(Configuration *config, const char *prefix, strategy_type strategy)
{

    PARCString *prefixStr = parcString_Create(prefix);
    PARCUnsigned *strategyValue = parcUnsigned_Create((unsigned) strategy);
    parcHashMap_Put(config->strategy_map, prefixStr, strategyValue);
    parcUnsigned_Release(&strategyValue);
    parcString_Release(&prefixStr);
}

struct iovec *
configuration_SetWldr(Configuration *config, struct iovec *request){

    header_control_message *header  = request[0].iov_base;
    set_wldr_command *control = request[1].iov_base;
    ConnectionTable *table = forwarder_GetConnectionTable(config->forwarder);
    Connection *conn = NULL;
    bool success = false;

    const char *symbolicOrConnid = control->symbolicOrConnid;

    if(utils_IsNumber(symbolicOrConnid)){
        //case for connid as input: check if connID present in the fwd table
        conn = (Connection *) connectionTable_FindById(table, (unsigned) strtold(symbolicOrConnid, NULL));
        if(conn){
            success = true;
        }else{
            logger_Log(forwarder_GetLogger(config->forwarder), LoggerFacility_IO, PARCLogLevel_Error, __func__,
                            "ConnID not found, check list connections");    //failure
        }
    }else{
        //case for symbolic as input: check if symbolic name can be resolved
        unsigned connid = symbolicNameTable_Get(config->symbolicNameTable, symbolicOrConnid);
        if (connid != UINT32_MAX){
            conn = (Connection *) connectionTable_FindById(table, connid);
            if (conn) {
                if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Debug)) {
                logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Debug, __func__,
                                "Set wldr resolve name '%s' to connid %u", symbolicOrConnid, connid);
                }
                success = true;
            }
        } else {
            if (logger_IsLoggable(config->logger, LoggerFacility_Config, PARCLogLevel_Warning)) {
                 logger_Log(config->logger, LoggerFacility_Config, PARCLogLevel_Error, __func__,
                              "Symbolic name '%s' could not be resolved", symbolicOrConnid);
            }   //failure
        }
    }


    //generate ACK/NACK
    struct iovec* response;

    if (success){
            switch (control->activate){
                case ACTIVATE_ON:
                    connection_EnableWldr(conn);
                    response = utils_CreateAck(header, control, sizeof(set_wldr_command));
                    break;

                case ACTIVATE_OFF:
                    connection_DisableWldr(conn);
                    response = utils_CreateAck(header, control, sizeof(set_wldr_command));
                    break;

                default:    //received wrong value
                    response = utils_CreateNack(header, control, sizeof(set_wldr_command));
                    break;
            }
    } else {
        response = utils_CreateNack(header, control, sizeof(set_wldr_command));
    }

    return response;
}


strategy_type
configuration_GetForwardingStrategy(Configuration *config, const char *prefix)
{
    PARCString *prefixStr = parcString_Create(prefix);
    const unsigned *val = parcHashMap_Get(config->strategy_map, prefixStr);
    parcString_Release(&prefixStr);

    if (val == NULL) {
        return LAST_STRATEGY_VALUE;
    } else  {
        return (strategy_type) *val;
    }
}


struct iovec *
configuration_SetForwardingStrategy(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    set_strategy_command *control = request[1].iov_base;

    const char *prefix =
        utils_PrefixLenToString(control->addressType, &control->address, &control->len);
    strategy_type strategy = control->strategyType;
    strategy_type existingFwdStrategy = configuration_GetForwardingStrategy(config, prefix);

    if(existingFwdStrategy == LAST_STRATEGY_VALUE || strategy != existingFwdStrategy){
        //means such a new strategy is not present in the hash table or has to be updated
        _configuration_StoreFwdStrategy(config, prefix, strategy);
        Name *hicnPrefix =
            name_CreateFromAddress(control->addressType, control->address, control->len);
        forwarder_SetStrategy(config->forwarder, hicnPrefix, strategy);
        name_Release(&hicnPrefix);
    }

    struct iovec *response = utils_CreateAck(header, control, sizeof(set_strategy_command));

    return response;
}


void
configuration_SetObjectStoreSize(Configuration *config, size_t maximumObjectCount)
{
    config->maximumContentObjectStoreSize = maximumObjectCount;

    forwarder_SetContentObjectStoreSize(config->forwarder, config->maximumContentObjectStoreSize);
}

Forwarder *
configuration_GetForwarder(const Configuration *config)
{
    return config->forwarder;
}

Logger *
configuration_GetLogger(const Configuration *config)
{
    return config->logger;
}


struct iovec *
configuration_MapMeEnable(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    mapme_activator_command *control = request[1].iov_base;
    const char *stateString[2] = {"on", "off"};


    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer, "The mapme enable setting received is: %s",
                            stateString[control->activate]);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **) &result);
    parcBufferComposer_Release(&composer);

    struct iovec *response = utils_CreateAck(header, control, sizeof(mapme_activator_command));

    return response;
}

struct iovec *
configuration_MapMeDiscovery(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    mapme_activator_command *control = request[1].iov_base;
    const char *stateString[2] = {"on", "off"};

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer, "The mapme discovery setting received is: %s",
                            stateString[control->activate]);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **) &result);
    parcBufferComposer_Release(&composer);

    struct iovec *response = utils_CreateAck(header, control, sizeof(mapme_activator_command));

    return response;
}

struct iovec *
configuration_MapMeTimescale(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    mapme_timing_command *control = request[1].iov_base;

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer, "The mapme timescale value received is: %u",
                            control->timePeriod);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **) &result);
    parcBufferComposer_Release(&composer);

    struct iovec *response = utils_CreateAck(header, control, sizeof(mapme_timing_command));

    return response;
}

struct iovec *
configuration_MapMeRetx(Configuration *config, struct iovec *request)
{
    header_control_message *header  = request[0].iov_base;
    mapme_timing_command *control = request[1].iov_base;

    PARCBufferComposer *composer = parcBufferComposer_Create();
    parcBufferComposer_Format(composer, "The mapme retransmission time value received is: %u",
                            control->timePeriod);

    PARCBuffer *tempBuffer = parcBufferComposer_ProduceBuffer(composer);
    char *result = parcBuffer_ToString(tempBuffer);
    parcBuffer_Release(&tempBuffer);
    puts(result);
    parcMemory_Deallocate((void **) &result);
    parcBufferComposer_Release(&composer);

    struct iovec *response = utils_CreateAck(header, control, sizeof(mapme_timing_command));

    return response;
}




// ===========================
// Main functions that deal with receiving commands, executing them, and sending ACK/NACK


struct iovec *
configuration_DispatchCommand(Configuration *config, command_id command,
                                        struct iovec *control, unsigned ingressId){

    struct iovec *response = NULL;

    switch (command) {
        case ADD_LISTENER:
            response = configurationListeners_Add(config, control, ingressId);
            break;

        case ADD_CONNECTION:
            response = configuration_ProcessCreateTunnel(config, control);
            break;

        case LIST_CONNECTIONS:
            response = configuration_ProcessConnectionList(config, control);
            break;

        case ADD_ROUTE:
            response = configuration_ProcessRegisterHIcnPrefix(config, control, ingressId);
            break;

        case LIST_ROUTES:
            response = configuration_ProcessRegistrationList(config, control);
            break;

        case REMOVE_CONNECTION:
            response = configuration_ProcessRemoveTunnel(config, control);
            break;

        case REMOVE_ROUTE:
            response = configuration_ProcessUnregisterHIcnPrefix(config, control);
            break;

        case CACHE_STORE:
            response = configuration_ProcessCacheStore(config, control);
            break;

        case CACHE_SERVE:
            response = configuration_ProcessCacheServe(config, control);
            break;

        case CACHE_CLEAR:
            response = configuration_ProcessCacheClear(config, control);
            break;

        case SET_STRATEGY:
            response = configuration_SetForwardingStrategy(config, control);
            break;

        case SET_WLDR:
            response = configuration_SetWldr(config, control);
            break;

        case ADD_PUNTING:
            response = configurationListeners_AddPunting(config, control, ingressId);
            break;

        case LIST_LISTENERS:
            response = configuration_ProcessListenersList(config, control);
            break;

        case MAPME_ENABLE:
            response = configuration_MapMeEnable(config, control);
            break;

        case MAPME_DISCOVERY:
            response = configuration_MapMeDiscovery(config, control);
            break;

        case MAPME_TIMESCALE:
            response = configuration_MapMeTimescale(config, control);
            break;

        case MAPME_RETX:
            response = configuration_MapMeRetx(config, control);
            break;

        default:
            break;
    }

    return response;

}

void
configuration_ReceiveCommand(Configuration *config, command_id command, struct iovec *request, unsigned ingressId){

    parcAssertNotNull(config, "Parameter config must be non-null");
    parcAssertNotNull(request, "Parameter request must be non-null");
    struct iovec *response = configuration_DispatchCommand(config, command, request, ingressId);
    configuration_SendResponse(config, response, ingressId);

    switch(command) {
        case LIST_CONNECTIONS: case LIST_ROUTES: //case LIST_INTERFACES: case ETC...:
            parcMemory_Deallocate(&response[1].iov_base);   //deallocate payload only if generated at fwd side
            break;
        default:
            break;
    }

    //deallocate received request. It coincides with response[0].iov_base memory
    //parcMemory_Deallocate(&request);    //deallocate header and payload (if same sent by controller)
    parcMemory_Deallocate(&response);   //deallocate iovec pointer

}
