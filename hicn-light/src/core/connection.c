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
#include <limits.h>

#include <src/io/ioOperations.h>
#include <src/core/connection.h>
#include <src/io/addressPair.h>
#include <src/core/wldr.h>
#include <src/core/ticks.h>
#include <src/core/messageHandler.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

struct connection {
    const AddressPair *addressPair;
    IoOperations *ops;

    unsigned refCount;

    bool probing_active;
    unsigned probing_interval;
    unsigned counter;
    Ticks last_sent;
    Ticks delay;

    bool wldrAutoStart; //if true, wldr can be set automatically
                        //by default this value is set to true.
                        //if wldr is activated using a command (config file/hicnLightControl)
                        //this value is set to false so that a base station can
                        //not disable wldr at the client
    Wldr *wldr;
};

Connection *
connection_Create(IoOperations *ops)
{
    parcAssertNotNull(ops, "Parameter ops must be non-null");
    Connection *conn = parcMemory_AllocateAndClear(sizeof(Connection));
    parcAssertNotNull(conn, "parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(Connection));
    conn->addressPair = ioOperations_GetAddressPair(ops);
    conn->ops = ops;
    conn->refCount = 1;
    conn->wldr = NULL;
    conn->probing_active = false;

    conn->wldrAutoStart =  true;
    conn->probing_interval = 0;
    conn->counter = 0;
    conn->last_sent = 0;
    conn->delay = INT_MAX;
    return conn;
}

Connection *
connection_Acquire(Connection *connection)
{
    parcAssertNotNull(connection, "Parameter conn must be non-null");
    connection->refCount++;
    return connection;
}

void
connection_Release(Connection **connectionPtr)
{
    parcAssertNotNull(connectionPtr, "Parameter must be non-null double pointer");
    parcAssertNotNull(*connectionPtr, "Parameter must dereference to non-null pointer");
    Connection *conn = *connectionPtr;

    parcAssertTrue(conn->refCount > 0, "Invalid state, connection reference count should be positive, got 0.");
    conn->refCount--;
    if (conn->refCount == 0) {
        // don't destroy addressPair, its part of ops.
      ioOperations_Release(&conn->ops);
        if (conn->wldr != NULL) {
          wldr_Destroy(&(conn->wldr));
        }
        parcMemory_Deallocate((void **) &conn);
    }
    *connectionPtr = NULL;
}

bool
connection_Send(const Connection *conn, Message *message)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    parcAssertNotNull(message, "Parameter message must be non-null");

    if (ioOperations_IsUp(conn->ops)) {
        if (message_GetType(message) == MessagePacketType_ContentObject) {
            uint8_t connectionId = (uint8_t) connection_GetConnectionId(conn);
            message_UpdatePathLabel(message, connectionId);
        }
        if (conn->wldr != NULL) {
          wldr_SetLabel(conn->wldr, message);
        } else{
          message_ResetWldrLabel(message);
        }
        return ioOperations_Send(conn->ops, NULL, message);
    }
    return false;
}


static void
_sendProbe(Connection *conn, unsigned probeType, uint8_t *message)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");

    if (probeType == PACKET_TYPE_PROBE_REQUEST) {
        Ticks now = ioOperations_SendProbe(conn->ops, probeType, message);
        if (now != 0) {
            conn->last_sent = now;
        }
    } else {
      ioOperations_SendProbe(conn->ops, probeType, message);
    }
}


void
connection_Probe(Connection *conn)
{
    _sendProbe(conn, PACKET_TYPE_PROBE_REQUEST, NULL);
}

void
connection_HandleProbe(Connection *conn, uint8_t *probe, Ticks actualTime)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    parcAssertNotNull(probe, "Parameter pkt must be non-null");

    uint8_t probeType = messageHandler_GetProbePacketType(probe);
    if (probeType == PACKET_TYPE_PROBE_REQUEST) {
        _sendProbe(conn, PACKET_TYPE_PROBE_REPLY, probe);
    } else if (probeType == PACKET_TYPE_PROBE_REPLY) {
        Ticks delay = actualTime - conn->last_sent;
        if (delay == 0) {
            delay = 1;
        }
        if (delay < conn->delay) {
            conn->delay = delay;
        }
    } else {
        printf("receivde unkwon probe type\n");
    }
}

uint64_t
connection_GetDelay(Connection *conn)
{
    return (uint64_t) conn->delay;
}


IoOperations *
connection_GetIoOperations(const Connection *conn)
{
    return conn->ops;
}

unsigned
connection_GetConnectionId(const Connection *conn)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    return ioOperations_GetConnectionId(conn->ops);
}

const AddressPair *
connection_GetAddressPair(const Connection *conn)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    return ioOperations_GetAddressPair(conn->ops);
}

bool
connection_IsUp(const Connection *conn)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    if (!conn->ops)
        return false;
    return ioOperations_IsUp(conn->ops);
}

bool
connection_IsLocal(const Connection *conn)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    return ioOperations_IsLocal(conn->ops);
}

const void *
connection_Class(const Connection *conn)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    return ioOperations_Class(conn->ops);
}

bool
connection_ReSend(const Connection *conn, Message *message, bool notification)
{
    parcAssertNotNull(conn, "Parameter conn must be non-null");
    parcAssertNotNull(message, "Parameter message must be non-null");
    bool res = false;

    if (connection_IsUp(conn)) {
        //here the wldr header is alreay set: this message is a retransmission or a notification

        //we need to recompiute the path lable since we always store a pointer to the same message
        //if this message will be sent again to someonelse, the new path label must be computed starting
        //from the orignal labelorignal label. Notice that we heve the same problem in case of PIT
        //aggregation. That case is handled insied the MessageProcessor. This is specific to
        //WLDR retransmittions. This is done only for data packets

        if (message_GetType(message) == MessagePacketType_ContentObject) {
            uint8_t connectionId = (uint8_t) connection_GetConnectionId(conn);
            uint32_t old_path_label = message_GetPathLabel(message);
            message_UpdatePathLabel(message, connectionId);

            res = ioOperations_Send(conn->ops, NULL, message);

            message_SetPathLabel(message, old_path_label);
        } else {
            res = ioOperations_Send(conn->ops, NULL, message);
        }
    }

    if(notification){
        //the notification is never destroyed
      message_Release(&message);
    }

    return res;
}

void
connection_AllowWldrAutoStart(Connection *conn, bool allow)
{
    conn->wldrAutoStart = allow;
}

void
connection_EnableWldr(Connection *conn)
{
    if (!connection_IsLocal(conn)) {
        if (conn->wldr == NULL) {
            printf("----------------- enable wldr\n");
            conn->wldr = wldr_Init();
        }
    }
}

void
connection_DisableWldr(Connection *conn)
{
    if (!connection_IsLocal(conn)) {
        if (conn->wldr != NULL) {
            printf("----------------- disable wldr\n");
          wldr_Destroy(&(conn->wldr));
            conn->wldr = NULL;
        }
    }
}


bool
connection_HasWldr(const Connection *conn)
{
    if (conn->wldr == NULL) {
        return false;
    } else {
        return true;
    }
}

bool
connection_WldrAutoStartAllowed(const Connection *conn)
{
    return conn->wldrAutoStart;
}

void
connection_DetectLosses(Connection *conn, Message *message)
{
    if(conn->wldr != NULL)
      wldr_DetectLosses(conn->wldr, conn, message);
}

void
connection_HandleWldrNotification(Connection *conn, Message *message)
{
    if(conn->wldr != NULL)
      wldr_HandleWldrNotification(conn->wldr, conn, message);
}

