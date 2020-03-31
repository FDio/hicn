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

#include <limits.h>
#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/core/connection.h>
#include <hicn/core/connectionState.h>
#include <hicn/core/messageHandler.h>
#include <hicn/core/ticks.h>
#include <hicn/core/wldr.h>
#include <hicn/base/address_pair.h>
#include <hicn/io/ioOperations.h>

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>
#ifdef WITH_POLICY
#include <hicn/policy.h>
#endif /* WITH_POLICY */

struct connection {

  address_pair_t pair;
  IoOperations *ops;

  unsigned refCount;

  unsigned counter;

  bool wldrAutoStart;  // if true, wldr can be set automatically
                       // by default this value is set to true.
                       // if wldr is activated using a command (config
                       // file/hicnLightControl) this value is set to false so
                       // that a base station can not disable wldr at the client
  Wldr *wldr;

#ifdef WITH_POLICY
  policy_tags_t tags;
#endif /* WITH_POLICY */

};

Connection *
connection_Create(void /* IoOperations */ * ops)
{
  parcAssertNotNull(ops, "Parameter ops must be non-null");
  Connection *conn = parcMemory_AllocateAndClear(sizeof(Connection));
  parcAssertNotNull(conn, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(Connection));
  conn->pair = *ioOperations_GetAddressPair(ops);
  conn->ops = ops;
  conn->refCount = 1;
  conn->wldr = NULL;

  conn->wldrAutoStart = true;
  conn->counter = 0;

  /* By default, a connection will aim at the UP state */
  connection_SetAdminState(conn, CONNECTION_STATE_UP);

#ifdef WITH_POLICY
  conn->tags = POLICY_TAGS_EMPTY;
#endif /* WITH_POLICY */

  return conn;
}

Connection *connection_Acquire(Connection *connection) {
  parcAssertNotNull(connection, "Parameter conn must be non-null");
  connection->refCount++;
  return connection;
}

void connection_Release(Connection **connectionPtr) {
  parcAssertNotNull(connectionPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*connectionPtr,
                    "Parameter must dereference to non-null pointer");
  Connection *conn = *connectionPtr;

  parcAssertTrue(
      conn->refCount > 0,
      "Invalid state, connection reference count should be positive, got 0.");
  conn->refCount--;
  if (conn->refCount == 0) {
    // don't destroy pair, its part of ops.
    ioOperations_Release(&conn->ops);
    if (conn->wldr != NULL) {
      wldr_Destroy(&(conn->wldr));
    }
    parcMemory_Deallocate((void **)&conn);
  }
  *connectionPtr = NULL;
}

bool connection_Send(const Connection *conn, msgbuf_t *message, bool queue) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");

  /* NULL message means flush */
  if (!message) {
    return ioOperations_Send(conn->ops, NULL, NULL, false);
  }

  if (ioOperations_IsUp(conn->ops)) {
    if (msgbuf_type(message) == MessagePacketType_ContentObject) {
      uint8_t connectionId = (uint8_t)connection_GetConnectionId(conn);
      msgbuf_update_pathlabel(message, connectionId);
    }
    if (conn->wldr != NULL) {
      wldr_SetLabel(conn->wldr, message);
    } else {
      msgbuf_reset_wldr_label(message);
    }
    return ioOperations_Send(conn->ops, NULL, message, queue);
  }
  return false;
}

bool connection_SendIOVBuffer(const Connection *conn, struct iovec *msg,
    size_t size) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  parcAssertNotNull(msg, "Parameter message must be non-null");

  return ioOperations_SendIOVBuffer(conn->ops, msg, size);
}

bool connection_SendBuffer(const Connection *conn, u8 * buffer, size_t length)
{
  struct iovec iov[1];
  iov[0].iov_base = buffer;
  iov[0].iov_len = length;
  return connection_SendIOVBuffer(conn, iov, 1);
}

void connection_Probe(Connection *conn, uint8_t * probe) {
  ioOperations_SendProbe(conn->ops, probe);
}

void connection_HandleProbe(Connection *conn, uint8_t *probe){
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  parcAssertNotNull(probe, "Parameter pkt must be non-null");

  if(messageHandler_IsInterest(probe)){
    messageHandler_CreateProbeReply(probe, HF_INET6_TCP);
    ioOperations_SendProbe(conn->ops, probe);
  }
}

void /* IoOperations */ * connection_GetIoOperations(const Connection *conn) {
  return (void*)conn->ops;
}

unsigned connection_GetConnectionId(const Connection *conn) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  return ioOperations_GetConnectionId(conn->ops);
}

const address_pair_t * connection_GetAddressPair(const Connection *conn) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  return ioOperations_GetAddressPair(conn->ops);
}

bool connection_IsUp(const Connection *conn) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops) return false;
  return ioOperations_IsUp(conn->ops);
}

bool connection_IsLocal(const Connection *conn) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  return ioOperations_IsLocal(conn->ops);
}

const void *connection_Class(const Connection *conn) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  return ioOperations_Class(conn->ops);
}

bool connection_ReSend(const Connection *conn, msgbuf_t *message,
                       bool notification) {
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");
  bool res = false;

  if (connection_IsUp(conn)) {
    // here the wldr header is alreay set: this message is a retransmission or a
    // notification

    // we need to recompiute the path lable since we always store a pointer to
    // the same message if this message will be sent again to someonelse, the
    // new path label must be computed starting from the orignal labelorignal
    // label. Notice that we heve the same problem in case of PIT aggregation.
    // That case is handled insied the MessageProcessor. This is specific to
    // WLDR retransmittions. This is done only for data packets

    if (msgbuf_type(message) == MessagePacketType_ContentObject) {
      uint8_t connectionId = (uint8_t)connection_GetConnectionId(conn);
      uint32_t old_path_label = msgbuf_get_pathlabel(message);
      msgbuf_update_pathlabel(message, connectionId);

      res = ioOperations_Send(conn->ops, NULL, message, false); /* no queueing */

      msgbuf_set_pathlabel(message, old_path_label);
    } else {
      res = ioOperations_Send(conn->ops, NULL, message, false); /* no queueing */
    }
  }

  return res;
}

void connection_AllowWldrAutoStart(Connection *conn, bool allow) {
  conn->wldrAutoStart = allow;
}

void connection_EnableWldr(Connection *conn) {
  if (!connection_IsLocal(conn)) {
    if (conn->wldr == NULL) {
      printf("----------------- enable wldr\n");
      conn->wldr = wldr_Init();
    }
  }
}

void connection_DisableWldr(Connection *conn) {
  if (!connection_IsLocal(conn)) {
    if (conn->wldr != NULL) {
      printf("----------------- disable wldr\n");
      wldr_Destroy(&(conn->wldr));
      conn->wldr = NULL;
    }
  }
}

bool connection_HasWldr(const Connection *conn) {
  if (conn->wldr == NULL) {
    return false;
  } else {
    return true;
  }
}

bool connection_WldrAutoStartAllowed(const Connection *conn) {
  return conn->wldrAutoStart;
}

void connection_DetectLosses(Connection *conn, msgbuf_t *message) {
  if (conn->wldr != NULL) wldr_DetectLosses(conn->wldr, conn, message);
}

void connection_HandleWldrNotification(const Connection *conn, msgbuf_t *message) {
  if (conn->wldr != NULL)
    wldr_HandleWldrNotification(conn->wldr, conn, message);
}

connection_state_t connection_GetState(const Connection *conn)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return CONNECTION_STATE_UNDEFINED;
  return ioOperations_GetState(conn->ops);
}

void connection_SetState(Connection *conn, connection_state_t state)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return;
  ioOperations_SetState(conn->ops, state);
}

connection_state_t connection_GetAdminState(const Connection *conn)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return CONNECTION_STATE_UNDEFINED;
  return ioOperations_GetAdminState(conn->ops);
}

void connection_SetAdminState(Connection *conn, connection_state_t admin_state)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return;
  if ((admin_state != CONNECTION_STATE_UP) && (admin_state != CONNECTION_STATE_DOWN))
    return;
  ioOperations_SetAdminState(conn->ops, admin_state);
}

#ifdef WITH_POLICY
uint32_t connection_GetPriority(const Connection *conn)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return 0;
  return ioOperations_GetPriority(conn->ops);
}

void connection_SetPriority(Connection *conn, uint32_t priority)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return;
  ioOperations_SetPriority(conn->ops, priority);
}
#endif /* WITH_POLICY */

const char * connection_GetInterfaceName(const Connection * conn)
{
  parcAssertNotNull(conn, "Parameter conn must be non-null");
  if (!conn->ops)
    return NULL;
  return ioOperations_GetInterfaceName(conn->ops);
}

#ifdef WITH_POLICY

void connection_AddTag(Connection *conn, policy_tag_t tag)
{
    policy_tags_add(&conn->tags, tag);
}

void connection_RemoveTag(Connection *conn, policy_tag_t tag)
{
    policy_tags_remove(&conn->tags, tag);
}

policy_tags_t connection_GetTags(const Connection *conn)
{
    return conn->tags;
}

void connection_SetTags(Connection *conn, policy_tags_t tags)
{
    conn->tags = tags;
}

void connection_ClearTags(Connection *conn)
{
    conn->tags = POLICY_TAGS_EMPTY;
}

int connection_HasTag(const Connection *conn, policy_tag_t tag)
{
    return policy_tags_has(conn->tags, tag);
}

#endif /* WITH_POLICY */
