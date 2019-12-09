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
 * Methods common to TCP and PF_LOCAL stream-based listeners
 */

#ifndef streamConnection_h
#define streamConnection_h

#include <hicn/core/forwarder.h>
#include <hicn/core/messagePacketType.h>
#include <hicn/io/ioOperations.h>

/**
 * @function streamConnection_AcceptConnection
 * @abstract Receive a connection from a remote peer
 * @discussion
 *   We are the "server side" of the stream connection, so we need to accept the
 * client connection and setup state for her.
 *
 * @param <#param1#>
 * @return <#return#>
 */
IoOperations *streamConnection_AcceptConnection(Forwarder *forwarder, int fd,
        address_pair_t *pair, bool isLocal);

/**
 * @function streamConnection_OpenConnection
 * @abstract Initiate a connection to a remote peer
 * @discussion
 *   We are the "client side" of the stream connection.  We'll create state for
 * the peer, but it will be in the "down" state until the connection
 * establishes.
 *
 *   For TCP, both address pairs need to be the same address family: both INET
 * or both INET6.  The remote address must have the complete socket information
 * (address, port).  The local socket could be wildcarded or may specify down to
 * the (address, port) pair.
 *
 *   If the local address is IPADDR_ANY and the port is 0, then it is a normal
 * call to "connect" that will use whatever local IP address and whatever local
 * port for the connection.  If either the address or port is set, the local
 * socket will first be bound (via bind(2)), and then call connect().
 *
 *   AF_UNIX is not yet supported
 *
 *   If there's an error binding to the specified address or connecting to the
 * remote address, will return NULL.
 *
 * @param pair (takes ownership of this) is the complete socket pair of
 * (address, port) for each end, if INET or INET6.
 * @return NULL on error, otherwise the connections IO operations.
 */
IoOperations *streamConnection_OpenConnection(Forwarder *forwarder,
        address_pair_t *pair, bool isLocal, unsigned connid);

bool streamState_SendIOVBuffer(IoOperations *ops, struct iovec *response,
        size_t size);

#endif  // streamConnection_h
