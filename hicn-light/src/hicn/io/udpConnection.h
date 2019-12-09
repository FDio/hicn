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
 * @file udpConnection.h
 * @brief Represents a UDP connection (socket) for the connection table
 *
 * <#Detailed Description#>
 *
 */

#ifndef udpConnection_h
#define udpConnection_h

#include <hicn/base/address_pair.h>
#include <hicn/core/forwarder.h>
#include <hicn/io/ioOperations.h>

/**
 * Creates a UDP connection that can send to the remote address
 *
 * The address pair must both be same type (i.e. INET or INET6).
 *
 * @param [in] metis An allocated MetisForwarder (saves reference)
 * @param [in] fd The socket to use
 * @param [in] pair An allocated address pair for the connection (saves
 * reference)
 * @param [in] isLocal determines if the remote address is on the current system
 *
 * @retval non-null An allocated Io operations
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
IoOperations *udpConnection_Create(Forwarder *forwarder,
        const char * interfaceName, int fd, const address_pair_t *pair,
        bool isLocal, unsigned connection_id);
#endif  // udpConnection_h
