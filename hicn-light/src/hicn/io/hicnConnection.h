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
 * @file hicnConnection.h
 * @brief Represents a Hicn connection for the connection table
 *
 * <#Detailed Description#>
 *
 */

#ifndef hicnConnection_h
#define hicnConnection_h

#include <hicn/core/forwarder.h>
#include <hicn/io/ioOperations.h>
#include <hicn/base/address_pair.h>

/**
 * Creates a Hicn connection that can send to the remote address
 *
 * The address pair must both be same type (i.e. INET or INET6).
 *
 * @param [in] an allocated hicn-light Forwarder (saves reference)
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
IoOperations *hicnConnection_Create(Forwarder *forwarder,
        const char * interfaceName, int fd, const address_pair_t * pair,
        bool isLocal);
#endif  // hicnConnection_h
