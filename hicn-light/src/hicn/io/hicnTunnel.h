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
 * @file hicnTunnel.h
 * @brief Establish a tunnel to a remote system
 *
 * Creates a "hicn tunnel" to a remote system.  There must already be a local
 * HICN listener for the local side of the connection.
 *
 */

#ifndef hicnTunnel_h
#define hicnTunnel_h

#include <hicn/core/forwarder.h>
#include <hicn/io/ioOperations.h>
#include <hicn/io/listener.h>

/**
 * Establishes a connection to a remote system over HICN
 *
 * The remoteAddress must be of the same type (i.e. v4 or v6) as the
 * localAddress.  There must be an existing HICN listener on the local address.
 * If either of these are not true, will return NULL.
 *
 * The connection will go in the table immediately, and will be in the "up"
 * state.
 *
 * @param [in] an allocated hicn-light Forwarder
 * @param [in] localAddress The local IP address and port to use for the
 * connection
 * @param [in] remote Address the remote IP address for the connection, must
 * include a destination port.
 *
 * @retval non-null An allocated Io Operations structure for the connection
 * @retval null An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
IoOperations *hicnTunnel_Create(Forwarder *forwarder,
        const address_pair_t * pair);

IoOperations *hicnTunnel_CreateOnListener(Forwarder *forwarder,
                                          ListenerOps *localListener,
                                          const address_t *remoteaddress_t);

#endif  // hicnTunnel_h
