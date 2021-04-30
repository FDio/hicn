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
 * @file tcpTunnel.h
 * @brief Establish a tunnel to a remote system
 *
 */

#ifndef tcpTunnel_h
#define tcpTunnel_h

#include <hicn/core/forwarder.h>
#include <hicn/io/ioOperations.h>
#include <hicn/io/listener.h>
#include <hicn/utils/address.h>

/**
 */
// IoOperations *tcpTunnel_CreateOnListener(Forwarder *forwarder,
//                                            ListenerOps *localListener,
//                                            const Address *remoteAddress);

/**
 */
IoOperations *tcpTunnel_Create(Forwarder *forwarder,
                               const Address *localAddress,
                               const Address *remoteAddress);

#endif  // tcpTunnel_h
