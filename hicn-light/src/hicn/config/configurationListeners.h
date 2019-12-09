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
 * @file configurationListeners.h
 * @brief Configuration routines related to Listeners
 *
 * Adding and removing listeners.
 *
 */

#ifndef configurationListeners_h
#define configurationListeners_h

#include <hicn/config/configuration.h>
#include <hicn/core/forwarder.h>

/**
 * Setup udp, tcp, and local listeners
 *
 *   Will bind to all available IP protocols on the given port.
 *   Does not add Ethernet listeners.
 *
 * @param port is the UPD and TCP port to use
 * @param localPath is the AF_UNIX path to use, if NULL no AF_UNIX listener is
 * setup
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
void configurationListeners_SetupAll(const Configuration *config, uint16_t port,
                                     const char *localPath);

void configurationListeners_SetupLocalIPv4(const Configuration *config,
                                            uint16_t port);

bool configurationListeners_Remove(const Configuration *config);

// light functions

/**
 * Add new listener.
 *
 * @param request The request coming from hicnLightControl or the
 *                configuration file. The bytes in the request are
 *                ordered following the network byte order convention.
 *
 * @param ingressId The connection id of the incoming request.
 */
struct iovec *configurationListeners_Add(Configuration *config,
                                         struct iovec *request,
                                         unsigned ingressId);

struct iovec *configurationListeners_AddPunting(Configuration *config,
                                                struct iovec *request,
                                                unsigned ingressId);

#endif /* defined(configurationListeners_h) */
